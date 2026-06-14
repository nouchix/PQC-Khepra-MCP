package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	mrand "math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/agi"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/billing"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/config"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/license"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/net/tailnet"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/sekhem"
)

const (
	BannerSeparator     = "==========================================="
	HeaderContentType   = "Content-Type"
	MIMEApplicationJSON = "application/json"
	HeaderCORSOrigin    = "Access-Control-Allow-Origin"
)

type server struct {
	cfg     config.Config
	store   dag.Store
	agi     *agi.Engine
	sekhem  *sekhem.SekhemTriad
	licAPI  *LicensingAPI
	pubKey  []byte
	privKey []byte
}

func main() {
	showMachineID := flag.Bool("machine-id", false, "Print machine ID and exit")
	enrollmentToken := flag.String("enrollment-token", "", "Enrollment token")
	flag.Parse()

	if *showMachineID {
		printMachineID()
		return
	}

	initializeAgent(*enrollmentToken)
}

func printMachineID() {
	machineID := license.GenerateMachineID()
	fmt.Println(BannerSeparator)
	fmt.Println("  KHEPRA MACHINE ID (License Fingerprint)")
	fmt.Println(BannerSeparator)
	fmt.Printf("  Machine ID: %s\n", machineID)
	fmt.Println(BannerSeparator)
	fmt.Println("\nSend this Machine ID to your administrator\nto receive your license activation.")
	os.Exit(0)
}

func initializeAgent(token string) {
	if token == "" {
		token = os.Getenv("KHEPRA_ENROLLMENT_TOKEN")
	}

	cfg := config.LoadRuntime()
	baseCfg := config.Load() // config.Config for server struct (uses same env vars)
	store := dag.NewStore()

	// 1. Setup Licensing
	clientMgr, regMgr, enforcer := setupLicensing(token, store)

	// 2. Setup AGI and Sekhem
	arch := agi.NewEngine(store)
	triad := setupSekhem(arch, store)

	// 3. Setup API
	licAPI := NewLicensingAPI(LicensingDeps{
		ClientManager:      clientMgr,
		RegistryManager:    regMgr,
		DagLicenseEnforcer: enforcer,
		BillingCalculator:  billing.NewHybridBillingCalculator(500.0),
		TelemetryClient:    nil,
		DagStore:           store,
		IsAirGapped:        cfg.IsAirGapped,
		MachineID:          license.GenerateMachineID(),
	})

	pub, priv, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		log.Fatalf("[AGENT] Failed to generate signing identity: %v", err)
	}
	s := &server{cfg: baseCfg, store: store, agi: arch, sekhem: triad, licAPI: licAPI, pubKey: pub, privKey: priv}
	runServer(s, baseCfg)
}

func setupLicensing(token string, _ dag.Store) (*license.Manager, *license.LicenseManager, *license.DAGLicenseEnforcer) {
	licenseServer := os.Getenv("KHEPRA_LICENSE_SERVER")
	if licenseServer == "" {
		licenseServer = "https://telemetry.souhimbou.ai"
	}

	m, err := license.NewManager(licenseServer)
	if err != nil {
		log.Printf("[LICENSE] Error: %v", err)
	}

	if key := getMasterKey(); key != "" && m != nil {
		m.SetPrivateKey(key)
		log.Printf("[LICENSE] ✅ Sovereign mode enabled")
	}

	if token != "" && m != nil {
		m.SetEnrollmentToken(token)
	}
	if m != nil {
		if err := m.Initialize(); err != nil {
			log.Printf("[LICENSE] Warning: Using community mode: %v", err)
		}
	}

	home, _ := os.UserHomeDir()
	if home == "" {
		home = "."
	}
	tierStorePath := filepath.Join(home, ".khepra", "tiers.json")

	regMgr := license.NewLicenseManager(tierStorePath)
	enforcer := license.NewDAGLicenseEnforcer(regMgr)

	return m, regMgr, enforcer
}

func getMasterKey() string {
	if key := os.Getenv("KHEPRA_MASTER_KEY"); key != "" {
		return key
	}
	path := os.Getenv("KHEPRA_MASTER_KEY_PATH")
	if path == "" {
		path = "keys/offline/OFFLINE_ROOT_KEY.secret"
	}
	if data, err := os.ReadFile(path); err == nil {
		return strings.TrimSpace(string(data))
	}
	return ""
}

func setupSekhem(arch *agi.Engine, store dag.Store) *sekhem.SekhemTriad {
	mode := getDeploymentMode()
	triad, err := sekhem.NewSekhemTriad(arch, store, mode)
	if err != nil {
		log.Fatalf("[SEKHEM] Failed: %v", err)
	}
	_ = triad.Harmonize()
	return triad
}

func getDeploymentMode() sekhem.DeploymentMode {
	switch strings.ToLower(os.Getenv("KHEPRA_MODE")) {
	case "hybrid":
		return sekhem.ModeHybrid
	case "sovereign":
		return sekhem.ModeSovereign
	case "ironbank":
		return sekhem.ModeIronBank
	default:
		return sekhem.ModeEdge
	}
}

func runServer(s *server, cfg config.Config) {
	mux := http.NewServeMux()
	registerRoutes(mux, s)
	s.agi.Start()

	go func() {
		if cfg.TailscaleAuthKey != "" {
			startTailscale(mux, cfg)
		} else {
			startLocal(mux, cfg)
		}
	}()

	waitForInterrupt()
	s.agi.Stop()
	if s.sekhem != nil {
		s.sekhem.Stop()
	}
}

func registerRoutes(mux *http.ServeMux, s *server) {
	initSCADAPoller(mux)

	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/attest/new", s.attestNew)
	mux.HandleFunc("/dag/add", s.dagAdd)
	mux.HandleFunc("/dag/state", s.dagState)
	mux.HandleFunc("/agi/state", s.agiState)
	mux.HandleFunc("/agi/chat", s.agiChat)
	mux.HandleFunc("/agi/scan", s.agiScan)

	// ── Sovereign dashboard auth routes ──────────────────────────────────────
	// Called by the Vite dashboard's AuthProvider (src/contexts/AuthProvider.tsx)
	// to validate license keys and return user claims without Supabase.
	mux.HandleFunc("/api/v1/license/validate", s.licenseValidate)
	mux.HandleFunc("/api/v1/me/role", s.meRole)

	if s.licAPI != nil {
		s.licAPI.RegisterEndpoints(mux)
	}
}

// licenseValidate checks a license key from the dashboard's signIn flow.
// Request: { "license_key": "ASAF-...", "email": "..." }
// Response 200: { "tenant": "...", "tier": "...", "capabilities": [...] }
// Response 401: { "error": "..." }
func (s *server) licenseValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set(HeaderCORSOrigin, "http://localhost:8080")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	var req struct {
		LicenseKey string `json:"license_key"`
		Email      string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request"})
		return
	}

	// Load the master public key and validate the license file
	pubKey := s.pubKey
	// Find license file: check exe dir, then cwd
	cwd, _ := os.Getwd()
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	licPath := filepath.Join(cwd, "license.adinkhepra")
	if _, err := os.Stat(licPath); err != nil {
		licPath = filepath.Join(exeDir, "license.adinkhepra")
	}
	claims, err := license.Verify(licPath, pubKey)
	if err != nil {
		// Fallback: accept any ASAF- prefixed key for community tier (offline mode)
		if strings.HasPrefix(req.LicenseKey, "ASAF-") && len(req.LicenseKey) >= 20 {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"tenant":       req.Email,
				"tier":         "community",
				"capabilities": []string{"scan"},
			})
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid or expired license key"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"tenant":       claims.Tenant,
		"tier":         "professional",
		"capabilities": claims.Capabilities,
		"expires":      claims.Expiry.Format(time.RFC3339),
	})
}

// meRole returns the role for the currently authenticated user.
// Called by useUserRoles() in the Vite dashboard.
func (s *server) meRole(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(HeaderCORSOrigin, "http://localhost:8080")
	json.NewEncoder(w).Encode(map[string]string{"role": "user"})
}


func (s *server) health(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "time": time.Now()})
}

func (s *server) attestNew(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AgentID string `json:"agent_id"`
		Action  string `json:"action"`
		Symbol  string `json:"symbol"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if req.Action == "" {
		req.Action = "attest:new"
	}
	if req.Symbol == "" {
		req.Symbol = "Gye_Nyame"
	}

	// Use an existing DAG node as parent to maintain chain integrity
	var parents []string
	if existing := s.store.All(); len(existing) > 0 {
		parents = []string{existing[len(existing)-1].ID}
	}

	node := &dag.Node{
		Action: req.Action,
		Symbol: req.Symbol,
		Time:   time.Now().UTC().Format(time.RFC3339),
		PQC:    map[string]string{"agent_id": req.AgentID, "pub_key_hex": hex.EncodeToString(s.pubKey)},
	}
	if err := node.Sign(s.privKey); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "signing failed: " + err.Error()})
		return
	}
	if err := s.store.Add(node, parents); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "dag add failed: " + err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "attested",
		"node_id":        node.ID,
		"signature":      node.Signature,
		"public_key_hex": hex.EncodeToString(s.pubKey),
		"algorithm":      "ML-DSA-65",
		"timestamp":      node.Time,
	})
}

func (s *server) dagAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Symbol  string   `json:"symbol"`
		Action  string   `json:"action"`
		Parents []string `json:"parents"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if req.Action == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "action required"})
		return
	}
	node := &dag.Node{
		Action: req.Action,
		Symbol: req.Symbol,
		Time:   time.Now().UTC().Format(time.RFC3339),
	}
	if len(s.privKey) > 0 {
		_ = node.Sign(s.privKey)
	}
	if err := s.store.Add(node, req.Parents); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "node_id": node.ID})
}

func (s *server) dagState(w http.ResponseWriter, r *http.Request) {
	nodes := s.store.All()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "ok",
		"node_count": len(nodes),
		"nodes":      nodes,
	})
}

func (s *server) agiState(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(s.agi.GetState())
}

func (s *server) agiChat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if req.Message == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "message required"})
		return
	}
	response := s.agi.Chat(req.Message)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "response": response})
}

func (s *server) agiScan(w http.ResponseWriter, r *http.Request) {
	state := s.agi.GetState()
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "scan": state})
}

func startTailscale(mux *http.ServeMux, _ config.Config) {
	ts, _ := tailnet.NewServer("adinkhepra-node-" + randID())
	ln, _ := ts.Listen(context.Background(), ":45444")
	log.Fatal(http.Serve(ln, sWithJSON(mux)))
}

func startLocal(mux *http.ServeMux, cfg config.Config) {
	addr := "127.0.0.1:" + itoa(cfg.AgentListenPort)
	log.Printf("ADINKHEPRA agent alive @ %s", addr)
	log.Fatal(http.ListenAndServe(addr, sWithJSON(mux)))
}

func waitForInterrupt() {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
}

func sWithJSON(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CORS: allow the ASAF dashboard (any origin) to reach the local agent
		w.Header().Set(HeaderCORSOrigin, "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Private-Network", "true")
		// Handle preflight
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set(HeaderContentType, MIMEApplicationJSON)
		h.ServeHTTP(w, r)
	})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + (n % 10))
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func randID() string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 12)
	for i := range b {
		b[i] = letters[mrand.IntN(len(letters))]
	}
	return string(b)
}
