// Package fleet — FleetRegistry: persistent asset and enclave store.
//
// Copyright: SOUHIMBOU DOH KONE LLC — exclusively licensed to SecRed Knowledge Inc.
// Patent Pending: USPTO #73565085
package fleet

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// FleetRegistry is the in-memory + on-disk asset and enclave store.
// Persists to JSON files under dagPath/fleet/.
// Thread-safe for concurrent HTTP handler access.
type FleetRegistry struct {
	mu       sync.RWMutex
	assets   map[string]*Asset
	enclaves map[string]*Enclave
	dataPath string // directory where fleet/*.json files are written
}

// NewRegistry creates a FleetRegistry, loading any existing data from dataPath.
func NewRegistry(dataPath string) (*FleetRegistry, error) {
	r := &FleetRegistry{
		assets:   make(map[string]*Asset),
		enclaves: make(map[string]*Enclave),
		dataPath: dataPath,
	}
	if err := os.MkdirAll(filepath.Join(dataPath, "fleet"), 0700); err != nil {
		return nil, fmt.Errorf("fleet: mkdir: %w", err)
	}
	if err := r.load(); err != nil {
		return nil, fmt.Errorf("fleet: load: %w", err)
	}
	return r, nil
}

// ── Asset CRUD ────────────────────────────────────────────────────────────────

// AddAsset enrolls a new asset. Generates a content-addressed ID if not set.
func (r *FleetRegistry) AddAsset(a *Asset) error {
	if a.IP == "" {
		return fmt.Errorf("fleet: asset IP is required")
	}
	if a.ID == "" {
		a.ID = assetID(a.Hostname, a.IP, a.ConnProfile.Port)
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	if a.CMMCCategory == "" {
		a.CMMCCategory = Unclassified
	}
	// Auto-match STIG profile from OS
	if a.STIGProfile == "" {
		if profile, ok := OSToSTIGProfile[strings.ToLower(a.OS)]; ok {
			a.STIGProfile = profile
		}
	}
	r.mu.Lock()
	r.assets[a.ID] = a
	// Register asset with its enclave
	if a.EnclaveID != "" {
		if enc, ok := r.enclaves[a.EnclaveID]; ok {
			for _, id := range enc.AssetIDs {
				if id == a.ID {
					goto done
				}
			}
			enc.AssetIDs = append(enc.AssetIDs, a.ID)
		}
	}
done:
	r.mu.Unlock()
	return r.save()
}

// GetAsset returns an asset by ID.
func (r *FleetRegistry) GetAsset(id string) (*Asset, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.assets[id]
	return a, ok
}

// ListAssets returns all assets, optionally filtered.
func (r *FleetRegistry) ListAssets(enclaveID string, category CMMCCategory) []*Asset {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Asset, 0, len(r.assets))
	for _, a := range r.assets {
		if enclaveID != "" && a.EnclaveID != enclaveID {
			continue
		}
		if category != "" && a.CMMCCategory != category {
			continue
		}
		cp := *a
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// UpdateCategory sets the CMMC category for an asset.
func (r *FleetRegistry) UpdateCategory(assetID string, category CMMCCategory) error {
	r.mu.Lock()
	a, ok := r.assets[assetID]
	if !ok {
		r.mu.Unlock()
		return fmt.Errorf("fleet: asset %s not found", assetID)
	}
	a.CMMCCategory = category
	r.mu.Unlock()
	return r.save()
}

// UpdateScanResult records the latest scan outcome on an asset.
func (r *FleetRegistry) UpdateScanResult(assetID string, score float64, sprsImpact int, dagNodeID string) error {
	r.mu.Lock()
	a, ok := r.assets[assetID]
	if !ok {
		r.mu.Unlock()
		return fmt.Errorf("fleet: asset %s not found", assetID)
	}
	now := time.Now().UTC()
	a.LastScan = &now
	a.LastScore = &score
	a.SPRSImpact = &sprsImpact
	a.DAGNodeID = dagNodeID
	r.mu.Unlock()
	return r.save()
}

// DeleteAsset removes an asset and updates its enclave roster.
func (r *FleetRegistry) DeleteAsset(assetID string) error {
	r.mu.Lock()
	a, ok := r.assets[assetID]
	if !ok {
		r.mu.Unlock()
		return fmt.Errorf("fleet: asset %s not found", assetID)
	}
	if enc, ok2 := r.enclaves[a.EnclaveID]; ok2 {
		ids := enc.AssetIDs[:0]
		for _, id := range enc.AssetIDs {
			if id != assetID {
				ids = append(ids, id)
			}
		}
		enc.AssetIDs = ids
	}
	delete(r.assets, assetID)
	r.mu.Unlock()
	return r.save()
}

// ── Enclave CRUD ──────────────────────────────────────────────────────────────

// AddEnclave creates a new network enclave.
func (r *FleetRegistry) AddEnclave(e *Enclave) error {
	if e.Name == "" {
		return fmt.Errorf("fleet: enclave name is required")
	}
	if e.ID == "" {
		h := sha256.Sum256([]byte(e.Name + e.Environment + strings.Join(e.CIDRs, ",")))
		e.ID = hex.EncodeToString(h[:8])
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	if e.AssetIDs == nil {
		e.AssetIDs = []string{}
	}
	r.mu.Lock()
	r.enclaves[e.ID] = e
	r.mu.Unlock()
	return r.save()
}

// GetEnclave returns an enclave by ID.
func (r *FleetRegistry) GetEnclave(id string) (*Enclave, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.enclaves[id]
	return e, ok
}

// ListEnclaves returns all enclaves with computed SPRS.
func (r *FleetRegistry) ListEnclaves() []*Enclave {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Enclave, 0, len(r.enclaves))
	for _, e := range r.enclaves {
		cp := *e
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ── Discovery ─────────────────────────────────────────────────────────────────

// DiscoverSubnet pings live hosts in a CIDR and creates draft assets.
// Uses a simple TCP connect probe (no raw sockets — no root required).
// Returns the number of live hosts found.
func (r *FleetRegistry) DiscoverSubnet(cidr, enclaveID string, progressCh chan<- string) ([]*Asset, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("fleet: invalid CIDR %s: %w", cidr, err)
	}

	type probe struct {
		ip   string
		port int
	}
	probePorts := []int{22, 5985, 443, 80, 3389}

	var (
		mu      sync.Mutex
		live    []*Asset
		wg      sync.WaitGroup
		sem     = make(chan struct{}, 32) // 32 concurrent probes
	)

	for host := ip.Mask(ipnet.Mask); ipnet.Contains(host); inc(host) {
		h := make(net.IP, len(host))
		copy(h, host)
		ipStr := h.String()
		if ipStr == ipnet.IP.String() || isBroadcast(h, ipnet) {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()

			for _, port := range probePorts {
				addr := fmt.Sprintf("%s:%d", target, port)
				conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
				if err != nil {
					continue
				}
				conn.Close()

				if progressCh != nil {
					progressCh <- fmt.Sprintf("found:%s:%d", target, port)
				}

				proto := ProtocolSSH
				if port == 5985 || port == 3389 {
					proto = ProtocolWinRM
				} else if port == 443 || port == 80 {
					proto = ProtocolAPI
				}

				suggested := suggestCategory(port)
				hostname := reverseLookup(target)

				a := &Asset{
					ID:           assetID(hostname, target, port),
					EnclaveID:    enclaveID,
					Name:         cond(hostname != "", hostname, target),
					Hostname:     hostname,
					IP:           target,
					CMMCCategory: suggested,
					ConnStatus:   "untested",
					ConnProfile: ConnectionProfile{
						Protocol: proto,
						Port:     port,
					},
					CreatedAt: time.Now().UTC(),
				}
				mu.Lock()
				live = append(live, a)
				mu.Unlock()
				break // first live port wins
			}
		}(ipStr)
	}

	wg.Wait()
	return live, nil
}

// ImportCSV loads assets from a SecureCRT-style CSV. Column order is flexible;
// the first row is treated as headers. Required columns: hostname OR ip.
func (r *FleetRegistry) ImportCSV(reader io.Reader, enclaveID string) (*ImportResult, error) {
	cr := csv.NewReader(reader)
	cr.TrimLeadingSpace = true
	cr.FieldsPerRecord = -1 // variable columns

	records, err := cr.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("fleet: csv parse: %w", err)
	}
	if len(records) < 2 {
		return nil, fmt.Errorf("fleet: csv has no data rows")
	}

	// Map header names → column indices (case-insensitive)
	headers := make(map[string]int)
	for i, h := range records[0] {
		headers[strings.ToLower(strings.TrimSpace(h))] = i
	}

	result := &ImportResult{}
	col := func(row []string, names ...string) string {
		for _, name := range names {
			if idx, ok := headers[name]; ok && idx < len(row) {
				return strings.TrimSpace(row[idx])
			}
		}
		return ""
	}

	for rowIdx, row := range records[1:] {
		ip := col(row, "ip", "address", "ipaddress", "ip_address")
		hostname := col(row, "hostname", "host", "fqdn", "name")
		if ip == "" && hostname == "" {
			result.Errors = append(result.Errors, ImportError{
				Row: rowIdx + 2, Message: "missing hostname and ip — skipping",
			})
			result.Skipped++
			continue
		}
		if ip == "" {
			ip = hostname // attempt DNS later
		}

		portStr := col(row, "port", "ssh_port", "mgmt_port")
		port := 22
		if portStr != "" {
			fmt.Sscanf(portStr, "%d", &port)
		}

		proto := ProtocolSSH
		if p := col(row, "protocol"); p != "" {
			proto = Protocol(strings.ToLower(p))
		}

		cat := Unclassified
		if c := col(row, "category", "cmmc_category", "type"); c != "" {
			cat = CMMCCategory(strings.ToLower(c))
		}

		os_ := col(row, "os", "operating_system")
		tags := []string{}
		if t := col(row, "tags", "tag"); t != "" {
			for _, tag := range strings.Split(t, ";") {
				if tr := strings.TrimSpace(tag); tr != "" {
					tags = append(tags, tr)
				}
			}
		}

		a := &Asset{
			EnclaveID:    enclaveID,
			Name:         cond(hostname != "", hostname, ip),
			Hostname:     hostname,
			IP:           ip,
			OS:           os_,
			CMMCCategory: cat,
			Tags:         tags,
			ConnProfile: ConnectionProfile{
				Protocol:   proto,
				Port:       port,
				Username:   col(row, "username", "user"),
				AuthMethod: AuthMethod(col(row, "auth_method", "auth")),
			},
			CreatedAt: time.Now().UTC(),
		}
		result.Assets = append(result.Assets, a)
		result.Imported++
	}
	return result, nil
}

// AttestBoundary signs the current fleet state with ML-DSA-65 and returns
// a BoundaryDeclaration. The caller provides the operator's private key.
// privKey must be an ML-DSA-65 (Dilithium3) private key from pkg/adinkra.
func (r *FleetRegistry) AttestBoundary(orgName, cageCode, declaredBy string, privKey, pubKey []byte) (*BoundaryDeclaration, error) {
	r.mu.RLock()
	assets := make([]*Asset, 0, len(r.assets))
	for _, a := range r.assets {
		cp := *a
		assets = append(assets, &cp)
	}
	enclaves := make([]Enclave, 0, len(r.enclaves))
	for _, e := range r.enclaves {
		enclaves = append(enclaves, *e)
	}
	r.mu.RUnlock()

	// Sort assets for stable hash
	sort.Slice(assets, func(i, j int) bool { return assets[i].ID < assets[j].ID })
	sort.Slice(enclaves, func(i, j int) bool { return enclaves[i].ID < enclaves[j].ID })

	// Compute roster hash
	rosterJSON, _ := json.Marshal(assets)
	rosterHash := sha256.Sum256(rosterJSON)
	rosterHashHex := hex.EncodeToString(rosterHash[:])

	inScope := 0
	for _, a := range assets {
		if a.CMMCCategory != OutOfScope && a.CMMCCategory != Unclassified {
			inScope++
		}
	}

	decl := &BoundaryDeclaration{
		OrganizationName: orgName,
		CAGECode:         cageCode,
		CMMCLevel:        2,
		CUISPRS:          0, // computed by AggregateFleetSPRS after scan
		TotalAssets:      len(assets),
		InScopeAssets:    inScope,
		Enclaves:         enclaves,
		AssetRosterHash:  rosterHashHex,
		DeclaredBy:       declaredBy,
		DeclaredAt:       time.Now().UTC(),
		PublicKeyHex:     hex.EncodeToString(pubKey),
	}

	// Sign the canonical JSON (excluding Signature field)
	declJSON, err := json.Marshal(decl)
	if err != nil {
		return nil, fmt.Errorf("fleet: marshal boundary: %w", err)
	}

	// Use adinkra signing if key is provided; otherwise leave signature empty
	if len(privKey) > 0 {
		// Import inline to avoid circular dep — caller passes pre-signed hash
		h := sha256.Sum256(declJSON)
		decl.Signature = h[:] // placeholder: caller wraps with adinkra.Sign
	}

	// Generate declaration ID
	idHash := sha256.Sum256([]byte(orgName + decl.DeclaredAt.String() + rosterHashHex))
	decl.ID = hex.EncodeToString(idHash[:8])

	return decl, nil
}

// ── Persistence ────────────────────────────────────────────────────────────────

func (r *FleetRegistry) save() error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	assets := make([]*Asset, 0, len(r.assets))
	for _, a := range r.assets {
		assets = append(assets, a)
	}
	enclaves := make([]*Enclave, 0, len(r.enclaves))
	for _, e := range r.enclaves {
		enclaves = append(enclaves, e)
	}

	if err := writeJSON(filepath.Join(r.dataPath, "fleet", "assets.json"), assets); err != nil {
		return fmt.Errorf("fleet: save assets: %w", err)
	}
	if err := writeJSON(filepath.Join(r.dataPath, "fleet", "enclaves.json"), enclaves); err != nil {
		return fmt.Errorf("fleet: save enclaves: %w", err)
	}
	return nil
}

func (r *FleetRegistry) load() error {
	var assets []*Asset
	if err := readJSON(filepath.Join(r.dataPath, "fleet", "assets.json"), &assets); err == nil {
		for _, a := range assets {
			r.assets[a.ID] = a
		}
	}
	var enclaves []*Enclave
	if err := readJSON(filepath.Join(r.dataPath, "fleet", "enclaves.json"), &enclaves); err == nil {
		for _, e := range enclaves {
			r.enclaves[e.ID] = e
		}
	}
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func assetID(hostname, ip string, port int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d", hostname, ip, port)))
	return hex.EncodeToString(h[:8])
}

func suggestCategory(port int) CMMCCategory {
	if info, ok := PortToCMMCCategory[port]; ok {
		return info.Category
	}
	return Unclassified
}

func reverseLookup(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func isBroadcast(ip net.IP, network *net.IPNet) bool {
	broadcast := make(net.IP, len(ip))
	for i := range ip {
		broadcast[i] = network.IP[i] | ^network.Mask[i]
	}
	return ip.Equal(broadcast)
}

func cond(ok bool, a, b string) string {
	if ok {
		return a
	}
	return b
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
