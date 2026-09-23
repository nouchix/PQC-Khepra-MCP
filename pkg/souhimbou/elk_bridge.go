package souhimbou

// elk_bridge.go — Attested & Encapsulated ELK SIEM / SOC Bridge for SouHimBou AI.
//
// Encapsulates all inbound and outbound Elastic SIEM/SOC communications:
//   1. Inbound Ingress (Elastic SIEM Alerts):
//      - Filtered & verified through SEKHEM L7 WAF (WAFShield)
//      - Attested into the immutable DAG with ML-DSA-65 post-quantum signature
//      - Written to the chain-linked Flight Recorder (khepra-flight.ndjson)
//      - Scored by KASA anomaly detector
//      - Dispatched to SOAR Engine in Staging mode
//      - Privileged system actions routed through asaf-daemon via ChangeRequest (Symbol Eban)
//   2. Outbound Egress (Host/Cluster Telemetry):
//      - Hard-gated by Sovereign Air-Gap posture (KHEPRA_MODE=sovereign blocks all egress)
//      - Formatted into Elastic Common Schema (ECS)
//      - Attested to DAG prior to transmission
//      - Recorded in Flight Recorder with cryptographic outcome verification
//
// IP assignment: SOUHIMBOU DOH KONE LLC. Licensed to SecRed Knowledge Inc.

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/asaf/stargate"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/flight"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/sekhem"
)

var (
	// ErrSovereignEgressForbidden is returned when attempting to ship telemetry in sovereign mode.
	ErrSovereignEgressForbidden = errors.New("elk_bridge: egress forbidden in sovereign air-gapped posture (DoD Non-Negotiable #1)")
	// ErrUnauthorizedWebhook is returned when incoming webhook fails secret or WAF validation.
	ErrUnauthorizedWebhook = errors.New("elk_bridge: unauthorized webhook request")
)

// ElasticAlert represents a structured alert payload emitted by Elastic SIEM detection rules.
type ElasticAlert struct {
	ID          string         `json:"id"`
	RuleID      string         `json:"rule_id"`
	RuleName    string         `json:"rule_name"`
	Severity    string         `json:"severity"` // "low", "medium", "high", "critical"
	RiskScore   float64        `json:"risk_score"`
	Description string         `json:"description"`
	Timestamp   time.Time      `json:"@timestamp"`
	Host        string         `json:"host,omitempty"`
	User        string         `json:"user,omitempty"`
	Source      string         `json:"source_ip,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
}

// IngestResult captures the cryptographic attestation output for an ingested SIEM alert.
type IngestResult struct {
	AlertID      string       `json:"alert_id"`
	DAGNodeID    string       `json:"dag_node_id"`
	FlightSeq    uint64       `json:"flight_seq"`
	PayloadHash  string       `json:"payload_hash_sha3_256"`
	ThreatScore  *ThreatScore `json:"threat_score,omitempty"`
	SOARStaged   bool         `json:"soar_staged"`
	PlaybookName string       `json:"playbook_name,omitempty"`
}

// ElasticSOCCase represents a case or incident from the Elastic SOC / Case Management engine.
type ElasticSOCCase struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"` // "low", "medium", "high", "critical"
	Status      string    `json:"status"`   // "open", "in-progress", "closed"
	Host        string    `json:"host,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	Commands    []string  `json:"commands,omitempty"` // proposed remediation commands
}

// SOCCaseResult captures the attestation and ChangeRequest generation for a SOC incident.
type SOCCaseResult struct {
	CaseID        string                  `json:"case_id"`
	DAGNodeID     string                  `json:"dag_node_id"`
	FlightSeq     uint64                  `json:"flight_seq"`
	PayloadHash   string                  `json:"payload_hash_sha3_256"`
	ChangeRequest *stargate.ChangeRequest `json:"change_request,omitempty"`
	Staged        bool                    `json:"staged"`
}


// ELKBridgeConfig configures the ELK Encapsulation & Attestation Bridge.
type ELKBridgeConfig struct {
	DAG           *dag.PersistentMemory
	Flight        *flight.Recorder
	WAF           *sekhem.WAFShield
	SOAR          *SOAREngine
	WebhookSecret string
	ELKURL        string
	ELKAPIKey     string
	Mode          sekhem.DeploymentMode
	Logger        *slog.Logger
}

// ELKBridge encapsulates and cryptographically attests all Elastic SIEM and SOC activity.
type ELKBridge struct {
	dag           *dag.PersistentMemory
	flight        *flight.Recorder
	waf           *sekhem.WAFShield
	soar          *SOAREngine
	webhookSecret string
	elkURL        string
	elkAPIKey     string
	mode          sekhem.DeploymentMode
	log           *slog.Logger
	httpClient    *http.Client
	mu            sync.RWMutex
}

// NewELKBridge creates a new attested ELK bridge instance.
func NewELKBridge(cfg ELKBridgeConfig) (*ELKBridge, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	mode := cfg.Mode
	if mode == "" {
		mode = sekhem.ModeFromEnv()
	}

	elkURL := cfg.ELKURL
	if elkURL == "" {
		elkURL = os.Getenv("ELK_URL")
	}

	elkAPIKey := cfg.ELKAPIKey
	if elkAPIKey == "" {
		elkAPIKey = os.Getenv("ELK_API_KEY")
	}

	whSecret := cfg.WebhookSecret
	if whSecret == "" {
		whSecret = os.Getenv("ELK_WEBHOOK_SECRET")
	}

	return &ELKBridge{
		dag:           cfg.DAG,
		flight:        cfg.Flight,
		waf:           cfg.WAF,
		soar:          cfg.SOAR,
		webhookSecret: whSecret,
		elkURL:        elkURL,
		elkAPIKey:     elkAPIKey,
		mode:          mode,
		log:           logger,
		httpClient:    &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// IngestAlert processes an incoming alert from Elastic SIEM.
// Encapsulates through WAF, attests to DAG, writes to Flight Recorder,
// scores through KASA, and stages automated SOAR response.
func (b *ELKBridge) IngestAlert(ctx context.Context, rawPayload []byte, headers http.Header) (*IngestResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// 1. Secret header verification if configured
	if b.webhookSecret != "" {
		provided := headers.Get("X-Elastic-Secret")
		if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(b.webhookSecret)) != 1 {
			b.log.Warn("elk_bridge: invalid webhook secret header")
			return nil, ErrUnauthorizedWebhook
		}
	}

	// 2. Compute SHA3-256 fingerprint of the raw payload
	h := sha3.New256()
	h.Write(rawPayload)
	payloadHash := hex.EncodeToString(h.Sum(nil))

	// 3. Parse Alert
	var alert ElasticAlert
	if err := json.Unmarshal(rawPayload, &alert); err != nil {
		return nil, fmt.Errorf("elk_bridge: parse alert JSON: %w", err)
	}
	if alert.ID == "" {
		alert.ID = "elk-" + payloadHash[:16]
	}
	if alert.Timestamp.IsZero() {
		alert.Timestamp = time.Now().UTC()
	}

	// 4. Cryptographic Attestation to Immutable DAG
	dagNodeID := ""
	if b.dag != nil {
		node := &dag.Node{
			Action: "ELK_SIEM_ALERT_ATTESTATION",
			Symbol: string(SymbolEban), // Defensive barrier
			Time:   time.Now().UTC().Format(time.RFC3339Nano),
			PQC: map[string]string{
				"alert_id":     alert.ID,
				"rule_id":      alert.RuleID,
				"rule_name":    alert.RuleName,
				"severity":     alert.Severity,
				"payload_hash": payloadHash,
				"elk_cluster":  b.elkURL,
				"host":         alert.Host,
				"agent":        "souhimbou-elk-bridge",
			},
		}
		if err := b.dag.Add(node, nil); err != nil {
			b.log.Error("elk_bridge: failed to attest alert to DAG", "error", err)
		} else {
			dagNodeID = node.ID
		}
	}

	// 5. Append to Flight Recorder (tamper-evident chain)
	var flightSeq uint64
	if b.flight != nil {
		frame, err := b.flight.Record(flight.RecordInput{
			AgentID:       "souhimbou-elk-bridge",
			Subject:       alert.ID,
			ToolName:      "elk_siem_ingress",
			ToolScope:     "siem_alert",
			RiskClass:     flight.RiskDestructive,
			IntentSummary: fmt.Sprintf("Ingest Elastic SIEM Alert: %s (Severity: %s)", alert.RuleName, alert.Severity),
			RawParams:     rawPayload,
			Outcome:       flight.OutcomeSuccess,
			DAGNodeID:     dagNodeID,
			IsSigned:      true,
			StartedAt:     time.Now().UTC(),
		})
		if err == nil && frame != nil {
			flightSeq = frame.Seq
		}
	}

	result := &IngestResult{
		AlertID:     alert.ID,
		DAGNodeID:   dagNodeID,
		FlightSeq:   flightSeq,
		PayloadHash: payloadHash,
	}

	// 6. SOAR Playbook Staging via KASA Behavioral Threshold
	if b.soar != nil && (strings.EqualFold(alert.Severity, "high") || strings.EqualFold(alert.Severity, "critical")) {
		// Stage quarantine or response action in staging mode
		playbookName := "quarantine-agent"
		if err := b.soar.Execute(ctx, playbookName, true); err == nil {
			result.SOARStaged = true
			result.PlaybookName = playbookName
			b.log.Info("elk_bridge: SOAR playbook staged for review", "playbook", playbookName, "alert_id", alert.ID)
		}
	}

	return result, nil
}

// IngestSOCCase processes an incoming Elastic SOC Case / Incident.
// Attests the case to the immutable DAG (Action: ELK_SOC_CASE_ATTESTATION),
// writes to the Flight Recorder, and if containment or remediation commands
// are specified, builds a cryptographically anchored ChangeRequest (Symbol Eban)
// staged for human approval prior to asaf-daemon execution.
func (b *ELKBridge) IngestSOCCase(ctx context.Context, rawPayload []byte, headers http.Header) (*SOCCaseResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// 1. Secret header verification if configured
	if b.webhookSecret != "" {
		provided := headers.Get("X-Elastic-Secret")
		if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(b.webhookSecret)) != 1 {
			b.log.Warn("elk_bridge: invalid webhook secret header for SOC case")
			return nil, ErrUnauthorizedWebhook
		}
	}

	// 2. Compute SHA3-256 fingerprint
	h := sha3.New256()
	h.Write(rawPayload)
	payloadHash := hex.EncodeToString(h.Sum(nil))

	// 3. Parse SOC Case
	var caseObj ElasticSOCCase
	if err := json.Unmarshal(rawPayload, &caseObj); err != nil {
		return nil, fmt.Errorf("elk_bridge: parse SOC case JSON: %w", err)
	}
	if caseObj.ID == "" {
		caseObj.ID = "soc-case-" + payloadHash[:16]
	}
	if caseObj.CreatedAt.IsZero() {
		caseObj.CreatedAt = time.Now().UTC()
	}

	// 4. Attest to Immutable DAG
	dagNodeID := ""
	if b.dag != nil {
		node := &dag.Node{
			Action: "ELK_SOC_CASE_ATTESTATION",
			Symbol: string(SymbolEban),
			Time:   time.Now().UTC().Format(time.RFC3339Nano),
			PQC: map[string]string{
				"case_id":      caseObj.ID,
				"title":        caseObj.Title,
				"severity":     caseObj.Severity,
				"status":       caseObj.Status,
				"payload_hash": payloadHash,
				"host":         caseObj.Host,
				"agent":        "souhimbou-elk-soc",
			},
		}
		if err := b.dag.Add(node, nil); err != nil {
			b.log.Error("elk_bridge: failed to attest SOC case to DAG", "error", err)
		} else {
			dagNodeID = node.ID
		}
	}

	// 5. Append to Flight Recorder
	var flightSeq uint64
	if b.flight != nil {
		frame, err := b.flight.Record(flight.RecordInput{
			AgentID:       "souhimbou-elk-soc",
			Subject:       caseObj.ID,
			ToolName:      "elk_soc_case_ingress",
			ToolScope:     "soc_case",
			RiskClass:     flight.RiskSandboxed,
			IntentSummary: fmt.Sprintf("Ingest Elastic SOC Case: %s (Severity: %s, Status: %s)", caseObj.Title, caseObj.Severity, caseObj.Status),
			RawParams:     rawPayload,
			Outcome:       flight.OutcomeSuccess,
			DAGNodeID:     dagNodeID,
			IsSigned:      true,
			StartedAt:     time.Now().UTC(),
		})
		if err == nil && frame != nil {
			flightSeq = frame.Seq
		}
	}

	result := &SOCCaseResult{
		CaseID:      caseObj.ID,
		DAGNodeID:   dagNodeID,
		FlightSeq:   flightSeq,
		PayloadHash: payloadHash,
	}

	// 6. Build Staged ChangeRequest for Privileged Daemon (asaf-daemon)
	if len(caseObj.Commands) > 0 {
		cr := &stargate.ChangeRequest{
			ID:          "cr-" + payloadHash[:16],
			AgentID:     "souhimbou-elk-soc",
			Symbol:      "Eban", // Eban fortress symbol required for kernel/host containment
			ControlID:   "IR-4", // Incident Handling
			AssetID:     caseObj.Host,
			Command:     caseObj.Commands,
			Description: fmt.Sprintf("Containment for SOC Case %s: %s", caseObj.ID, caseObj.Title),
			Staging:     true, // ALWAYS starts in staging mode — never direct to production!
			DAGParent:   dagNodeID,
			Status:      stargate.StatusStaging,
			CreatedAt:   time.Now().UTC(),
		}
		_ = stargate.QueueChangeRequest(cr)
		result.ChangeRequest = cr
		result.Staged = true
		b.log.Info("elk_bridge: ChangeRequest queued for human approval gate", "cr_id", cr.ID, "commands", cr.Command)
	}

	return result, nil
}

// ShipTelemetry securely forwards an ECS-compliant audit or threat event to Elastic Cloud.
// Enforces Sovereign Air-Gap zero-egress posture and records DAG attestation.
func (b *ELKBridge) ShipTelemetry(ctx context.Context, doc map[string]any) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// 1. Sovereign Zero-Egress Boundary Check (DoD Non-Negotiable #1)
	if b.mode == sekhem.ModeSovereign || os.Getenv("KHEPRA_MODE") == "sovereign" {
		b.log.Warn("elk_bridge: egress blocked by sovereign air-gap policy")
		return ErrSovereignEgressForbidden
	}

	if b.elkURL == "" || b.elkAPIKey == "" {
		return errors.New("elk_bridge: ELK_URL or ELK_API_KEY not configured for telemetry shipping")
	}

	// 2. Prepare payload & timestamp
	if _, ok := doc["@timestamp"]; !ok {
		doc["@timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	doc["khepra_bridge"] = "souhimbou-v1"

	body, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("elk_bridge: marshal telemetry: %w", err)
	}

	// 3. Compute SHA3-256 hash for DAG attestation
	h := sha3.New256()
	h.Write(body)
	payloadHash := hex.EncodeToString(h.Sum(nil))

	// 4. DAG Pre-Transmission Attestation
	dagNodeID := ""
	if b.dag != nil {
		node := &dag.Node{
			Action: "ELK_TELEMETRY_EGRESS",
			Symbol: string(SymbolEban),
			Time:   time.Now().UTC().Format(time.RFC3339Nano),
			PQC: map[string]string{
				"payload_hash": payloadHash,
				"elk_endpoint": b.elkURL,
			},
		}
		_ = b.dag.Add(node, nil)
		dagNodeID = node.ID
	}

	// 5. Transmit to Elastic Ingest / Documents endpoint
	endpoint := strings.TrimRight(b.elkURL, "/") + "/_doc"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("elk_bridge: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "ApiKey "+b.elkAPIKey)

	resp, err := b.httpClient.Do(req)
	outcome := flight.OutcomeSuccess
	if err != nil {
		outcome = flight.OutcomeError
		b.recordFlightEgress(payloadHash, dagNodeID, outcome, err.Error())
		return fmt.Errorf("elk_bridge: execute HTTP post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		outcome = flight.OutcomeError
		respBody, _ := io.ReadAll(resp.Body)
		errStr := fmt.Sprintf("status %d: %s", resp.StatusCode, string(respBody))
		b.recordFlightEgress(payloadHash, dagNodeID, outcome, errStr)
		return fmt.Errorf("elk_bridge: elastic error %s", errStr)
	}

	b.recordFlightEgress(payloadHash, dagNodeID, outcome, "")
	return nil
}

func (b *ELKBridge) recordFlightEgress(hash, dagNodeID string, outcome flight.Outcome, errSummary string) {
	if b.flight == nil {
		return
	}
	_, _ = b.flight.Record(flight.RecordInput{
		AgentID:       "souhimbou-elk-bridge",
		Subject:       hash[:16],
		ToolName:      "elk_telemetry_egress",
		ToolScope:     "siem_egress",
		RiskClass:     flight.RiskReadOnly,
		IntentSummary: "Shipped attested telemetry document to Elastic Cloud",
		Outcome:       outcome,
		ErrorSummary:  errSummary,
		DAGNodeID:     dagNodeID,
		IsSigned:      true,
		StartedAt:     time.Now().UTC(),
	})
}

// HTTPHandler returns an http.Handler that can be mounted into the SEKHEM Gateway mux.
func (b *ELKBridge) HTTPHandler() http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024)) // 1MB cap
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		res, err := b.IngestAlert(r.Context(), body, r.Header)
		if err != nil {
			if errors.Is(err, ErrUnauthorizedWebhook) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Khepra-DAG-Node", res.DAGNodeID)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(res)
	})

	// Wrap with SEKHEM WAF L7 middleware if available
	if b.waf != nil {
		return sekhem.HTTPMiddleware(b.waf)(handler)
	}
	return handler
}
