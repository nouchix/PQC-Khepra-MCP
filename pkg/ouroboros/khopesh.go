package ouroboros

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/maat"
	khlog "github.com/nouchix/PQC-Khepra-MCP/pkg/logging"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/stig"
)

// KhopeshBlade represents an instrument of action
// Khopesh: Ancient Egyptian sword, symbol of authority
const ManualApprovalFormat = "[%s] Heka requires manual approval: %s"

type KhopeshBlade interface {
	CanStrike(heka maat.Heka) bool
	Strike(heka maat.Heka) error
	Name() string
}

// RemediationBlade auto-remediates issues
type RemediationBlade struct {
	name string
}

func NewRemediationBlade() *RemediationBlade {
	return &RemediationBlade{
		name: "khopesh-remediation",
	}
}

func (rb *RemediationBlade) CanStrike(heka maat.Heka) bool {
	return heka.Action == maat.ActionPurify
}

func (rb *RemediationBlade) Strike(heka maat.Heka) error {
	if !heka.Autonomous {
		log.Printf(ManualApprovalFormat, rb.name, heka.Isfet.ID)
		return nil
	}

	log.Printf("[%q] Striking: %q (Action: %q)", rb.name, khlog.SanitizeForLog(heka.Isfet.ID), heka.Action)

	// REAL IMPLEMENTATION: Link to stig.Remediator
	remediator := stig.NewRemediator(nil)
	result, err := remediator.Remediate(heka.Isfet.ID)

	if err != nil {
		log.Printf("[%q] Remediation FAILED for %q: %v", rb.name, khlog.SanitizeForLog(heka.Isfet.ID), khlog.SanitizeForLog(err.Error()))
		return err
	}

	log.Printf("[%q] Remediation Status: %q for %q", rb.name, result.Status, khlog.SanitizeForLog(heka.Isfet.ID))
	log.Printf("[%q] Execution Output: %q", rb.name, khlog.SanitizeForLog(result.Output))
	log.Printf("[%q] KASA wisdom applied: %q", rb.name, khlog.SanitizeForLog(heka.Wisdom))

	return nil
}

func (rb *RemediationBlade) Name() string {
	return rb.name
}

// FirewallBlade submits IP ban decisions to the Crowdsec LAPI bouncer endpoint.
//
// Crowdsec is the single enforcement authority for IP blocklists on the VPS.
// SEKHEM / Ouroboros is a signal source; Crowdsec is the actuator.
// This replaces the former iptables exec call which conflicted with Crowdsec's
// own blocklist management (two independent systems → rule conflicts, impossible
// incident response).
//
// Required environment variables:
//
//	CROWDSEC_LAPI_URL      — Crowdsec LAPI base URL (default: http://localhost:8080)
//	CROWDSEC_BOUNCER_KEY   — bouncer API key registered via `cscli bouncers add`
type FirewallBlade struct {
	name           string
	crowdsecURL    string
	crowdsecAPIKey string
	httpClient     *http.Client
}

func NewFirewallBlade() *FirewallBlade {
	csURL := os.Getenv("CROWDSEC_LAPI_URL")
	if csURL == "" {
		csURL = "http://localhost:8080"
	}
	csKey := os.Getenv("CROWDSEC_BOUNCER_KEY")
	if csKey == "" {
		log.Println("[khopesh-firewall] WARNING: CROWDSEC_BOUNCER_KEY not set — IP bans will be logged but not enforced")
	}
	return &FirewallBlade{
		name:           "khopesh-firewall",
		crowdsecURL:    csURL,
		crowdsecAPIKey: csKey,
		httpClient:     &http.Client{Timeout: 5 * time.Second},
	}
}

func (fb *FirewallBlade) CanStrike(heka maat.Heka) bool {
	return heka.Action == maat.ActionBanish
}

func (fb *FirewallBlade) Strike(heka maat.Heka) error {
	if !heka.Autonomous {
		log.Printf(ManualApprovalFormat, fb.name, heka.Isfet.ID)
		return nil
	}

	// Collect actionable IP omens first — only log if there is at least one.
	// CVE/STIG findings route here via ActionBanish but carry no IP omens;
	// logging "Processing banishment" for them produces misleading journal noise.
	var lastErr error
	submitted := 0
	for _, omen := range heka.Isfet.Omens {
		if omen.Name != "ip" || omen.Malevolence < 0.7 {
			continue
		}
		if submitted == 0 {
			log.Printf("[%q] Processing banishment for Isfet: %q", fb.name, heka.Isfet.ID)
		}
		ip := omen.Value
		log.Printf("[%q] Submitting Crowdsec decision: ban ip=%q malevolence=%.2f isfet=%q",
			fb.name, khlog.SanitizeForLog(ip), omen.Malevolence, khlog.SanitizeForLog(heka.Isfet.ID))
		if err := fb.submitCrowdsecDecision(ip, "24h", "ban"); err != nil {
			log.Printf("[%q] Crowdsec submission failed for %q: %v", fb.name, ip, err)
			lastErr = err
		} else {
			log.Printf("[%q] SUCCESS: ip=%q submitted to Crowdsec (24h ban)", fb.name, ip)
			submitted++
		}
	}

	return lastErr
}

// submitCrowdsecDecision POSTs a single IP decision to the Crowdsec LAPI.
func (fb *FirewallBlade) submitCrowdsecDecision(ip, duration, decType string) error {
	if fb.crowdsecAPIKey == "" {
		return fmt.Errorf("CROWDSEC_BOUNCER_KEY not configured — cannot enforce ban for %s", ip)
	}

	payload, err := json.Marshal([]map[string]string{
		{"duration": duration, "scope": "Ip", "type": decType, "value": ip},
	})
	if err != nil {
		return fmt.Errorf("marshal decision: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost,
		fb.crowdsecURL+"/v1/decisions",
		bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Api-Key", fb.crowdsecAPIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := fb.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("Crowdsec LAPI POST: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("Crowdsec returned HTTP %d: %s", resp.StatusCode, body)
	}
	return nil
}

func (fb *FirewallBlade) Name() string {
	return fb.name
}

// IsolationBlade isolates network segments
type IsolationBlade struct {
	name string
}

func NewIsolationBlade() *IsolationBlade {
	return &IsolationBlade{
		name: "khopesh-isolation",
	}
}

func (ib *IsolationBlade) CanStrike(heka maat.Heka) bool {
	return heka.Action == maat.ActionSeal || heka.Action == maat.ActionIsolate
}

func (ib *IsolationBlade) Strike(heka maat.Heka) error {
	// Isolation always requires manual approval (too disruptive)
	log.Printf(ManualApprovalFormat+" (Action: %q)", ib.name, heka.Isfet.ID, heka.Action)
	return nil
}

func (ib *IsolationBlade) Name() string {
	return ib.name
}

// MonitorBlade observes without action
type MonitorBlade struct {
	name string
}

func NewMonitorBlade() *MonitorBlade {
	return &MonitorBlade{
		name: "khopesh-monitor",
	}
}

func (mb *MonitorBlade) CanStrike(heka maat.Heka) bool {
	return heka.Action == maat.ActionObserve
}

func (mb *MonitorBlade) Strike(heka maat.Heka) error {
	log.Printf("[%q] Observing: %q (Severity: %q)", mb.name, heka.Isfet.ID, heka.Isfet.Severity)
	return nil
}

func (mb *MonitorBlade) Name() string {
	return mb.name
}

// ConfigBlade manages configuration changes
type ConfigBlade struct {
	name string
}

func NewConfigBlade() *ConfigBlade {
	return &ConfigBlade{
		name: "khopesh-config",
	}
}

func (cb *ConfigBlade) CanStrike(heka maat.Heka) bool {
	return heka.Action == maat.ActionPurify
}

func (cb *ConfigBlade) Strike(heka maat.Heka) error {
	if !heka.Autonomous {
		log.Printf(ManualApprovalFormat, cb.name, heka.Isfet.ID)
		return nil
	}

	// Apply configuration remediation based on KASA recommendation
	log.Printf("[%q] Purifying configuration: %q (source: %q)",
		cb.name, heka.Isfet.ID, heka.Isfet.Source)
	log.Printf("[%q] Applying config fix per KASA guidance: %q",
		cb.name, heka.Wisdom)

	return nil
}

func (cb *ConfigBlade) Name() string {
	return cb.name
}
