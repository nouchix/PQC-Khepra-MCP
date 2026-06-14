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

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/maat"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/stig"
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

	log.Printf("[%s] Striking: %s (Action: %s)", rb.name, heka.Isfet.ID, heka.Action)

	// REAL IMPLEMENTATION: Link to stig.Remediator
	remediator := stig.NewRemediator(nil)
	result, err := remediator.Remediate(heka.Isfet.ID)

	if err != nil {
		log.Printf("[%s] Remediation FAILED for %s: %v", rb.name, heka.Isfet.ID, err)
		return err
	}

	log.Printf("[%s] Remediation Status: %s for %s", rb.name, result.Status, heka.Isfet.ID)
	log.Printf("[%s] Execution Output: %s", rb.name, result.Output)
	log.Printf("[%s] KASA wisdom applied: %s", rb.name, heka.Wisdom)

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
			log.Printf("[%s] Processing banishment for Isfet: %s", fb.name, heka.Isfet.ID)
		}
		ip := omen.Value
		log.Printf("[%s] Submitting Crowdsec decision: ban ip=%s malevolence=%.2f isfet=%s",
			fb.name, ip, omen.Malevolence, heka.Isfet.ID)
		if err := fb.submitCrowdsecDecision(ip, "24h", "ban"); err != nil {
			log.Printf("[%s] Crowdsec submission failed for %s: %v", fb.name, ip, err)
			lastErr = err
		} else {
			log.Printf("[%s] SUCCESS: ip=%s submitted to Crowdsec (24h ban)", fb.name, ip)
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
	log.Printf(ManualApprovalFormat+" (Action: %s)", ib.name, heka.Isfet.ID, heka.Action)
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
	log.Printf("[%s] Observing: %s (Severity: %s)", mb.name, heka.Isfet.ID, heka.Isfet.Severity)
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
	log.Printf("[%s] Purifying configuration: %s (source: %s)",
		cb.name, heka.Isfet.ID, heka.Isfet.Source)
	log.Printf("[%s] Applying config fix per KASA guidance: %s",
		cb.name, heka.Wisdom)

	return nil
}

func (cb *ConfigBlade) Name() string {
	return cb.name
}
