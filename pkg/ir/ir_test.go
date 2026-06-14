package ir

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// generateTestKeys generates real ML-DSA-65 (FIPS 204) keys for testing
// TRL 10: No mocks, no stubs - real PQC cryptography
func generateTestKeys(t *testing.T) (pubKey []byte, privKey []byte) {
	t.Helper()

	pk, sk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ML-DSA-65 key pair: %v", err)
	}

	pubKey, err = pk.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	privKey, err = sk.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	return pubKey, privKey
}

func TestIncidentTypes(t *testing.T) {
	// Test severity levels
	severities := []Severity{
		SevCritical,
		SevHigh,
		SevMedium,
		SevLow,
	}

	for _, s := range severities {
		if s == "" {
			t.Error("severity should not be empty")
		}
	}

	// Test status values
	statuses := []Status{
		StatusOpen,
		StatusInProgress,
		StatusContained,
		StatusClosed,
	}

	for _, s := range statuses {
		if s == "" {
			t.Error("status should not be empty")
		}
	}
}

func TestIncidentStructure(t *testing.T) {
	incident := &Incident{
		ID:          "inc-123",
		Title:       "Test Incident",
		Description: "A test security incident",
		Severity:    SevHigh,
		Status:      StatusOpen,
		Type:        "malware",
		DetectedAt:  time.Now(),
		UpdatedAt:   time.Now(),
		IOCs: []IOC{
			{Type: "ip", Value: "192.168.1.100", Desc: "Malicious IP"},
			{Type: "hash", Value: "abc123", Desc: "Malware hash"},
		},
		Events: []Event{
			{Timestamp: time.Now(), Message: "Incident created", Actor: "System"},
		},
	}

	if incident.ID == "" {
		t.Error("expected non-empty incident ID")
	}

	if len(incident.IOCs) != 2 {
		t.Errorf("expected 2 IOCs, got %d", len(incident.IOCs))
	}

	if len(incident.Events) != 1 {
		t.Errorf("expected 1 event, got %d", len(incident.Events))
	}
}

func TestIOCStructure(t *testing.T) {
	ioc := IOC{
		Type:  "domain",
		Value: "malicious.example.com",
		Desc:  "C2 domain",
	}

	if ioc.Type == "" {
		t.Error("expected non-empty IOC type")
	}

	if ioc.Value == "" {
		t.Error("expected non-empty IOC value")
	}
}

func TestEventStructure(t *testing.T) {
	event := Event{
		Timestamp: time.Now(),
		Message:   "Status changed to Contained",
		Actor:     "security-analyst",
	}

	if event.Message == "" {
		t.Error("expected non-empty event message")
	}

	if event.Actor == "" {
		t.Error("expected non-empty event actor")
	}

	if event.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
}

func TestNewManager(t *testing.T) {
	// Use in-memory DAG for testing (NOT production GlobalDAG)
	// This ensures test data never pollutes the forensic-grade production DAG
	store := dag.NewMemory()
	mgr := NewManager(store)

	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}

	if mgr.store == nil {
		t.Error("expected store to be set")
	}
}

func TestManager_CreateIncident(t *testing.T) {
	// Use in-memory DAG for testing (NOT production GlobalDAG)
	// This ensures test data never pollutes the forensic-grade production DAG
	store := dag.NewMemory()
	mgr := NewManager(store)

	_, privKey := generateTestKeys(t)

	incident, err := mgr.CreateIncident(
		"Ransomware Detection Alert",
		"Automated detection of ransomware behavior on workstation WS-001",
		SevCritical,
		"ransomware",
		privKey,
	)

	if err != nil {
		t.Fatalf("CreateIncident failed: %v", err)
	}

	if incident == nil {
		t.Fatal("expected non-nil incident")
	}

	if incident.ID == "" {
		t.Error("expected non-empty incident ID")
	}

	if incident.Title != "Ransomware Detection Alert" {
		t.Errorf("expected title 'Ransomware Detection Alert', got '%s'", incident.Title)
	}

	if incident.Severity != SevCritical {
		t.Errorf("expected severity CRITICAL, got %s", incident.Severity)
	}

	if incident.Status != StatusOpen {
		t.Errorf("expected status OPEN, got %s", incident.Status)
	}

	if len(incident.Events) != 1 {
		t.Error("expected initial event to be added")
	}

	// Verify the event was properly created
	if incident.Events[0].Actor != "System" {
		t.Errorf("expected event actor 'System', got '%s'", incident.Events[0].Actor)
	}
}

func TestManager_AddIOC(t *testing.T) {
	// Use in-memory DAG for testing (NOT production GlobalDAG)
	store := dag.NewMemory()
	mgr := NewManager(store)

	_, privKey := generateTestKeys(t)

	// First create an incident
	incident, err := mgr.CreateIncident(
		"Phishing Campaign Detection",
		"Detected phishing email campaign targeting finance department",
		SevHigh,
		"phishing",
		privKey,
	)
	if err != nil {
		t.Fatalf("CreateIncident failed: %v", err)
	}

	// Add IOC
	err = mgr.AddIOC(incident, "url", "http://malicious-phishing.com/login", "Phishing URL targeting corporate SSO", privKey)
	if err != nil {
		t.Fatalf("AddIOC failed: %v", err)
	}

	if len(incident.IOCs) != 1 {
		t.Errorf("expected 1 IOC, got %d", len(incident.IOCs))
	}

	ioc := incident.IOCs[0]
	if ioc.Type != "url" {
		t.Errorf("expected IOC type 'url', got '%s'", ioc.Type)
	}

	if ioc.Value != "http://malicious-phishing.com/login" {
		t.Errorf("expected IOC value mismatch")
	}

	// Should have added an event (create + IOC add)
	if len(incident.Events) != 2 {
		t.Errorf("expected 2 events after adding IOC, got %d", len(incident.Events))
	}

	// Add another IOC
	time.Sleep(1 * time.Millisecond) // Ensure DAG node uniqueness
	err = mgr.AddIOC(incident, "email", "attacker@suspicious-domain.com", "Sender address", privKey)
	if err != nil {
		t.Fatalf("Second AddIOC failed: %v", err)
	}

	if len(incident.IOCs) != 2 {
		t.Errorf("expected 2 IOCs after second add, got %d", len(incident.IOCs))
	}
}

func TestManager_UpdateStatus(t *testing.T) {
	// Use in-memory DAG for testing (NOT production GlobalDAG)
	store := dag.NewMemory()
	mgr := NewManager(store)

	_, privKey := generateTestKeys(t)

	incident, err := mgr.CreateIncident(
		"DDoS Attack Detection",
		"Detected volumetric DDoS attack on external web servers",
		SevCritical,
		"ddos",
		privKey,
	)
	if err != nil {
		t.Fatalf("CreateIncident failed: %v", err)
	}

	// Update to In Progress
	err = mgr.UpdateStatus(incident, StatusInProgress, "SOC analyst assigned, initiating response", privKey)
	if err != nil {
		t.Fatalf("UpdateStatus to InProgress failed: %v", err)
	}

	if incident.Status != StatusInProgress {
		t.Errorf("expected status IN_PROGRESS, got %s", incident.Status)
	}

	// Update to Contained
	err = mgr.UpdateStatus(incident, StatusContained, "Upstream filtering activated, attack mitigated", privKey)
	if err != nil {
		t.Fatalf("UpdateStatus to Contained failed: %v", err)
	}

	if incident.Status != StatusContained {
		t.Errorf("expected status CONTAINED, got %s", incident.Status)
	}

	// Verify events were added
	hasAGIEvents := false
	for _, event := range incident.Events {
		if event.Actor == "AGI" {
			hasAGIEvents = true
			break
		}
	}

	if !hasAGIEvents {
		t.Error("expected AGI events from status updates")
	}
}

func TestIncidentLifecycle(t *testing.T) {
	// Use in-memory DAG for testing (NOT production GlobalDAG)
	// This ensures test data never pollutes the forensic-grade production DAG
	store := dag.NewMemory()
	mgr := NewManager(store)

	_, privKey := generateTestKeys(t)

	// 1. Create incident - Initial Detection
	incident, err := mgr.CreateIncident(
		"Advanced Persistent Threat Detection",
		"SIEM correlation detected APT-style lateral movement from compromised workstation",
		SevCritical,
		"apt",
		privKey,
	)
	if err != nil {
		t.Fatalf("CreateIncident failed: %v", err)
	}

	// 2. Add IOCs discovered during initial triage
	iocs := []struct {
		iocType string
		value   string
		desc    string
	}{
		{"hash", "sha256:a1b2c3d4e5f6789012345678901234567890abcd", "Malicious DLL hash"},
		{"ip", "203.0.113.42", "C2 server IP"},
		{"domain", "c2.malicious-apt.net", "Command and control domain"},
		{"ip", "10.0.50.100", "Patient zero workstation"},
	}

	for _, ioc := range iocs {
		err = mgr.AddIOC(incident, ioc.iocType, ioc.value, ioc.desc, privKey)
		if err != nil {
			t.Fatalf("AddIOC failed for %s: %v", ioc.value, err)
		}
		// Small delay to ensure DAG node uniqueness (timestamp_ns)
		time.Sleep(1 * time.Millisecond)
	}

	if len(incident.IOCs) != 4 {
		t.Errorf("expected 4 IOCs, got %d", len(incident.IOCs))
	}

	// 3. Status progression through incident response lifecycle
	statusProgression := []struct {
		status Status
		msg    string
	}{
		{StatusInProgress, "IR team activated, beginning forensic analysis"},
		{StatusContained, "Affected systems isolated, C2 communication blocked at perimeter"},
		{StatusClosed, "Incident resolved - root cause analysis complete, lessons learned documented"},
	}

	for _, sp := range statusProgression {
		err = mgr.UpdateStatus(incident, sp.status, sp.msg, privKey)
		if err != nil {
			t.Fatalf("UpdateStatus to %s failed: %v", sp.status, err)
		}
	}

	// 4. Verify final state
	if incident.Status != StatusClosed {
		t.Errorf("expected final status CLOSED, got %s", incident.Status)
	}

	if len(incident.IOCs) != 4 {
		t.Errorf("expected 4 IOCs in final state, got %d", len(incident.IOCs))
	}

	// Expected events: 1 create + 4 IOC adds + 3 status changes = 8
	expectedEvents := 8
	if len(incident.Events) != expectedEvents {
		t.Errorf("expected %d events in timeline, got %d", expectedEvents, len(incident.Events))
	}

	// Verify timeline integrity
	for i := 1; i < len(incident.Events); i++ {
		if incident.Events[i].Timestamp.Before(incident.Events[i-1].Timestamp) {
			t.Error("event timeline is not chronologically ordered")
		}
	}
}

func TestSeverityConstants(t *testing.T) {
	if SevCritical != "CRITICAL" {
		t.Errorf("expected SevCritical='CRITICAL', got '%s'", SevCritical)
	}
	if SevHigh != "HIGH" {
		t.Errorf("expected SevHigh='HIGH', got '%s'", SevHigh)
	}
	if SevMedium != "MEDIUM" {
		t.Errorf("expected SevMedium='MEDIUM', got '%s'", SevMedium)
	}
	if SevLow != "LOW" {
		t.Errorf("expected SevLow='LOW', got '%s'", SevLow)
	}
}

func TestStatusConstants(t *testing.T) {
	if StatusOpen != "OPEN" {
		t.Errorf("expected StatusOpen='OPEN', got '%s'", StatusOpen)
	}
	if StatusInProgress != "IN_PROGRESS" {
		t.Errorf("expected StatusInProgress='IN_PROGRESS', got '%s'", StatusInProgress)
	}
	if StatusContained != "CONTAINED" {
		t.Errorf("expected StatusContained='CONTAINED', got '%s'", StatusContained)
	}
	if StatusClosed != "CLOSED" {
		t.Errorf("expected StatusClosed='CLOSED', got '%s'", StatusClosed)
	}
}

func TestConcurrentIncidentCreation(t *testing.T) {
	// Use in-memory DAG for testing (NOT production GlobalDAG)
	store := dag.NewMemory()
	mgr := NewManager(store)

	// Generate keys once for all goroutines
	_, privKey := generateTestKeys(t)

	// Create multiple incidents concurrently to test thread safety
	// Each incident has unique data to avoid duplicate node conflicts in the DAG
	done := make(chan bool, 10)
	errors := make(chan error, 10)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			// Unique title and description per goroutine to ensure unique DAG nodes
			title := fmt.Sprintf("Concurrent Test Incident #%d - %d", idx, time.Now().UnixNano())
			desc := fmt.Sprintf("Testing concurrent incident creation for thread safety - instance %d", idx)
			_, err := mgr.CreateIncident(
				title,
				desc,
				SevMedium,
				"test",
				privKey,
			)
			if err != nil {
				errors <- fmt.Errorf("concurrent CreateIncident %d failed: %v", idx, err)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Check for any errors
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}

func TestIncidentWithPlaybook(t *testing.T) {
	incident := &Incident{
		ID:          "inc-playbook-test",
		Title:       "Malware Detection with Playbook",
		Description: "Testing incident with associated playbook",
		Severity:    SevHigh,
		Status:      StatusOpen,
		Type:        "malware",
		DetectedAt:  time.Now(),
		UpdatedAt:   time.Now(),
		PlaybookID:  "PB-MALWARE-001",
	}

	if incident.PlaybookID != "PB-MALWARE-001" {
		t.Errorf("expected playbook ID 'PB-MALWARE-001', got '%s'", incident.PlaybookID)
	}
}
