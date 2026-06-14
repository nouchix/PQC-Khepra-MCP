package ir

import (
	"fmt"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/lorentz"
)

// Manager handles the lifecycle of incidents
type Manager struct {
	store dag.Store
}

// NewManager creates a new Incident Manager
func NewManager(store dag.Store) *Manager {
	return &Manager{store: store}
}

// CreateIncident initializes a new incident and logs it to the DAG
func (m *Manager) CreateIncident(title, desc string, severity Severity, iType string, privKey []byte) (*Incident, error) {
	// Generate unique incident ID with nanosecond precision to avoid duplicates
	now := time.Now()
	incident := &Incident{
		ID:          fmt.Sprintf("inc-%d-%d", now.Unix(), now.Nanosecond()),
		Title:       title,
		Description: desc,
		Severity:    severity,
		Status:      StatusOpen,
		Type:        iType,
		DetectedAt:  now,
		UpdatedAt:   now,
		Events: []Event{
			{
				Timestamp: now,
				Message:   fmt.Sprintf("Incident Created: %s", title),
				Actor:     "System",
			},
		},
	}

	// Persist to DAG
	if err := m.logToDAG(incident, "incident_created", privKey); err != nil {
		return nil, err
	}

	return incident, nil
}

// AddIOC adds an Indicator of Compromise to an incident
func (m *Manager) AddIOC(incident *Incident, iocType, value, desc string, privKey []byte) error {
	ioc := IOC{Type: iocType, Value: value, Desc: desc}
	incident.IOCs = append(incident.IOCs, ioc)
	incident.UpdatedAt = time.Now()

	// Add event
	incident.Events = append(incident.Events, Event{
		Timestamp: time.Now(),
		Message:   fmt.Sprintf("IOC Added: %s (%s)", value, iocType),
		Actor:     "AGI",
	})

	return m.logToDAG(incident, "incident_updated", privKey)
}

// UpdateStatus changes the status of an incident
func (m *Manager) UpdateStatus(incident *Incident, status Status, msg string, privKey []byte) error {
	incident.Status = status
	incident.UpdatedAt = time.Now()
	incident.Events = append(incident.Events, Event{
		Timestamp: time.Now(),
		Message:   fmt.Sprintf("Status Changed to %s: %s", status, msg),
		Actor:     "AGI",
	})

	return m.logToDAG(incident, "incident_status_change", privKey)
}

// logToDAG serializes the incident and writes a signed node to the DAG
func (m *Manager) logToDAG(inc *Incident, action string, privKey []byte) error {
	// data, err := json.Marshal(inc) // unused currently

	node := dag.Node{
		Action: action,
		Symbol: "Sankofa", // "Go back and get it" - Learn from the past
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"incident_id":  inc.ID,
			"severity":     string(inc.Severity),
			"type":         inc.Type,
			"status":       string(inc.Status),
			"version":      "1.0",
			"title":        inc.Title,
			"timestamp_ns": fmt.Sprintf("%d", time.Now().UnixNano()), // Ensure uniqueness for each update
		},
	}

	// Sign and Add
	if err := node.Sign(privKey); err != nil {
		return err
	}
	return m.store.Add(&node, []string{})
}
