package ir

import "time"

// Severity levels matching NIST 800-61
type Severity string

const (
	SevCritical Severity = "CRITICAL"
	SevHigh     Severity = "HIGH"
	SevMedium   Severity = "MEDIUM"
	SevLow      Severity = "LOW"
)

// Status tracks the incident lifecycle
type Status string

const (
	StatusOpen       Status = "OPEN"
	StatusInProgress Status = "IN_PROGRESS"
	StatusContained  Status = "CONTAINED"
	StatusClosed     Status = "CLOSED"
)

// Incident represents a security incident
type Incident struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    Severity  `json:"severity"`
	Status      Status    `json:"status"`
	Type        string    `json:"type"` // e.g., MALWARE, PHISHING, DDOS, UNKNOWN
	DetectedAt  time.Time `json:"detected_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	IOCs        []IOC     `json:"iocs"`
	Events      []Event   `json:"timeline"`
	PlaybookID  string    `json:"playbook_id,omitempty"`
}

// IOC represents an Indicator of Compromise
type IOC struct {
	Type  string `json:"type"` // IP, HASH, DOMAIN, URL, EMAIL
	Value string `json:"value"`
	Desc  string `json:"description,omitempty"`
}

// Event represents an action or status change in the incident timeline
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message"`
	Actor     string    `json:"actor"` // "AGI", "User", "System"
}
