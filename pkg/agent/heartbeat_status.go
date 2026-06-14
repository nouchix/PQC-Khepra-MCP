package agent

import (
	"time"
)

// HeartbeatStatus defines the state of an agent
type HeartbeatStatus string

const (
	StatusActive    HeartbeatStatus = "active"
	StatusSuspended HeartbeatStatus = "suspended"
	StatusRevoked   HeartbeatStatus = "revoked"
)

// HeartbeatResponse is the payload received from SouHimBou
type HeartbeatResponse struct {
	Status      HeartbeatStatus `json:"status"`
	NextCheckIn time.Time       `json:"next_checkin"`
	Commands    []string        `json:"commands,omitempty"` // Signed commands would go here
}

// AgentState manages the local lifecycle based on backend instructions
type AgentState struct {
	ID        string
	Status    HeartbeatStatus
	LastPulse time.Time
	RevokedAt time.Time
}

// ProcessHeartbeatResponse updates the agent's state based on the backend response
func (a *AgentState) ProcessHeartbeatResponse(resp HeartbeatResponse) {
	a.LastPulse = time.Now()

	switch resp.Status {
	case StatusRevoked:
		a.Status = StatusRevoked
		a.RevokedAt = time.Now()
		// In a real implementation, this would trigger key wiping and self-destruct

	case StatusSuspended:
		if a.Status != StatusRevoked {
			a.Status = StatusSuspended
		}

	case StatusActive:
		if a.Status != StatusRevoked {
			a.Status = StatusActive
		}
	}
}

// IsOperational returns true if the agent is allowed to run tasks
func (a *AgentState) IsOperational() bool {
	return a.Status == StatusActive
}
