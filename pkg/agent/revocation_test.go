package agent

import (
	"testing"
)

func TestRevocation(t *testing.T) {
	agent := &AgentState{
		ID:     "agent-01",
		Status: StatusActive,
	}

	// 1. Nominal Heartbeat
	agent.ProcessHeartbeatResponse(HeartbeatResponse{Status: StatusActive})
	if !agent.IsOperational() {
		t.Error("Agent should be active")
	}

	// 2. Suspend
	agent.ProcessHeartbeatResponse(HeartbeatResponse{Status: StatusSuspended})
	if agent.Status != StatusSuspended {
		t.Errorf("Expected status Suspended, got %s", agent.Status)
	}
	if agent.IsOperational() {
		t.Error("Suspended agent should not be operational")
	}

	// 3. Reactivate
	agent.ProcessHeartbeatResponse(HeartbeatResponse{Status: StatusActive})
	if agent.Status != StatusActive {
		t.Errorf("Expected status Active, got %s", agent.Status)
	}

	// 4. Revoke
	agent.ProcessHeartbeatResponse(HeartbeatResponse{Status: StatusRevoked})
	if agent.Status != StatusRevoked {
		t.Errorf("Expected status Revoked, got %s", agent.Status)
	}
	if agent.RevokedAt.IsZero() {
		t.Error("RevokedAt timestamp should be set")
	}

	// 5. Attempt Reactivation (Should Fail - Revocation is permanent)
	agent.ProcessHeartbeatResponse(HeartbeatResponse{Status: StatusActive})
	if agent.Status != StatusRevoked {
		t.Error("Revoked agent should NOT become active again")
	}
}
