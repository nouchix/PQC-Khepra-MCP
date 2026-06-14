package gateway

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Agent represents a connected Khepra Scarab Agent
type Agent struct {
	ID             string
	OrganizationID string
	MachineID      string
	Conn           *websocket.Conn
	LastSeen       time.Time
	mu             sync.Mutex
}

// AgentManager handles the lifecycle of remote agent links
type AgentManager struct {
	agents map[string]*Agent // Key: MachineID
	mu     sync.RWMutex
}

// NewAgentManager creates a new manager for remote links
func NewAgentManager() *AgentManager {
	return &AgentManager{
		agents: make(map[string]*Agent),
	}
}

// RegisterAgent adds a new agent connection to the demarc registry
func (m *AgentManager) RegisterAgent(agent *Agent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.agents[agent.MachineID] = agent
	log.Printf("[DEMARC] Agent %s registered from %s", agent.MachineID, agent.Conn.RemoteAddr())
}

// ExecuteOnAgent sends a command to a remote agent across the link
func (m *AgentManager) ExecuteOnAgent(machineID string, command string, args []string) (string, error) {
	m.mu.RLock()
	agent, ok := m.agents[machineID]
	m.mu.RUnlock()

	if !ok {
		return "", fmt.Errorf("agent %s not connected to demarc", machineID)
	}

	agent.mu.Lock()
	defer agent.mu.Unlock()

	// Prepare payload (signed in real scenario)
	payload := map[string]interface{}{
		"type":    "execute",
		"command": command,
		"args":    args,
		"sent_at": time.Now().Unix(),
	}

	if err := agent.Conn.WriteJSON(payload); err != nil {
		return "", fmt.Errorf("link failure: %w", err)
	}

	// 10-second read deadline for the agent's execution response over the WebSocket link.
	agent.Conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var resp map[string]interface{}
	if err := agent.Conn.ReadJSON(&resp); err != nil {
		return "", fmt.Errorf("response timeout on link: %w", err)
	}

	if status, ok := resp["status"].(string); ok && status == "error" {
		return "", fmt.Errorf("execution error: %v", resp["error"])
	}

	return resp["output"].(string), nil
}
