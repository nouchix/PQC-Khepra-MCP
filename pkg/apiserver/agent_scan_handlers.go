//go:build saas

package apiserver

// ─── Agent Scanner HTTP Surface ───────────────────────────────────────────────
//
// POST /api/v1/scan/agent        — trigger a full 6-layer scan
// GET  /api/v1/scan/agent/stream — SSE progress stream for a running scan
// GET  /api/v1/scan/agent/:id   — fetch completed report (authenticated)
//
// Uses the real souhimbou.AgentScanner and souhimbou.AgentTarget types from
// pkg/souhimbou/agent_scanner.go.  The Fabric and DAGStore are nil when no
// SouHimBou agent is wired — the scanner still runs, just without DAG
// attestation (gracefully degraded for Presight demo mode).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/souhimbou"
)

// ─── In-memory scan store ─────────────────────────────────────────────────────

type agentScanJob struct {
	ID        string
	Target    souhimbou.AgentTarget
	StartedAt time.Time
	Done      bool
	Result    *souhimbou.AgentScanReport
	Events    []agentScanSSEEvent
	mu        sync.RWMutex
	subs      []chan agentScanSSEEvent
}

type agentScanSSEEvent struct {
	Type    string `json:"type"`
	Payload any    `json:"payload"`
}

var (
	agentScanJobs   = map[string]*agentScanJob{}
	agentScanJobsMu sync.RWMutex
)

func newAgentScanJob(target souhimbou.AgentTarget) *agentScanJob {
	return &agentScanJob{
		ID:        uuid.New().String(),
		Target:    target,
		StartedAt: time.Now().UTC(),
	}
}

func (j *agentScanJob) publish(ev agentScanSSEEvent) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Events = append(j.Events, ev)
	for _, ch := range j.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (j *agentScanJob) subscribe() chan agentScanSSEEvent {
	ch := make(chan agentScanSSEEvent, 64)
	j.mu.Lock()
	for _, ev := range j.Events {
		ch <- ev
	}
	if j.Done {
		close(ch)
	} else {
		j.subs = append(j.subs, ch)
	}
	j.mu.Unlock()
	return ch
}

func (j *agentScanJob) complete(report *souhimbou.AgentScanReport) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Done = true
	j.Result = report
	for _, ch := range j.subs {
		close(ch)
	}
	j.subs = nil
}

// ─── Request model ────────────────────────────────────────────────────────────

// agentScanTriggerReq maps to souhimbou.AgentTarget for JSON binding.
type agentScanTriggerReq struct {
	Target    string `json:"target" binding:"required"` // base URL of the agent
	AgentType string `json:"agent_type"`                // mcp|openai|langserve|ollama|http
	Tier      string `json:"tier"`                      // free|pro|enterprise
	APIKey    string `json:"api_key,omitempty"`          // never stored
	RepoPath  string `json:"repo_path,omitempty"`
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

// handleAgentScanTrigger — POST /api/v1/scan/agent
func (s *Server) handleAgentScanTrigger(c *gin.Context) {
	var req agentScanTriggerReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Tier == "" {
		req.Tier = "free"
	}

	target := souhimbou.AgentTarget{
		URL:      req.Target,
		Type:     souhimbou.AgentType(req.AgentType),
		APIKey:   req.APIKey,
		RepoPath: req.RepoPath,
		Tier:     req.Tier,
	}

	job := newAgentScanJob(target)
	agentScanJobsMu.Lock()
	agentScanJobs[job.ID] = job
	agentScanJobsMu.Unlock()

	go runAgentScanBackground(job)

	c.JSON(http.StatusAccepted, gin.H{
		"scan_id":    job.ID,
		"target":     req.Target,
		"agent_type": req.AgentType,
		"tier":       req.Tier,
		"started_at": job.StartedAt,
		"stream_url": fmt.Sprintf("/api/v1/scan/agent/stream?id=%s", job.ID),
	})
}

// handleAgentScanStream — GET /api/v1/scan/agent/stream?id=<id>
func (s *Server) handleAgentScanStream(c *gin.Context) {
	scanID := c.Query("id")
	if scanID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id query param required"})
		return
	}
	agentScanJobsMu.RLock()
	job, ok := agentScanJobs[scanID]
	agentScanJobsMu.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
		return
	}

	ch := job.subscribe()
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("X-Accel-Buffering", "no")
	c.Status(http.StatusOK)
	flusher, hasFlusher := c.Writer.(http.Flusher)

	writeSSE := func(ev agentScanSSEEvent) {
		data, _ := json.Marshal(ev)
		fmt.Fprintf(c.Writer, "data: %s\n\n", data)
		if hasFlusher {
			flusher.Flush()
		}
	}

	ctx := c.Request.Context()
	for {
		select {
		case ev, open := <-ch:
			if !open {
				writeSSE(agentScanSSEEvent{Type: "done", Payload: map[string]any{"scan_id": scanID}})
				return
			}
			writeSSE(ev)
		case <-ctx.Done():
			return
		case <-time.After(25 * time.Second):
			fmt.Fprintf(c.Writer, ": heartbeat\n\n")
			if hasFlusher {
				flusher.Flush()
			}
		}
	}
}

// handleAgentScanResult — GET /api/v1/scan/agent/:id  (authenticated)
func (s *Server) handleAgentScanResult(c *gin.Context) {
	agentScanJobsMu.RLock()
	job, ok := agentScanJobs[c.Param("id")]
	agentScanJobsMu.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
		return
	}
	job.mu.RLock()
	defer job.mu.RUnlock()
	if !job.Done {
		c.JSON(http.StatusAccepted, gin.H{"status": "running", "scan_id": job.ID})
		return
	}
	c.JSON(http.StatusOK, job.Result)
}

// ─── Background runner ────────────────────────────────────────────────────────

func runAgentScanBackground(job *agentScanJob) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	job.publish(agentScanSSEEvent{
		Type:    "started",
		Payload: map[string]any{"target": job.Target.URL, "tier": job.Target.Tier},
	})

	// Run the full 6-layer scan.
	// Fabric and DAGStore are nil → scanner runs without DAG attestation (demo-safe).
	scanner := souhimbou.NewAgentScanner(nil, nil)
	report, err := scanner.Scan(ctx, job.Target)
	if err != nil {
		job.publish(agentScanSSEEvent{
			Type:    "error",
			Payload: map[string]any{"error": err.Error()},
		})
	}
	job.complete(report)
}

// ─── Route registration ───────────────────────────────────────────────────────

// setupAgentScanRoutes wires agent scan endpoints into gin route groups.
// pub endpoints have no auth — required for the Presight / demo funnel.
func (s *Server) setupAgentScanRoutes(pub *gin.RouterGroup, auth *gin.RouterGroup) {
	pub.POST("/scan/agent", s.handleAgentScanTrigger)
	pub.GET("/scan/agent/stream", s.handleAgentScanStream)
	auth.GET("/scan/agent/:id", s.handleAgentScanResult)
}
