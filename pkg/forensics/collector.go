// Package forensics implements Imhotep's Eye - Digital Forensics Collection and Documentation
//
// "The Architect sees all, records all, forgets nothing."
//
// This module provides continuous forensic documentation of the system environment,
// creating an immutable audit trail in the PQC DAG for:
// - System state snapshots
// - Process monitoring
// - Network connections
// - File integrity monitoring
// - User activity tracking
// - Security event correlation
package forensics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// EvidenceType categorizes forensic evidence
type EvidenceType string

const (
	EvidenceSystemState   EvidenceType = "SYSTEM_STATE"
	EvidenceProcess       EvidenceType = "PROCESS"
	EvidenceNetwork       EvidenceType = "NETWORK"
	EvidenceFileIntegrity EvidenceType = "FILE_INTEGRITY"
	EvidenceUserActivity  EvidenceType = "USER_ACTIVITY"
	EvidenceSecurityEvent EvidenceType = "SECURITY_EVENT"
	EvidenceConfig        EvidenceType = "CONFIG"
	EvidenceArtifact      EvidenceType = "ARTIFACT"
)

// Evidence represents a single piece of forensic evidence
type Evidence struct {
	ID          string                 `json:"id"`
	Type        EvidenceType           `json:"type"`
	Timestamp   time.Time              `json:"timestamp"`
	Source      string                 `json:"source"`       // Hostname/IP
	Collector   string                 `json:"collector"`    // Collection method
	Description string                 `json:"description"`
	Data        map[string]interface{} `json:"data"`
	Hash        string                 `json:"hash"`         // SHA256 of Data
	ChainOfCustody []string            `json:"chain_of_custody"`
}

// ForensicSnapshot represents a point-in-time system state
type ForensicSnapshot struct {
	SnapshotID    string              `json:"snapshot_id"`
	Timestamp     time.Time           `json:"timestamp"`
	Hostname      string              `json:"hostname"`
	OS            string              `json:"os"`
	Architecture  string              `json:"architecture"`
	SystemState   *SystemState        `json:"system_state"`
	Processes     []ProcessInfo       `json:"processes"`
	NetworkConns  []NetworkConnection `json:"network_connections"`
	OpenPorts     []PortInfo          `json:"open_ports"`
	FileHashes    map[string]string   `json:"file_hashes"`    // Critical files
	UserSessions  []UserSession       `json:"user_sessions"`
	SecurityEvents []SecurityEvent    `json:"security_events"`
	Hash          string              `json:"hash"`           // Overall snapshot hash
}

// SystemState captures current system metrics
type SystemState struct {
	Uptime        string  `json:"uptime"`
	LoadAverage   string  `json:"load_average"`
	MemoryTotal   uint64  `json:"memory_total_bytes"`
	MemoryUsed    uint64  `json:"memory_used_bytes"`
	DiskTotal     uint64  `json:"disk_total_bytes"`
	DiskUsed      uint64  `json:"disk_used_bytes"`
	CPUCount      int     `json:"cpu_count"`
	GoRoutines    int     `json:"goroutines"`
	BootTime      string  `json:"boot_time"`
	KernelVersion string  `json:"kernel_version"`
}

// ProcessInfo captures running process information
type ProcessInfo struct {
	PID        int      `json:"pid"`
	PPID       int      `json:"ppid"`
	Name       string   `json:"name"`
	Executable string   `json:"executable"`
	CmdLine    string   `json:"cmdline"`
	User       string   `json:"user"`
	State      string   `json:"state"`
	StartTime  string   `json:"start_time"`
	CPU        float64  `json:"cpu_percent"`
	Memory     uint64   `json:"memory_bytes"`
	OpenFiles  int      `json:"open_files"`
	Hash       string   `json:"executable_hash,omitempty"`
}

// NetworkConnection captures active network connections
type NetworkConnection struct {
	Protocol    string `json:"protocol"`
	LocalAddr   string `json:"local_addr"`
	LocalPort   int    `json:"local_port"`
	RemoteAddr  string `json:"remote_addr"`
	RemotePort  int    `json:"remote_port"`
	State       string `json:"state"`
	PID         int    `json:"pid"`
	ProcessName string `json:"process_name"`
}

// PortInfo represents an open port
type PortInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service"`
	PID      int    `json:"pid"`
}

// UserSession represents an active user session
type UserSession struct {
	User      string    `json:"user"`
	Terminal  string    `json:"terminal"`
	Host      string    `json:"host"`
	LoginTime time.Time `json:"login_time"`
	Idle      string    `json:"idle"`
}

// SecurityEvent represents a security-relevant event
type SecurityEvent struct {
	EventID     string    `json:"event_id"`
	Timestamp   time.Time `json:"timestamp"`
	Category    string    `json:"category"`    // auth, network, file, process
	Severity    string    `json:"severity"`    // info, warning, critical
	Source      string    `json:"source"`
	Description string    `json:"description"`
	Data        map[string]string `json:"data"`
}

// Collector performs forensic collection operations
type Collector struct {
	hostname       string
	criticalPaths  []string
	lastSnapshot   *ForensicSnapshot
	snapshotMu     sync.Mutex
	evidenceBuffer []Evidence
	bufferMu       sync.Mutex

	// Callbacks for DAG integration
	OnEvidenceCollected func(e *Evidence)
	OnSnapshotComplete  func(s *ForensicSnapshot)
}

// NewCollector creates a new forensic collector
func NewCollector() *Collector {
	hostname, _ := os.Hostname()

	return &Collector{
		hostname: hostname,
		criticalPaths: []string{
			// System binaries
			"/bin/sh",
			"/bin/bash",
			"/usr/bin/sudo",
			"/usr/bin/ssh",
			"/usr/bin/sshd",
			// Windows equivalents
			"C:\\Windows\\System32\\cmd.exe",
			"C:\\Windows\\System32\\powershell.exe",
			"C:\\Windows\\System32\\sshd.exe",
			// Application configs
			"/etc/passwd",
			"/etc/shadow",
			"/etc/ssh/sshd_config",
		},
		evidenceBuffer: make([]Evidence, 0),
	}
}

// AddCriticalPath adds a path to monitor for file integrity
func (c *Collector) AddCriticalPath(path string) {
	c.criticalPaths = append(c.criticalPaths, path)
}

// CollectSnapshot performs a full forensic snapshot
func (c *Collector) CollectSnapshot(ctx context.Context) (*ForensicSnapshot, error) {
	log.Println("[FORENSICS] Initiating forensic snapshot collection...")

	snapshot := &ForensicSnapshot{
		SnapshotID:   fmt.Sprintf("forensic-%d", time.Now().UnixNano()),
		Timestamp:    time.Now().UTC(),
		Hostname:     c.hostname,
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
		FileHashes:   make(map[string]string),
	}

	// Collect in parallel for performance
	var wg sync.WaitGroup
	var mu sync.Mutex

	// System State
	wg.Add(1)
	go func() {
		defer wg.Done()
		state := c.collectSystemState(ctx)
		mu.Lock()
		snapshot.SystemState = state
		mu.Unlock()
	}()

	// Processes
	wg.Add(1)
	go func() {
		defer wg.Done()
		procs := c.collectProcesses(ctx)
		mu.Lock()
		snapshot.Processes = procs
		mu.Unlock()
	}()

	// Network Connections
	wg.Add(1)
	go func() {
		defer wg.Done()
		conns := c.collectNetworkConnections(ctx)
		mu.Lock()
		snapshot.NetworkConns = conns
		mu.Unlock()
	}()

	// Open Ports
	wg.Add(1)
	go func() {
		defer wg.Done()
		ports := c.collectOpenPorts(ctx)
		mu.Lock()
		snapshot.OpenPorts = ports
		mu.Unlock()
	}()

	// File Hashes
	wg.Add(1)
	go func() {
		defer wg.Done()
		hashes := c.collectFileHashes()
		mu.Lock()
		snapshot.FileHashes = hashes
		mu.Unlock()
	}()

	// User Sessions
	wg.Add(1)
	go func() {
		defer wg.Done()
		sessions := c.collectUserSessions(ctx)
		mu.Lock()
		snapshot.UserSessions = sessions
		mu.Unlock()
	}()

	wg.Wait()

	// Calculate overall snapshot hash
	snapshot.Hash = c.hashSnapshot(snapshot)

	// Store for comparison
	c.snapshotMu.Lock()
	c.lastSnapshot = snapshot
	c.snapshotMu.Unlock()

	// Callback
	if c.OnSnapshotComplete != nil {
		c.OnSnapshotComplete(snapshot)
	}

	log.Printf("[FORENSICS] Snapshot complete: %s (Processes: %d, Connections: %d, Files: %d)",
		snapshot.SnapshotID, len(snapshot.Processes), len(snapshot.NetworkConns), len(snapshot.FileHashes))

	return snapshot, nil
}

// collectSystemState gathers system metrics
func (c *Collector) collectSystemState(ctx context.Context) *SystemState {
	state := &SystemState{
		CPUCount:   runtime.NumCPU(),
		GoRoutines: runtime.NumGoroutine(),
	}

	// OS-specific collection
	switch runtime.GOOS {
	case "linux":
		c.collectLinuxState(ctx, state)
	case "windows":
		c.collectWindowsState(ctx, state)
	case "darwin":
		c.collectDarwinState(ctx, state)
	}

	return state
}

// collectLinuxState gathers Linux-specific metrics
func (c *Collector) collectLinuxState(ctx context.Context, state *SystemState) {
	// Uptime
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		parts := strings.Fields(string(data))
		if len(parts) > 0 {
			state.Uptime = parts[0] + " seconds"
		}
	}

	// Load average
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		parts := strings.Fields(string(data))
		if len(parts) >= 3 {
			state.LoadAverage = strings.Join(parts[:3], " ")
		}
	}

	// Kernel version
	if data, err := os.ReadFile("/proc/version"); err == nil {
		state.KernelVersion = strings.Split(string(data), " ")[2]
	}
}

// collectWindowsState gathers Windows-specific metrics
func (c *Collector) collectWindowsState(ctx context.Context, state *SystemState) {
	// Uptime via wmic
	cmd := exec.CommandContext(ctx, "wmic", "os", "get", "lastbootuptime")
	if output, err := cmd.Output(); err == nil {
		state.BootTime = strings.TrimSpace(string(output))
	}

	// System info (Query Windows version using cmd /c ver, which is fast and does not hang)
	cmd = exec.CommandContext(ctx, "cmd", "/c", "ver")
	if output, err := cmd.Output(); err == nil {
		state.KernelVersion = strings.TrimSpace(string(output))
	} else {
		state.KernelVersion = "Windows"
	}
}

// collectDarwinState gathers macOS-specific metrics
func (c *Collector) collectDarwinState(ctx context.Context, state *SystemState) {
	// Uptime
	cmd := exec.CommandContext(ctx, "uptime")
	if output, err := cmd.Output(); err == nil {
		state.Uptime = strings.TrimSpace(string(output))
	}

	// Kernel version
	cmd = exec.CommandContext(ctx, "uname", "-r")
	if output, err := cmd.Output(); err == nil {
		state.KernelVersion = strings.TrimSpace(string(output))
	}
}

// collectProcesses gathers running process information
func (c *Collector) collectProcesses(ctx context.Context) []ProcessInfo {
	var processes []ProcessInfo

	switch runtime.GOOS {
	case "linux":
		processes = c.collectLinuxProcesses()
	case "windows":
		processes = c.collectWindowsProcesses(ctx)
	case "darwin":
		processes = c.collectDarwinProcesses(ctx)
	}

	return processes
}

// collectLinuxProcesses gathers process info on Linux
func (c *Collector) collectLinuxProcesses() []ProcessInfo {
	var processes []ProcessInfo

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return processes
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check if directory name is a PID
		pid := 0
		if _, err := fmt.Sscanf(entry.Name(), "%d", &pid); err != nil {
			continue
		}

		proc := ProcessInfo{PID: pid}
		procDir := filepath.Join("/proc", entry.Name())

		// Executable
		if exe, err := os.Readlink(filepath.Join(procDir, "exe")); err == nil {
			proc.Executable = exe
			proc.Hash = c.hashFile(exe)
		}

		// Command line
		if cmdline, err := os.ReadFile(filepath.Join(procDir, "cmdline")); err == nil {
			proc.CmdLine = strings.ReplaceAll(string(cmdline), "\x00", " ")
		}

		// Status
		if status, err := os.ReadFile(filepath.Join(procDir, "status")); err == nil {
			for _, line := range strings.Split(string(status), "\n") {
				if strings.HasPrefix(line, "Name:") {
					proc.Name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
				} else if strings.HasPrefix(line, "PPid:") {
					fmt.Sscanf(strings.TrimPrefix(line, "PPid:"), "%d", &proc.PPID)
				} else if strings.HasPrefix(line, "State:") {
					proc.State = strings.TrimSpace(strings.TrimPrefix(line, "State:"))
				} else if strings.HasPrefix(line, "Uid:") {
					proc.User = strings.Fields(strings.TrimPrefix(line, "Uid:"))[0]
				}
			}
		}

		processes = append(processes, proc)
	}

	return processes
}

// collectWindowsProcesses gathers process info on Windows
func (c *Collector) collectWindowsProcesses(ctx context.Context) []ProcessInfo {
	var processes []ProcessInfo

	cmd := exec.CommandContext(ctx, "tasklist", "/fo", "csv")
	output, err := cmd.Output()
	if err != nil {
		return processes
	}

	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}

		// Parse CSV
		fields := parseCSVLine(line)
		if len(fields) < 2 {
			continue
		}

		proc := ProcessInfo{
			Name: strings.Trim(fields[0], "\""),
			User: "N/A",
		}
		fmt.Sscanf(strings.Trim(fields[1], "\""), "%d", &proc.PID)

		processes = append(processes, proc)
	}

	return processes
}

// collectDarwinProcesses gathers process info on macOS
func (c *Collector) collectDarwinProcesses(ctx context.Context) []ProcessInfo {
	var processes []ProcessInfo

	cmd := exec.CommandContext(ctx, "ps", "aux")
	output, err := cmd.Output()
	if err != nil {
		return processes
	}

	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 11 {
			continue
		}

		proc := ProcessInfo{
			User: fields[0],
			Name: fields[10],
		}
		fmt.Sscanf(fields[1], "%d", &proc.PID)

		processes = append(processes, proc)
	}

	return processes
}

// collectNetworkConnections gathers active network connections
func (c *Collector) collectNetworkConnections(ctx context.Context) []NetworkConnection {
	var conns []NetworkConnection

	switch runtime.GOOS {
	case "linux":
		conns = c.collectLinuxNetConns()
	case "windows":
		conns = c.collectWindowsNetConns(ctx)
	case "darwin":
		conns = c.collectDarwinNetConns(ctx)
	}

	return conns
}

// collectLinuxNetConns parses /proc/net/tcp and /proc/net/udp
func (c *Collector) collectLinuxNetConns() []NetworkConnection {
	var conns []NetworkConnection

	// TCP connections
	if data, err := os.ReadFile("/proc/net/tcp"); err == nil {
		for _, conn := range parseLinuxNetstat(string(data), "tcp") {
			conns = append(conns, conn)
		}
	}

	// UDP connections
	if data, err := os.ReadFile("/proc/net/udp"); err == nil {
		for _, conn := range parseLinuxNetstat(string(data), "udp") {
			conns = append(conns, conn)
		}
	}

	return conns
}

// parseLinuxNetstat parses /proc/net/tcp or /proc/net/udp
func parseLinuxNetstat(data, protocol string) []NetworkConnection {
	var conns []NetworkConnection

	lines := strings.Split(data, "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		conn := NetworkConnection{Protocol: protocol}

		// Local address
		localParts := strings.Split(fields[1], ":")
		if len(localParts) == 2 {
			conn.LocalAddr = hexToIP(localParts[0])
			fmt.Sscanf(localParts[1], "%X", &conn.LocalPort)
		}

		// Remote address
		remoteParts := strings.Split(fields[2], ":")
		if len(remoteParts) == 2 {
			conn.RemoteAddr = hexToIP(remoteParts[0])
			fmt.Sscanf(remoteParts[1], "%X", &conn.RemotePort)
		}

		// State
		var state int
		fmt.Sscanf(fields[3], "%X", &state)
		conn.State = tcpStateToString(state)

		conns = append(conns, conn)
	}

	return conns
}

// hexToIP converts hex IP to dotted notation
func hexToIP(hex string) string {
	if len(hex) != 8 {
		return hex
	}

	var ip [4]byte
	fmt.Sscanf(hex, "%02X%02X%02X%02X", &ip[3], &ip[2], &ip[1], &ip[0])
	return net.IP(ip[:]).String()
}

// tcpStateToString converts TCP state number to string
func tcpStateToString(state int) string {
	states := map[int]string{
		1:  "ESTABLISHED",
		2:  "SYN_SENT",
		3:  "SYN_RECV",
		4:  "FIN_WAIT1",
		5:  "FIN_WAIT2",
		6:  "TIME_WAIT",
		7:  "CLOSE",
		8:  "CLOSE_WAIT",
		9:  "LAST_ACK",
		10: "LISTEN",
		11: "CLOSING",
	}
	if s, ok := states[state]; ok {
		return s
	}
	return "UNKNOWN"
}

// collectWindowsNetConns uses netstat on Windows
func (c *Collector) collectWindowsNetConns(ctx context.Context) []NetworkConnection {
	var conns []NetworkConnection

	cmd := exec.CommandContext(ctx, "netstat", "-ano")
	output, err := cmd.Output()
	if err != nil {
		return conns
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		proto := strings.ToLower(fields[0])
		if proto != "tcp" && proto != "udp" {
			continue
		}

		conn := NetworkConnection{Protocol: proto}

		// Local address
		localParts := strings.Split(fields[1], ":")
		if len(localParts) >= 2 {
			conn.LocalAddr = localParts[0]
			fmt.Sscanf(localParts[len(localParts)-1], "%d", &conn.LocalPort)
		}

		// Remote address
		remoteParts := strings.Split(fields[2], ":")
		if len(remoteParts) >= 2 {
			conn.RemoteAddr = remoteParts[0]
			fmt.Sscanf(remoteParts[len(remoteParts)-1], "%d", &conn.RemotePort)
		}

		// State
		if proto == "tcp" && len(fields) >= 4 {
			conn.State = fields[3]
		}

		// PID
		pidField := fields[len(fields)-1]
		fmt.Sscanf(pidField, "%d", &conn.PID)

		conns = append(conns, conn)
	}

	return conns
}

// collectDarwinNetConns uses lsof on macOS
func (c *Collector) collectDarwinNetConns(ctx context.Context) []NetworkConnection {
	var conns []NetworkConnection

	cmd := exec.CommandContext(ctx, "lsof", "-i", "-n", "-P")
	output, err := cmd.Output()
	if err != nil {
		return conns
	}

	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}

		conn := NetworkConnection{
			ProcessName: fields[0],
			Protocol:    strings.ToLower(fields[7]),
		}
		fmt.Sscanf(fields[1], "%d", &conn.PID)

		// Parse address
		addr := fields[8]
		if strings.Contains(addr, "->") {
			parts := strings.Split(addr, "->")
			if len(parts) == 2 {
				localParts := strings.Split(parts[0], ":")
				if len(localParts) >= 2 {
					conn.LocalAddr = localParts[0]
					fmt.Sscanf(localParts[len(localParts)-1], "%d", &conn.LocalPort)
				}
				remoteParts := strings.Split(parts[1], ":")
				if len(remoteParts) >= 2 {
					conn.RemoteAddr = remoteParts[0]
					fmt.Sscanf(remoteParts[len(remoteParts)-1], "%d", &conn.RemotePort)
				}
			}
		}

		conns = append(conns, conn)
	}

	return conns
}

// collectOpenPorts scans for listening ports
func (c *Collector) collectOpenPorts(ctx context.Context) []PortInfo {
	var ports []PortInfo

	// Use the network connections to find listening ports
	conns := c.collectNetworkConnections(ctx)
	seen := make(map[string]bool)

	for _, conn := range conns {
		if conn.State == "LISTEN" {
			key := fmt.Sprintf("%s:%d", conn.Protocol, conn.LocalPort)
			if !seen[key] {
				ports = append(ports, PortInfo{
					Port:     conn.LocalPort,
					Protocol: conn.Protocol,
					State:    "LISTEN",
					PID:      conn.PID,
				})
				seen[key] = true
			}
		}
	}

	// Sort by port number
	sort.Slice(ports, func(i, j int) bool {
		return ports[i].Port < ports[j].Port
	})

	return ports
}

// collectFileHashes computes SHA256 hashes of critical files
func (c *Collector) collectFileHashes() map[string]string {
	hashes := make(map[string]string)

	for _, path := range c.criticalPaths {
		hash := c.hashFile(path)
		if hash != "" {
			hashes[path] = hash
		}
	}

	return hashes
}

// hashFile computes SHA256 of a file
func (c *Collector) hashFile(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return ""
	}

	return hex.EncodeToString(hasher.Sum(nil))
}

// collectUserSessions gathers active user sessions
func (c *Collector) collectUserSessions(ctx context.Context) []UserSession {
	var sessions []UserSession

	switch runtime.GOOS {
	case "linux", "darwin":
		cmd := exec.CommandContext(ctx, "who")
		output, err := cmd.Output()
		if err == nil {
			for _, line := range strings.Split(string(output), "\n") {
				if strings.TrimSpace(line) == "" {
					continue
				}
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					sessions = append(sessions, UserSession{
						User:     fields[0],
						Terminal: fields[1],
					})
				}
			}
		}
	case "windows":
		cmd := exec.CommandContext(ctx, "query", "user")
		output, err := cmd.Output()
		if err == nil {
			for i, line := range strings.Split(string(output), "\n") {
				if i == 0 || strings.TrimSpace(line) == "" {
					continue
				}
				fields := strings.Fields(line)
				if len(fields) >= 1 {
					sessions = append(sessions, UserSession{
						User: strings.TrimPrefix(fields[0], ">"),
					})
				}
			}
		}
	}

	return sessions
}

// hashSnapshot computes overall hash of a forensic snapshot
func (c *Collector) hashSnapshot(snapshot *ForensicSnapshot) string {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return ""
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// CreateEvidence creates a new evidence record
func (c *Collector) CreateEvidence(evidenceType EvidenceType, description string, data map[string]interface{}) *Evidence {
	dataJSON, _ := json.Marshal(data)
	hash := sha256.Sum256(dataJSON)

	evidence := &Evidence{
		ID:          fmt.Sprintf("evidence-%d", time.Now().UnixNano()),
		Type:        evidenceType,
		Timestamp:   time.Now().UTC(),
		Source:      c.hostname,
		Collector:   "KASA-Forensics-v1",
		Description: description,
		Data:        data,
		Hash:        hex.EncodeToString(hash[:]),
		ChainOfCustody: []string{
			fmt.Sprintf("%s: Collected by KASA Forensic Collector", time.Now().UTC().Format(time.RFC3339)),
		},
	}

	// Buffer evidence
	c.bufferMu.Lock()
	c.evidenceBuffer = append(c.evidenceBuffer, *evidence)
	c.bufferMu.Unlock()

	// Callback
	if c.OnEvidenceCollected != nil {
		c.OnEvidenceCollected(evidence)
	}

	return evidence
}

// GetLastSnapshot returns the most recent forensic snapshot
func (c *Collector) GetLastSnapshot() *ForensicSnapshot {
	c.snapshotMu.Lock()
	defer c.snapshotMu.Unlock()
	return c.lastSnapshot
}

// CompareSnapshots identifies changes between two snapshots
func (c *Collector) CompareSnapshots(old, new *ForensicSnapshot) []string {
	var changes []string

	// Compare processes
	oldProcs := make(map[int]ProcessInfo)
	for _, p := range old.Processes {
		oldProcs[p.PID] = p
	}

	for _, p := range new.Processes {
		if _, exists := oldProcs[p.PID]; !exists {
			changes = append(changes, fmt.Sprintf("NEW PROCESS: PID=%d Name=%s", p.PID, p.Name))
		}
	}

	// Compare network connections
	oldConns := make(map[string]bool)
	for _, conn := range old.NetworkConns {
		key := fmt.Sprintf("%s:%d->%s:%d", conn.LocalAddr, conn.LocalPort, conn.RemoteAddr, conn.RemotePort)
		oldConns[key] = true
	}

	for _, conn := range new.NetworkConns {
		key := fmt.Sprintf("%s:%d->%s:%d", conn.LocalAddr, conn.LocalPort, conn.RemoteAddr, conn.RemotePort)
		if !oldConns[key] {
			changes = append(changes, fmt.Sprintf("NEW CONNECTION: %s", key))
		}
	}

	// Compare file hashes
	for path, newHash := range new.FileHashes {
		if oldHash, exists := old.FileHashes[path]; exists {
			if oldHash != newHash {
				changes = append(changes, fmt.Sprintf("FILE MODIFIED: %s", path))
			}
		} else {
			changes = append(changes, fmt.Sprintf("NEW CRITICAL FILE: %s", path))
		}
	}

	return changes
}

// parseCSVLine parses a single CSV line
func parseCSVLine(line string) []string {
	var fields []string
	var field strings.Builder
	inQuotes := false

	for _, r := range line {
		switch {
		case r == '"':
			inQuotes = !inQuotes
		case r == ',' && !inQuotes:
			fields = append(fields, field.String())
			field.Reset()
		default:
			field.WriteRune(r)
		}
	}
	fields = append(fields, field.String())

	return fields
}

// GenerateReport creates a human-readable forensic report
func (c *Collector) GenerateReport(snapshot *ForensicSnapshot) string {
	var sb strings.Builder

	sb.WriteString("═══════════════════════════════════════════════════════════════\n")
	sb.WriteString("           IMHOTEP FORENSIC ANALYSIS REPORT\n")
	sb.WriteString("═══════════════════════════════════════════════════════════════\n\n")

	sb.WriteString(fmt.Sprintf("Snapshot ID:  %s\n", snapshot.SnapshotID))
	sb.WriteString(fmt.Sprintf("Timestamp:    %s\n", snapshot.Timestamp.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Hostname:     %s\n", snapshot.Hostname))
	sb.WriteString(fmt.Sprintf("OS/Arch:      %s/%s\n", snapshot.OS, snapshot.Architecture))
	sb.WriteString(fmt.Sprintf("Hash:         %s\n\n", snapshot.Hash))

	sb.WriteString("SYSTEM STATE:\n")
	sb.WriteString("───────────────────────────────────────────────────────────────\n")
	if snapshot.SystemState != nil {
		sb.WriteString(fmt.Sprintf("  CPUs:       %d\n", snapshot.SystemState.CPUCount))
		sb.WriteString(fmt.Sprintf("  Goroutines: %d\n", snapshot.SystemState.GoRoutines))
		sb.WriteString(fmt.Sprintf("  Uptime:     %s\n", snapshot.SystemState.Uptime))
		sb.WriteString(fmt.Sprintf("  Kernel:     %s\n", snapshot.SystemState.KernelVersion))
	}

	sb.WriteString(fmt.Sprintf("\nPROCESSES: %d running\n", len(snapshot.Processes)))
	sb.WriteString("───────────────────────────────────────────────────────────────\n")
	for i, p := range snapshot.Processes {
		if i >= 20 {
			sb.WriteString(fmt.Sprintf("  ... and %d more\n", len(snapshot.Processes)-20))
			break
		}
		sb.WriteString(fmt.Sprintf("  [%d] %s (User: %s)\n", p.PID, p.Name, p.User))
	}

	sb.WriteString(fmt.Sprintf("\nNETWORK CONNECTIONS: %d active\n", len(snapshot.NetworkConns)))
	sb.WriteString("───────────────────────────────────────────────────────────────\n")
	for i, conn := range snapshot.NetworkConns {
		if i >= 20 {
			sb.WriteString(fmt.Sprintf("  ... and %d more\n", len(snapshot.NetworkConns)-20))
			break
		}
		sb.WriteString(fmt.Sprintf("  %s %s:%d -> %s:%d (%s)\n",
			conn.Protocol, conn.LocalAddr, conn.LocalPort,
			conn.RemoteAddr, conn.RemotePort, conn.State))
	}

	sb.WriteString(fmt.Sprintf("\nLISTENING PORTS: %d open\n", len(snapshot.OpenPorts)))
	sb.WriteString("───────────────────────────────────────────────────────────────\n")
	for _, port := range snapshot.OpenPorts {
		sb.WriteString(fmt.Sprintf("  %s/%d (PID: %d)\n", port.Protocol, port.Port, port.PID))
	}

	sb.WriteString(fmt.Sprintf("\nFILE INTEGRITY: %d files monitored\n", len(snapshot.FileHashes)))
	sb.WriteString("───────────────────────────────────────────────────────────────\n")
	for path, hash := range snapshot.FileHashes {
		sb.WriteString(fmt.Sprintf("  %s\n    SHA256: %s\n", path, hash))
	}

	sb.WriteString("\n═══════════════════════════════════════════════════════════════\n")

	return sb.String()
}
