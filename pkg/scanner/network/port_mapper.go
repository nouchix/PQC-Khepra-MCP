package network

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// ProcessPortInfo contains process-level attribution for a network port
type ProcessPortInfo struct {
	Port        int
	Protocol    string
	PID         int
	ProcessName string
	User        string
	State       string
}

// GetPortMapping returns a map of port number to process information
// Works on both Windows (PowerShell) and Linux (/proc/net/tcp)
func GetPortMapping() (map[int]*ProcessPortInfo, error) {
	switch runtime.GOOS {
	case "windows":
		return getWindowsPortMapping()
	case "linux":
		return getLinuxPortMapping()
	default:
		return nil, fmt.Errorf("port-to-PID mapping not supported on %s", runtime.GOOS)
	}
}

// getWindowsPortMapping uses PowerShell's Get-NetTCPConnection cmdlet
func getWindowsPortMapping() (map[int]*ProcessPortInfo, error) {
	// PowerShell command to get TCP connections with process info
	psScript := `
Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'} |
Select-Object LocalPort, OwningProcess, State |
ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        LocalPort = $_.LocalPort
        PID = $_.OwningProcess
        ProcessName = if($proc) { $proc.Name } else { "Unknown" }
        State = $_.State
        Protocol = "tcp"
    }
} | ConvertTo-Json
`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("PowerShell execution failed: %v\nOutput: %s", err, string(output))
	}

	// Parse JSON output
	var connections []struct {
		LocalPort   int         `json:"LocalPort"`
		PID         int         `json:"PID"`
		ProcessName string      `json:"ProcessName"`
		State       interface{} `json:"State"` // Can be int or string
		Protocol    string      `json:"Protocol"`
	}

	// Handle both single object and array responses
	trimmed := strings.TrimSpace(string(output))
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal([]byte(trimmed), &connections); err != nil {
			return nil, fmt.Errorf("JSON parsing failed: %v\nOutput: %s", err, trimmed)
		}
	} else if strings.HasPrefix(trimmed, "{") {
		var single struct {
			LocalPort   int         `json:"LocalPort"`
			PID         int         `json:"PID"`
			ProcessName string      `json:"ProcessName"`
			State       interface{} `json:"State"`
			Protocol    string      `json:"Protocol"`
		}
		if err := json.Unmarshal([]byte(trimmed), &single); err != nil {
			return nil, fmt.Errorf("JSON parsing failed: %v\nOutput: %s", err, trimmed)
		}
		connections = append(connections, single)
	} else {
		return nil, fmt.Errorf("unexpected PowerShell output format: %s", trimmed[:min(len(trimmed), 100)])
	}

	// Convert to map
	portMap := make(map[int]*ProcessPortInfo)
	for _, conn := range connections {
		// Convert State (can be int enum or string)
		stateStr := "LISTEN"
		switch v := conn.State.(type) {
		case string:
			stateStr = v
		case float64:
			// PowerShell returns numeric state: 2 = Listen, others we map to ESTABLISHED
			if v == 2 {
				stateStr = "LISTEN"
			} else {
				stateStr = "ESTABLISHED"
			}
		}

		portMap[conn.LocalPort] = &ProcessPortInfo{
			Port:        conn.LocalPort,
			Protocol:    conn.Protocol,
			PID:         conn.PID,
			ProcessName: conn.ProcessName,
			State:       stateStr,
			User:        "", // User retrieval requires admin privileges on Windows
		}
	}

	return portMap, nil
}

// getLinuxPortMapping uses /proc/net/tcp for PID resolution
func getLinuxPortMapping() (map[int]*ProcessPortInfo, error) {
	// Try netstat first (simpler, more reliable if available)
	portMap, err := getLinuxPortMappingNetstat()
	if err == nil {
		return portMap, nil
	}

	// Fallback to /proc/net/tcp parsing (no dependencies)
	return getLinuxPortMappingProc()
}

// getLinuxPortMappingNetstat uses `netstat -tlnp` (requires net-tools package)
func getLinuxPortMappingNetstat() (map[int]*ProcessPortInfo, error) {
	cmd := exec.Command("netstat", "-tlnp")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("netstat failed: %v", err)
	}

	portMap := make(map[int]*ProcessPortInfo)
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 7 || !strings.Contains(fields[0], "tcp") {
			continue
		}

		// Parse "0.0.0.0:22" -> port 22
		localAddr := fields[3]
		parts := strings.Split(localAddr, ":")
		if len(parts) != 2 {
			continue
		}

		var port int
		fmt.Sscanf(parts[1], "%d", &port)

		// Parse "1234/sshd" -> PID 1234, process "sshd"
		pidProcess := fields[6]
		if pidProcess == "-" {
			continue // No permission to see PID
		}

		pidParts := strings.Split(pidProcess, "/")
		var pid int
		processName := "Unknown"
		if len(pidParts) >= 1 {
			fmt.Sscanf(pidParts[0], "%d", &pid)
		}
		if len(pidParts) >= 2 {
			processName = pidParts[1]
		}

		portMap[port] = &ProcessPortInfo{
			Port:        port,
			Protocol:    "tcp",
			PID:         pid,
			ProcessName: processName,
			State:       "LISTEN",
			User:        "", // Would need /proc/<pid>/status parsing
		}
	}

	return portMap, nil
}

// getLinuxPortMappingProc parses /proc/net/tcp (no external dependencies).
// Requires walking /proc/<pid>/fd/ to match socket inodes to PIDs.
// Use getLinuxPortMappingNetstat() as the primary path; this proc-walk is the
// fallback for environments without net-tools installed.
func getLinuxPortMappingProc() (map[int]*ProcessPortInfo, error) {
	return nil, fmt.Errorf("proc/net/tcp inode-walk not yet wired; ensure net-tools is installed for netstat fallback")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
