package agi

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// collectRunningProcesses returns a live snapshot of running processes.
// Uses ps on Linux/macOS and tasklist on Windows.
// Returns an empty slice on any platform or permission error.
func collectRunningProcesses() []Process {
	var out []byte
	var err error

	switch runtime.GOOS {
	case "linux", "darwin":
		// -e: all processes, -o: custom format (no header)
		out, err = exec.Command("ps", "-e", "-o", "pid=,comm=,user=,%cpu=,%mem=").Output()
	case "windows":
		out, err = exec.Command("tasklist", "/FO", "CSV", "/NH").Output()
	default:
		return nil
	}
	if err != nil {
		return nil
	}

	var procs []Process
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		switch runtime.GOOS {
		case "linux", "darwin":
			// Fields: PID COMM USER %CPU %MEM
			fields := strings.Fields(line)
			if len(fields) < 5 {
				continue
			}
			pid, _ := strconv.Atoi(fields[0])
			cpu, _ := strconv.ParseFloat(fields[3], 64)
			mem, _ := strconv.ParseFloat(fields[4], 64)
			procs = append(procs, Process{
				PID:        pid,
				Name:       fields[1],
				User:       fields[2],
				CPUPercent: cpu,
				MemoryMB:   mem,
			})

		case "windows":
			// CSV format: "Image Name","PID","Session Name","Session#","Mem Usage"
			parts := strings.Split(line, "\",\"")
			if len(parts) < 5 {
				continue
			}
			name := strings.Trim(parts[0], "\"")
			pid, _ := strconv.Atoi(strings.Trim(parts[1], "\""))
			procs = append(procs, Process{
				PID:  pid,
				Name: name,
				User: os.Getenv("USERNAME"),
			})
		}
	}
	return procs
}

// collectNetworkConnections returns active network connections.
// Uses ss on Linux, netstat on macOS/Windows.
// Returns an empty slice on any platform or permission error.
func collectNetworkConnections() []NetworkConnection {
	var out []byte
	var err error

	switch runtime.GOOS {
	case "linux":
		// -tnp: TCP, numeric, show PID
		out, err = exec.Command("ss", "-tnp").Output()
	case "darwin":
		out, err = exec.Command("netstat", "-an", "-p", "tcp").Output()
	case "windows":
		out, err = exec.Command("netstat", "-ano").Output()
	default:
		return nil
	}
	if err != nil {
		return nil
	}

	var conns []NetworkConnection
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "State") || strings.HasPrefix(line, "Proto") ||
			strings.HasPrefix(line, "Netid") || strings.HasPrefix(line, "Active") {
			continue
		}

		fields := strings.Fields(line)
		switch runtime.GOOS {
		case "linux":
			// ss -tnp: State RecvQ SendQ LocalAddr PeerAddr [Process]
			if len(fields) < 5 {
				continue
			}
			conns = append(conns, NetworkConnection{
				State:      fields[0],
				LocalAddr:  fields[3],
				RemoteAddr: fields[4],
			})
		case "darwin", "windows":
			// netstat: Proto RecvQ SendQ LocalAddr ForeignAddr State [PID]
			if len(fields) < 5 {
				continue
			}
			pid := 0
			if len(fields) >= 7 {
				pid, _ = strconv.Atoi(fields[6])
			} else if len(fields) == 6 {
				pid, _ = strconv.Atoi(fields[5])
			}
			conns = append(conns, NetworkConnection{
				LocalAddr:  fields[3],
				RemoteAddr: fields[4],
				State:      fields[len(fields)-1],
				PID:        pid,
			})
		}
	}
	return conns
}
