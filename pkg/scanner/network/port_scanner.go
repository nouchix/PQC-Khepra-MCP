package network

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"
)

// PortResult holds the outcome of a single port probe
type PortResult struct {
	Port    int
	State   string // "open", "closed"
	Service string // "ssh", "http", "unknown"
	Banner  string
}

// NativeScanner manages the scan configuration
type NativeScanner struct {
	Target  string
	Ports   []int
	Timeout time.Duration
	Threads int
}

// NewScanner creates a scanner with safe defaults (Non-Aggressive)
func NewScanner(target string, ports []int) *NativeScanner {
	if len(ports) == 0 {
		ports = CommonPorts()
	}
	return &NativeScanner{
		Target:  target,
		Ports:   ports,
		Timeout: 2 * time.Second, // Fast connect
		Threads: 50,              // Politeness factor
	}
}

// Scan executes the port sweep using a worker pool pattern
func (s *NativeScanner) Scan(ctx context.Context) []PortResult {
	results := make(chan PortResult, len(s.Ports))
	jobs := make(chan int, len(s.Ports))
	var wg sync.WaitGroup

	// 1. Spawn Workers
	for i := 0; i < s.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				// Check Context Cancellation
				select {
				case <-ctx.Done():
					return
				default:
					s.probe(port, results)
				}
			}
		}()
	}

	// 2. Dispatch Jobs
	for _, port := range s.Ports {
		jobs <- port
	}
	close(jobs)

	// 3. Wait & Close
	wg.Wait()
	close(results)

	// 4. Collect
	var findings []PortResult
	for res := range results {
		if res.State == "open" {
			findings = append(findings, res)
		}
	}
	return findings
}

// probe attempts to connect and identify the service
func (s *NativeScanner) probe(port int, results chan<- PortResult) {
	address := net.JoinHostPort(s.Target, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, s.Timeout)

	if err != nil {
		return // Closed or Filtered
	}
	defer conn.Close()

	// Port is Open! Capture Banner.
	res := PortResult{Port: port, State: "open", Service: "unknown"}

	// Banner Grab Logic (Simplified ZGrab replacement)
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	bannerBuf := make([]byte, 1024)
	n, _ := conn.Read(bannerBuf)
	if n > 0 {
		res.Banner = string(bannerBuf[:n])
		res.Service = identifyService(res.Banner, port)
	} else {
		res.Service = guessService(port)
	}

	results <- res
}

func guessService(port int) string {
	switch port {
	case 22:
		return "ssh"
	case 80:
		return "http"
	case 443:
		return "https"
	case 3306:
		return "mysql"
	case 5432:
		return "postgres"
	default:
		return "unknown"
	}
}

func identifyService(banner string, port int) string {
	// Simple Heuristics
	if len(banner) > 3 && (banner[:3] == "SSH") {
		return "ssh"
	}
	if len(banner) > 4 && (banner[:4] == "HTTP") {
		return "http"
	}
	// Fallback to port guess
	return guessService(port)
}

func CommonPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
		1723, 3306, 3389, 5432, 5900, 8080, 8443,
	}
}
