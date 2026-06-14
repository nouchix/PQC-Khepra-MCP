package scanner

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// Result represents a finding from the scanner
type Result struct {
	Target      string `json:"target"`
	Port        int    `json:"port"`
	Service     string `json:"service"`
	Status      string `json:"status"` // "OPEN", "FILTERED"
	Fingerprint string `json:"fingerprint"`
	Banner      string `json:"banner"` // The "Voice" of the service
}

// Scanner is the core reconnaissance engine
type Scanner struct {
	Ports       []int
	Concurrency int    // Number of concurrent threads (default: 1000)
	Proxy       string // SOCKS5 Proxy Address (e.g. "127.0.0.1:9050")
}

// New creates a new Scanner instance.
// By default, it loads the Top 100 Enterprise ports.
// Call ScanAllPorts() to enable full 1-65535 scanning.
func New() *Scanner {
	return &Scanner{
		Ports:       commonPorts,
		Concurrency: 1000,
	}
}

// SetProxy enables SOCKS5 routing for IP masking (e.g. Tor)
func (s *Scanner) SetProxy(proxyAddr string) {
	s.Proxy = proxyAddr
}

// SetFullScan enables scanning of all 65535 TCP ports
func (s *Scanner) SetFullScan() {
	all := make([]int, 65535)
	for i := 0; i < 65535; i++ {
		all[i] = i + 1
	}
	s.Ports = all
}

// FocusPorts reshuffles the scanning queue to prioritize ports identified by
// external intelligence (e.g. Shodan, Config files, Packet/TShark).
// It ensures high-value targets are scanned immediately by the worker pool.
func (s *Scanner) FocusPorts(intel []int) {
	unique := make(map[int]bool)
	for _, p := range s.Ports {
		unique[p] = true
	}

	// Ensure Intel ports are included
	for _, p := range intel {
		unique[p] = true
	}

	// Reconstruct the slice: Priority List FIRST
	var newOrder []int

	// 1. High Priority (Intel)
	for _, p := range intel {
		if unique[p] {
			newOrder = append(newOrder, p)
			delete(unique, p) // Mark as added
		}
	}

	// 2. The Rest (Standard List)
	var remaining []int
	for p := range unique {
		remaining = append(remaining, p)
	}
	sort.Ints(remaining)

	s.Ports = append(newOrder, remaining...)
}

// Run performs a concurrent port scan on the target using a worker pool
func (s *Scanner) Run(target string) ([]Result, error) {
	// Resolve IP (Local or Proxy?)
	// If Proxy is set, we let the Proxy resolve it! So we don't leak DNS locally.
	targetIP := target
	if s.Proxy == "" {
		ips, err := net.LookupIP(target)
		if err != nil {
			// Fallback: maybe it's already an IP
			if net.ParseIP(target) == nil {
				return nil, fmt.Errorf("failed to resolve target: %v", err)
			}
		} else {
			targetIP = ips[0].String()
		}
	}

	results := make(chan Result)
	var finalResults []Result

	// Worker Pool Control
	portsChan := make(chan int, len(s.Ports))
	var wg sync.WaitGroup

	// Start Workers
	for i := 0; i < s.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portsChan {
				res := s.scanPort(targetIP, port)
				if res != nil {
					results <- *res
				}
			}
		}()
	}

	// Feed Workers
	go func() {
		for _, p := range s.Ports {
			portsChan <- p
		}
		close(portsChan)
	}()

	// Collector
	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		finalResults = append(finalResults, r)
		if s.Proxy != "" && len(finalResults) == 1 {
			fmt.Printf("[SCANNER] Tunnel Active. Found open port via %s\n", s.Proxy)
		}
	}

	// Sort by port for clean output
	sort.Slice(finalResults, func(i, j int) bool {
		return finalResults[i].Port < finalResults[j].Port
	})

	return finalResults, nil
}

func (s *Scanner) scanPort(host string, port int) *Result {
	address := net.JoinHostPort(host, fmt.Sprint(port))
	timeout := 2000 * time.Millisecond

	var conn net.Conn
	var err error

	if s.Proxy != "" {
		conn, err = s.dialSOCKS5(address)
	} else {
		conn, err = net.DialTimeout("tcp", address, timeout)
	}

	if err != nil {
		return nil // Closed
	}
	defer conn.Close()

	// [raid] Active Recon: Grab the Banner
	banner := s.grabBanner(conn, port, host)
	serviceName := identifyService(port)
	if banner != "" {
		// Heuristic: If banner contains SSH, correct the service name
		if len(banner) > 3 && banner[:3] == "SSH" {
			serviceName = "SSH"
		}
	}

	return &Result{
		Target:  host,
		Port:    port,
		Status:  "OPEN",
		Service: serviceName,
		Banner:  banner,
	}
}

// grabBanner attempts to coerce the service into identifying itself.
func (s *Scanner) grabBanner(conn net.Conn, port int, host string) string {
	// Protocol-Specific Probes
	switch port {
	case 80, 443, 8080, 8443, 11434, 18789:
		return s.httpBanner(conn, host)
	default:
		return s.genericBanner(conn)
	}
}

// genericBanner just listens. Good for SSH, FTP, SMTP.
func (s *Scanner) genericBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(1000 * time.Millisecond))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}
	return string(buffer[:n])
}

// httpBanner sends a HEAD request to extract Server header
func (s *Scanner) httpBanner(conn net.Conn, host string) string {
	conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	conn.SetReadDeadline(time.Now().Add(1000 * time.Millisecond))

	req := fmt.Sprintf("HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: Khepra-Commando/1.0\r\n\r\n", host)
	conn.Write([]byte(req))

	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}
	return string(buffer[:n])
}

// dialSOCKS5 implements a minimal Zero-Dependency SOCKS5 client handshake
func (s *Scanner) dialSOCKS5(targetAddr string) (net.Conn, error) {
	// 1. Connect to Proxy
	proxyConn, err := net.DialTimeout("tcp", s.Proxy, 2000*time.Millisecond)
	if err != nil {
		return nil, err
	}

	// 2. Client Greeting
	_, err = proxyConn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		proxyConn.Close()
		return nil, err
	}

	// 3. Server Choice
	header := make([]byte, 2)
	_, err = proxyConn.Read(header)
	if err != nil || header[0] != 0x05 || header[1] != 0x00 {
		proxyConn.Close()
		return nil, fmt.Errorf("proxy handshake failed")
	}

	// 4. Client Connection Request
	host, portStr, _ := net.SplitHostPort(targetAddr)
	portInt := commonPorts[0]
	fmt.Sscanf(portStr, "%d", &portInt)

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(portInt>>8), byte(portInt&0xff))

	_, err = proxyConn.Write(req)
	if err != nil {
		proxyConn.Close()
		return nil, err
	}

	// 5. Server Response
	resp := make([]byte, 256)
	n, err := proxyConn.Read(resp)
	if err != nil || n < 4 || resp[1] != 0x00 {
		proxyConn.Close()
		return nil, fmt.Errorf("proxy connect failed")
	}

	return proxyConn, nil
}

func identifyService(port int) string {
	switch port {
	case 21:
		return "FTP"
	case 22:
		return "SSH"
	case 23:
		return "Telnet"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 80:
		return "HTTP"
	case 443:
		return "HTTPS"
	case 3389:
		return "RDP"
	case 8080:
		return "HTTP-Alt"
	case 8443:
		return "HTTPS-Alt"
	case 11434:
		return "Ollama-LLM"
	case 18789:
		return "OpenClaw-NemoClaw" // NVIDIA NemoClaw / OpenClaw agent gateway default port
	default:
		return "Unknown"
	}
}

var commonPorts = []int{
	20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
	1433, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 11434, 18789, 27017,
}
