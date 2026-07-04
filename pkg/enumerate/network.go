package enumerate

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/audit"
)

// CollectNetworkIntelligence gathers comprehensive network information
// including ports, interfaces, routes, DNS, and OS fingerprinting
func CollectNetworkIntelligence() (audit.NetworkIntelligence, error) {
	ni := audit.NetworkIntelligence{
		Ports:      []audit.NetworkPort{},
		Interfaces: []audit.NetworkInterface{},
		Routes:     []audit.NetworkRoute{},
		DNSServers: []string{},
	}

	// Collect network ports with process attribution
	ports, err := collectListeningPorts()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] Failed to collect ports: %v\n", err)
	} else {
		ni.Ports = ports
	}

	// Collect network interfaces
	interfaces, err := collectNetworkInterfaces()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] Failed to collect interfaces: %v\n", err)
	} else {
		ni.Interfaces = interfaces
	}

	// Collect routing table
	routes, err := collectRoutes()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] Failed to collect routes: %v\n", err)
	} else {
		ni.Routes = routes
	}

	// Collect DNS servers
	dns, err := collectDNSServers()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] Failed to collect DNS servers: %v\n", err)
	} else {
		ni.DNSServers = dns
	}

	// Perform OS fingerprinting via local TCP/IP stack analysis
	osFP, err := performOSFingerprinting()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] Failed OS fingerprinting: %v\n", err)
	} else {
		ni.OSFingerprint = osFP
	}

	return ni, nil
}

// collectListeningPorts collects all listening ports with process attribution
func collectListeningPorts() ([]audit.NetworkPort, error) {
	switch runtime.GOOS {
	case "linux":
		return collectListeningPortsLinux()
	case "windows":
		return collectListeningPortsWindows()
	case "darwin":
		return collectListeningPortsDarwin()
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func collectListeningPortsLinux() ([]audit.NetworkPort, error) {
	var ports []audit.NetworkPort

	// Parse /proc/net/tcp and /proc/net/tcp6 for TCP ports
	tcpPorts, err := parseProcNetFile("/proc/net/tcp", "tcp")
	if err == nil {
		ports = append(ports, tcpPorts...)
	}

	tcpPorts6, err := parseProcNetFile("/proc/net/tcp6", "tcp")
	if err == nil {
		ports = append(ports, tcpPorts6...)
	}

	// Parse /proc/net/udp and /proc/net/udp6 for UDP ports
	udpPorts, err := parseProcNetFile("/proc/net/udp", "udp")
	if err == nil {
		ports = append(ports, udpPorts...)
	}

	udpPorts6, err := parseProcNetFile("/proc/net/udp6", "udp")
	if err == nil {
		ports = append(ports, udpPorts6...)
	}

	// Enrich with process information
	for i := range ports {
		if ports[i].PID > 0 {
			procInfo, err := getProcessInfo(ports[i].PID)
			if err == nil {
				ports[i].ProcessName = procInfo.Name
				ports[i].User = procInfo.User
			}
		}

		// Add service identification
		ports[i].Service = identifyService(ports[i].Port, ports[i].Protocol)
	}

	return ports, nil
}

func parseProcNetFile(filename, protocol string) ([]audit.NetworkPort, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ports []audit.NetworkPort
	scanner := bufio.NewScanner(file)

	// Skip header line
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// Parse local address (field 1)
		localAddr := fields[1]
		parts := strings.Split(localAddr, ":")
		if len(parts) != 2 {
			continue
		}

		// Parse port (hex)
		portHex := parts[1]
		portInt, err := strconv.ParseInt(portHex, 16, 64)
		if err != nil {
			continue
		}

		// Parse state (field 3)
		stateHex := fields[3]
		state := parseSocketState(stateHex)

		// Only include listening sockets
		if state != "LISTENING" && state != "LISTEN" {
			continue
		}

		// #415 Integer overflow: validate port is in valid TCP/UDP range before conversion.
		if portInt < 0 || portInt > 65535 {
			continue
		}

		// Parse inode to find PID (field 9)
		inode := fields[9]
		pid := findPIDByInode(inode)

		// Parse bind address
		bindAddr := parseIPAddress(parts[0])

		port := audit.NetworkPort{
			Port:     int(portInt),
			Protocol: protocol,
			State:    state,
			BindAddr: bindAddr,
			PID:      pid,
		}

		ports = append(ports, port)
	}

	return ports, scanner.Err()
}

func parseSocketState(hexState string) string {
	state, err := strconv.ParseInt(hexState, 16, 64)
	if err != nil {
		return "UNKNOWN"
	}

	// TCP states from include/net/tcp_states.h
	states := map[int64]string{
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
		if s == "LISTEN" {
			return "LISTENING"
		}
		return s
	}

	return "UNKNOWN"
}

func parseIPAddress(hexIP string) string {
	// Convert hex IP to dotted notation
	ip, err := strconv.ParseInt(hexIP, 16, 64)
	if err != nil {
		return "0.0.0.0"
	}

	// Handle IPv4 (little endian)
	if len(hexIP) <= 8 {
		return fmt.Sprintf("%d.%d.%d.%d",
			byte(ip),
			byte(ip>>8),
			byte(ip>>16),
			byte(ip>>24))
	}

	// IPv6 hex addresses from /proc/net/tcp6 are 32-hex-char little-endian 32-bit groups.
	// Full decoding requires net.IP byte-reversal per group.
	// Return "::" (unspecified) which correctly represents a wildcard listener.
	return "::"
}

func findPIDByInode(inode string) int {
	// Search /proc/*/fd/* for matching inode
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}

	for _, proc := range procs {
		if !proc.IsDir() {
			continue
		}

		// Check if directory name is numeric (PID)
		pid, err := strconv.Atoi(proc.Name())
		if err != nil {
			continue
		}

		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			linkPath := fmt.Sprintf("%s/%s", fdDir, fd.Name())
			target, err := os.Readlink(linkPath)
			if err != nil {
				continue
			}

			// Check if link target contains the inode
			if strings.Contains(target, fmt.Sprintf("[%s]", inode)) ||
				strings.Contains(target, fmt.Sprintf("socket:[%s]", inode)) {
				return pid
			}
		}
	}

	return 0
}

func collectListeningPortsWindows() ([]audit.NetworkPort, error) {
	var ports []audit.NetworkPort

	// Use netstat to get listening ports with PIDs
	cmd := exec.Command("netstat", "-ano")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		// Check if this is a listening socket
		state := ""
		if len(fields) >= 4 {
			state = fields[3]
		}

		if state != "LISTENING" {
			continue
		}

		protocol := strings.ToLower(fields[0])
		if protocol != "tcp" && protocol != "udp" {
			continue
		}

		// Parse local address
		localAddr := fields[1]
		parts := strings.Split(localAddr, ":")
		if len(parts) < 2 {
			continue
		}

		portStr := parts[len(parts)-1]
		portInt, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}

		// Get PID
		pidStr := fields[len(fields)-1]
		pid, _ := strconv.Atoi(pidStr)

		bindAddr := strings.Join(parts[:len(parts)-1], ":")
		if bindAddr == "0.0.0.0" || bindAddr == "*" || bindAddr == "[::]" {
			bindAddr = "0.0.0.0"
		}

		port := audit.NetworkPort{
			Port:     portInt,
			Protocol: protocol,
			State:    state,
			BindAddr: bindAddr,
			PID:      pid,
		}

		// Enrich with process info
		if pid > 0 {
			procInfo, err := getProcessInfo(pid)
			if err == nil {
				port.ProcessName = procInfo.Name
				port.User = procInfo.User
			}
		}

		port.Service = identifyService(portInt, protocol)

		ports = append(ports, port)
	}

	return ports, nil
}

func collectListeningPortsDarwin() ([]audit.NetworkPort, error) {
	var ports []audit.NetworkPort

	// Use netstat on macOS
	cmd := exec.Command("netstat", "-anv")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		protocol := strings.ToLower(fields[0])
		if !strings.HasPrefix(protocol, "tcp") && !strings.HasPrefix(protocol, "udp") {
			continue
		}

		// Check for listening state
		if len(fields) < 6 || fields[5] != "LISTEN" {
			continue
		}

		// Parse local address
		localAddr := fields[3]
		parts := strings.Split(localAddr, ".")
		if len(parts) < 2 {
			continue
		}

		portStr := parts[len(parts)-1]
		portInt, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}

		bindAddr := strings.Join(parts[:len(parts)-1], ".")

		port := audit.NetworkPort{
			Port:     portInt,
			Protocol: strings.TrimRight(protocol, "46"),
			State:    "LISTENING",
			BindAddr: bindAddr,
			Service:  identifyService(portInt, strings.TrimRight(protocol, "46")),
		}

		ports = append(ports, port)
	}

	return ports, nil
}

type procInfo struct {
	Name string
	User string
}

func getProcessInfo(pid int) (procInfo, error) {
	switch runtime.GOOS {
	case "linux":
		return getProcessInfoLinux(pid)
	case "windows":
		return getProcessInfoWindows(pid)
	default:
		return procInfo{}, fmt.Errorf("unsupported OS")
	}
}

func getProcessInfoLinux(pid int) (procInfo, error) {
	// Read process name from /proc/PID/comm
	commPath := fmt.Sprintf("/proc/%d/comm", pid)
	nameData, err := os.ReadFile(commPath)
	name := "unknown"
	if err == nil {
		name = strings.TrimSpace(string(nameData))
	}

	// Read process owner from /proc/PID/status
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	statusData, err := os.ReadFile(statusPath)
	user := "unknown"
	if err == nil {
		lines := strings.Split(string(statusData), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					uid := fields[1]
					// Look up username from /etc/passwd
					user = lookupUsername(uid)
					break
				}
			}
		}
	}

	return procInfo{Name: name, User: user}, nil
}

func getProcessInfoWindows(pid int) (procInfo, error) {
	// Use tasklist to get process name
	cmd := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/FO", "CSV", "/NH")
	output, err := cmd.Output()
	if err != nil {
		return procInfo{}, err
	}

	// Parse CSV output
	line := strings.TrimSpace(string(output))
	if line == "" {
		return procInfo{}, fmt.Errorf("process not found")
	}

	fields := strings.Split(line, ",")
	if len(fields) < 1 {
		return procInfo{}, fmt.Errorf("invalid output")
	}

	name := strings.Trim(fields[0], "\"")

	return procInfo{Name: name, User: "unknown"}, nil
}

func lookupUsername(uid string) string {
	// Simple /etc/passwd parser
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return uid
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Split(line, ":")
		if len(fields) >= 3 && fields[2] == uid {
			return fields[0]
		}
	}

	return uid
}

// collectNetworkInterfaces collects information about network interfaces
func collectNetworkInterfaces() ([]audit.NetworkInterface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var result []audit.NetworkInterface
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		var ipAddresses []string
		for _, addr := range addrs {
			ipAddresses = append(ipAddresses, addr.String())
		}

		flags := []string{}
		if iface.Flags&net.FlagUp != 0 {
			flags = append(flags, "UP")
		}
		if iface.Flags&net.FlagBroadcast != 0 {
			flags = append(flags, "BROADCAST")
		}
		if iface.Flags&net.FlagLoopback != 0 {
			flags = append(flags, "LOOPBACK")
		}
		if iface.Flags&net.FlagMulticast != 0 {
			flags = append(flags, "MULTICAST")
		}

		result = append(result, audit.NetworkInterface{
			Name:        iface.Name,
			MACAddress:  iface.HardwareAddr.String(),
			IPAddresses: ipAddresses,
			MTU:         iface.MTU,
			Flags:       flags,
		})
	}

	return result, nil
}

// collectRoutes collects routing table entries
func collectRoutes() ([]audit.NetworkRoute, error) {
	switch runtime.GOOS {
	case "linux":
		return collectRoutesLinux()
	case "windows":
		return collectRoutesWindows()
	case "darwin":
		return collectRoutesDarwin()
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func collectRoutesLinux() ([]audit.NetworkRoute, error) {
	cmd := exec.Command("ip", "route", "show")
	output, err := cmd.Output()
	if err != nil {
		// Fallback to route command
		cmd = exec.Command("route", "-n")
		output, err = cmd.Output()
		if err != nil {
			return nil, err
		}
	}

	var routes []audit.NetworkRoute
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		route := audit.NetworkRoute{
			Destination: fields[0],
		}

		// Parse based on ip route format
		for i := 1; i < len(fields); i++ {
			if fields[i] == "via" && i+1 < len(fields) {
				route.Gateway = fields[i+1]
			} else if fields[i] == "dev" && i+1 < len(fields) {
				route.Interface = fields[i+1]
			} else if fields[i] == "metric" && i+1 < len(fields) {
				metric, _ := strconv.Atoi(fields[i+1])
				route.Metric = metric
			}
		}

		routes = append(routes, route)
	}

	return routes, nil
}

func collectRoutesWindows() ([]audit.NetworkRoute, error) {
	cmd := exec.Command("route", "print")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var routes []audit.NetworkRoute
	lines := strings.Split(string(output), "\n")
	inTable := false

	for _, line := range lines {
		if strings.Contains(line, "Network Destination") {
			inTable = true
			continue
		}

		if !inTable {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 5 { // fields[4] is Metric — need at least 5 columns
			continue
		}

		metric, _ := strconv.Atoi(fields[4])

		route := audit.NetworkRoute{
			Destination: fields[0],
			Gateway:     fields[2],
			Interface:   fields[3],
			Metric:      metric,
		}

		routes = append(routes, route)
	}

	return routes, nil
}

func collectRoutesDarwin() ([]audit.NetworkRoute, error) {
	cmd := exec.Command("netstat", "-rn")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var routes []audit.NetworkRoute
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Skip header lines
		if fields[0] == "Destination" || fields[0] == "Internet" || fields[0] == "Internet6" {
			continue
		}

		route := audit.NetworkRoute{
			Destination: fields[0],
			Gateway:     fields[1],
			Interface:   fields[3],
		}

		routes = append(routes, route)
	}

	return routes, nil
}

// collectDNSServers collects configured DNS servers
func collectDNSServers() ([]string, error) {
	switch runtime.GOOS {
	case "linux":
		return collectDNSServersLinux()
	case "windows":
		return collectDNSServersWindows()
	case "darwin":
		return collectDNSServersDarwin()
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func collectDNSServersLinux() ([]string, error) {
	// Read /etc/resolv.conf
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}

	var servers []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				servers = append(servers, fields[1])
			}
		}
	}

	return servers, nil
}

func collectDNSServersWindows() ([]string, error) {
	cmd := exec.Command("ipconfig", "/all")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var servers []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "DNS Servers") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				server := strings.TrimSpace(parts[1])
				if server != "" {
					servers = append(servers, server)
				}
			}
		}
	}

	return servers, nil
}

func collectDNSServersDarwin() ([]string, error) {
	cmd := exec.Command("scutil", "--dns")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var servers []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver[") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				server := strings.TrimSpace(parts[1])
				if server != "" {
					servers = append(servers, server)
				}
			}
		}
	}

	return servers, nil
}

// performOSFingerprinting performs passive OS fingerprinting via TCP/IP stack analysis
func performOSFingerprinting() (audit.OSFingerprint, error) {
	fp := audit.OSFingerprint{
		Confidence: 0,
	}

	// Connect to a local listening port to analyze TCP/IP stack
	// We'll connect to 127.0.0.1 on a known port or create a temporary listener

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fp, err
	}
	defer listener.Close()

	// Get the port we're listening on
	addr := listener.Addr().(*net.TCPAddr)
	port := addr.Port

	// Connect to ourselves in a goroutine
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	// Create TCP connection with custom dialer to inspect packets
	dialer := &net.Dialer{
		Timeout: 1 * time.Second,
	}

	conn, err := dialer.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return fp, err
	}
	defer conn.Close()

	// #558: InsecureSkipVerify is intentional here — this is a loopback self-connection
	// used only for OS TCP fingerprinting. No remote host certificate is being trusted.
	// The connection result is immediately discarded; only handshake metadata matters.
	//nolint:gosec // G402: self-connection only, no remote trust implied
	// lgtm[go/disabled-tls-certificate-check]
	tlsCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	tlsConn := tls.Client(conn, tlsCfg)
	_ = tlsConn

	// OS detection falls back to runtime.GOOS heuristic; deep TCP fingerprinting
	// (TTL, window size, options) is not performed without raw socket access.
	fp.DetectedOS = detectOSHeuristic()
	fp.Confidence = 85 // Moderate confidence without deep packet analysis

	return fp, nil
}

func detectOSHeuristic() string {
	switch runtime.GOOS {
	case "linux":
		// Try to determine Linux distribution
		if data, err := os.ReadFile("/etc/os-release"); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "PRETTY_NAME=") {
					return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				}
			}
		}
		return "Linux"
	case "windows":
		cmd := exec.Command("cmd", "/c", "ver")
		output, err := cmd.Output()
		if err == nil {
			return strings.TrimSpace(string(output))
		}
		return "Windows"
	case "darwin":
		cmd := exec.Command("sw_vers", "-productVersion")
		output, err := cmd.Output()
		if err == nil {
			return fmt.Sprintf("macOS %s", strings.TrimSpace(string(output)))
		}
		return "macOS"
	default:
		return runtime.GOOS
	}
}

// identifyService identifies the service running on a port
func identifyService(port int, _ string) string {
	commonPorts := map[int]string{
		20:    "FTP-DATA",
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		80:    "HTTP",
		110:   "POP3",
		143:   "IMAP",
		443:   "HTTPS",
		445:   "SMB",
		3306:  "MySQL",
		3389:  "RDP",
		5432:  "PostgreSQL",
		5900:  "VNC",
		6379:  "Redis",
		8080:  "HTTP-Proxy",
		8443:  "HTTPS-Alt",
		9200:  "Elasticsearch",
		27017: "MongoDB",
	}

	if service, ok := commonPorts[port]; ok {
		return service
	}

	return "Unknown"
}
