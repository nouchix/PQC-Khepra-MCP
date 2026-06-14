package gateway

import (
	"net/http/httptest"
	"testing"
)

func TestFirewallLayer_MethodWhitelist(t *testing.T) {
	cfg := &FirewallConfig{
		AllowedMethods: []string{"GET", "POST"},
	}

	fw, err := NewFirewallLayer(cfg)
	if err != nil {
		t.Fatalf("Failed to create firewall: %v", err)
	}

	tests := []struct {
		name    string
		method  string
		blocked bool
	}{
		{"GET allowed", "GET", false},
		{"POST allowed", "POST", false},
		{"PUT blocked", "PUT", true},
		{"DELETE blocked", "DELETE", true},
		{"PATCH blocked", "PATCH", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/api/test", nil)
			blocked, _ := fw.Check(req)
			if blocked != tt.blocked {
				t.Errorf("Method %s: expected blocked=%v, got blocked=%v", tt.method, tt.blocked, blocked)
			}
		})
	}
}

func TestFirewallLayer_SQLInjectionDetection(t *testing.T) {
	cfg := &FirewallConfig{
		EnableSQLiProtection: true,
		AllowedMethods:       []string{"GET", "POST"},
	}

	fw, err := NewFirewallLayer(cfg)
	if err != nil {
		t.Fatalf("Failed to create firewall: %v", err)
	}

	tests := []struct {
		name       string
		path       string
		queryKey   string
		queryValue string
		blocked    bool
	}{
		{"Clean path", "/api/users/123", "", "", false},
		{"SQLi union select", "/api/users", "id", "1 UNION SELECT * FROM users", true},
		{"SQLi comment", "/api/users", "id", "1--", true},
		{"SQLi OR injection", "/api/users", "name", "admin' OR '1'='1", true},
		{"SQLi semicolon", "/api/users", "id", "1; DROP TABLE users", true},
		{"Clean query", "/api/users", "name", "john", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			if tt.queryKey != "" {
				q := req.URL.Query()
				q.Set(tt.queryKey, tt.queryValue)
				req.URL.RawQuery = q.Encode()
			}
			blocked, reason := fw.Check(req)
			if blocked != tt.blocked {
				t.Errorf("Query %s=%s: expected blocked=%v, got blocked=%v (reason: %s)", tt.queryKey, tt.queryValue, tt.blocked, blocked, reason)
			}
		})
	}
}

func TestFirewallLayer_XSSDetection(t *testing.T) {
	cfg := &FirewallConfig{
		EnableXSSProtection: true,
		AllowedMethods:      []string{"GET", "POST"},
	}

	fw, err := NewFirewallLayer(cfg)
	if err != nil {
		t.Fatalf("Failed to create firewall: %v", err)
	}

	tests := []struct {
		name       string
		queryValue string
		blocked    bool
	}{
		{"Clean query", "hello", false},
		{"XSS script tag", "<script>alert('xss')</script>", true},
		{"XSS event handler", "<img onerror=alert(1)>", true},
		{"XSS javascript:", "javascript:alert(1)", true},
		{"XSS iframe", "<iframe src='evil.com'>", true},
		{"Clean text", "hello world", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/search", nil)
			q := req.URL.Query()
			q.Set("q", tt.queryValue)
			req.URL.RawQuery = q.Encode()
			blocked, reason := fw.Check(req)
			if blocked != tt.blocked {
				t.Errorf("Query q=%s: expected blocked=%v, got blocked=%v (reason: %s)", tt.queryValue, tt.blocked, blocked, reason)
			}
		})
	}
}

func TestFirewallLayer_LFIDetection(t *testing.T) {
	cfg := &FirewallConfig{
		EnableLFIProtection: true,
		AllowedMethods:      []string{"GET"},
	}

	fw, err := NewFirewallLayer(cfg)
	if err != nil {
		t.Fatalf("Failed to create firewall: %v", err)
	}

	tests := []struct {
		name       string
		path       string
		queryKey   string
		queryValue string
		blocked    bool
	}{
		{"Clean path", "/api/files/document.pdf", "", "", false},
		{"LFI path traversal", "/api/files/../../../etc/passwd", "", "", true},
		{"LFI etc passwd", "/api/files", "path", "/etc/passwd", true},
		{"LFI windows path", "/api/files", "path", "c:\\windows\\system32", true},
		{"LFI php filter", "/api/files", "path", "php://filter/convert.base64-encode/resource=index.php", true},
		{"Clean relative", "/api/files/subfolder/doc.pdf", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			if tt.queryKey != "" {
				q := req.URL.Query()
				q.Set(tt.queryKey, tt.queryValue)
				req.URL.RawQuery = q.Encode()
			}
			blocked, reason := fw.Check(req)
			if blocked != tt.blocked {
				t.Errorf("Path %s query=%s: expected blocked=%v, got blocked=%v (reason: %s)", tt.path, tt.queryValue, tt.blocked, blocked, reason)
			}
		})
	}
}

func TestFirewallLayer_RCEDetection(t *testing.T) {
	cfg := &FirewallConfig{
		EnableRCEProtection: true,
		AllowedMethods:      []string{"GET", "POST"},
	}

	fw, err := NewFirewallLayer(cfg)
	if err != nil {
		t.Fatalf("Failed to create firewall: %v", err)
	}

	tests := []struct {
		name       string
		path       string
		queryKey   string
		queryValue string
		blocked    bool
	}{
		{"Clean path", "/api/execute", "cmd", "list", false},
		{"RCE pipe", "/api/execute", "cmd", "ls|cat /etc/passwd", true},
		{"RCE semicolon", "/api/execute", "cmd", "ls;rm -rf /", true},
		{"RCE backtick", "/api/execute", "cmd", "`whoami`", true},
		{"RCE bash", "/api/execute", "cmd", "/bin/bash -c 'ls'", true},
		{"RCE netcat", "/api/execute", "cmd", "nc -e /bin/sh", true},
		{"Clean command name", "/api/commands/backup", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			if tt.queryKey != "" {
				q := req.URL.Query()
				q.Set(tt.queryKey, tt.queryValue)
				req.URL.RawQuery = q.Encode()
			}
			blocked, reason := fw.Check(req)
			if blocked != tt.blocked {
				t.Errorf("Query %s=%s: expected blocked=%v, got blocked=%v (reason: %s)", tt.queryKey, tt.queryValue, tt.blocked, blocked, reason)
			}
		})
	}
}

func TestFirewallLayer_IPBlocking(t *testing.T) {
	cfg := &FirewallConfig{
		AllowedMethods: []string{"GET"},
	}

	fw, err := NewFirewallLayer(cfg)
	if err != nil {
		t.Fatalf("Failed to create firewall: %v", err)
	}

	// Add an IP to blocklist
	fw.AddBlockedIP("192.168.1.100")

	tests := []struct {
		name     string
		clientIP string
		blocked  bool
	}{
		{"Allowed IP", "10.0.0.1", false},
		{"Blocked IP", "192.168.1.100", true},
		{"Another allowed IP", "172.16.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/test", nil)
			req.RemoteAddr = tt.clientIP + ":12345"
			blocked, _ := fw.Check(req)
			if blocked != tt.blocked {
				t.Errorf("IP %s: expected blocked=%v, got blocked=%v", tt.clientIP, tt.blocked, blocked)
			}
		})
	}

	// Test removal
	fw.RemoveBlockedIP("192.168.1.100")
	req := httptest.NewRequest("GET", "/api/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	blocked, _ := fw.Check(req)
	if blocked {
		t.Error("IP should be unblocked after removal")
	}
}

func TestFirewallLayer_RequestSizeLimit(t *testing.T) {
	cfg := &FirewallConfig{
		AllowedMethods:      []string{"POST"},
		MaxRequestSizeBytes: 1024, // 1KB limit
	}

	fw, err := NewFirewallLayer(cfg)
	if err != nil {
		t.Fatalf("Failed to create firewall: %v", err)
	}

	tests := []struct {
		name          string
		contentLength int64
		blocked       bool
	}{
		{"Small request", 100, false},
		{"At limit", 1024, false},
		{"Over limit", 2048, true},
		{"Way over limit", 1024 * 1024, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/upload", nil)
			req.ContentLength = tt.contentLength
			blocked, _ := fw.Check(req)
			if blocked != tt.blocked {
				t.Errorf("Size %d: expected blocked=%v, got blocked=%v", tt.contentLength, tt.blocked, blocked)
			}
		})
	}
}

func TestFirewallLayer_UserAgentInspection(t *testing.T) {
	// Test XSS in User-Agent (RCE patterns are too aggressive for UA)
	cfg := &FirewallConfig{
		EnableXSSProtection: true,
		AllowedMethods:      []string{"GET"},
	}

	fw, err := NewFirewallLayer(cfg)
	if err != nil {
		t.Fatalf("Failed to create firewall: %v", err)
	}

	tests := []struct {
		name      string
		userAgent string
		blocked   bool
	}{
		{"Normal browser", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", false},
		{"Curl", "curl/7.68.0", false},
		{"XSS in UA", "<script>alert('xss')</script>", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/test", nil)
			req.Header.Set("User-Agent", tt.userAgent)
			blocked, reason := fw.Check(req)
			if blocked != tt.blocked {
				t.Errorf("UA %s: expected blocked=%v, got blocked=%v (reason: %s)", tt.userAgent, tt.blocked, blocked, reason)
			}
		})
	}
}

func TestFirewallLayer_GetStats(t *testing.T) {
	cfg := &FirewallConfig{
		EnableSQLiProtection: true,
		EnableXSSProtection:  true,
		EnableLFIProtection:  true,
		EnableRCEProtection:  true,
	}

	fw, err := NewFirewallLayer(cfg)
	if err != nil {
		t.Fatalf("Failed to create firewall: %v", err)
	}

	stats := fw.GetStats()

	// Verify stats structure
	if _, ok := stats["sqli_patterns"]; !ok {
		t.Error("Stats missing sqli_patterns")
	}
	if _, ok := stats["xss_patterns"]; !ok {
		t.Error("Stats missing xss_patterns")
	}
	if _, ok := stats["blocked_ips_count"]; !ok {
		t.Error("Stats missing blocked_ips_count")
	}

	// Verify pattern counts are > 0
	if stats["sqli_patterns"].(int) == 0 {
		t.Error("Expected SQLi patterns to be loaded")
	}
	if stats["xss_patterns"].(int) == 0 {
		t.Error("Expected XSS patterns to be loaded")
	}
}

func BenchmarkFirewallCheck(b *testing.B) {
	cfg := &FirewallConfig{
		EnableSQLiProtection: true,
		EnableXSSProtection:  true,
		EnableLFIProtection:  true,
		EnableRCEProtection:  true,
		AllowedMethods:       []string{"GET", "POST", "PUT", "DELETE"},
	}

	fw, _ := NewFirewallLayer(cfg)
	req := httptest.NewRequest("GET", "/api/users?name=john&age=25&city=newyork", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fw.Check(req)
	}
}
