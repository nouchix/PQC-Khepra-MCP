// Package phantom - WiFi Puck (OYEALINK SRT873) Security Hardening
//
// The OYEALINK SRT873 MiFi is a portable 4G/LTE hotspot that can serve as:
// - Air-gapped network segment (isolated from main network)
// - Mobile Phantom mesh node (on the go)
// - Traffic relay with obfuscation
// - Backup connectivity (4G when WiFi compromised)
//
// SECURITY HARDENING:
// 1. Change default credentials (admin/admin is DANGEROUS)
// 2. Disable UPnP (auto port forwarding = security hole)
// 3. Disable WPS (PIN attack vulnerability)
// 4. Enable MAC filtering (whitelist your devices only)
// 5. Enable firewall with restrictive rules
// 6. Use DNS over HTTPS (prevent DNS snooping)
// 7. Hidden SSID (doesn't broadcast network name)
// 8. WPA3 encryption (if supported, otherwise WPA2-AES)
//
// Device: OYEALINK SRT873
// Admin IP: 192.168.8.1
// Default User: admin
// Default Pass: admin (CHANGE THIS!)
package phantom

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// =============================================================================
// WIFI PUCK CONFIGURATION
// =============================================================================

// WiFiPuckConfig holds the configuration for the OYEALINK hotspot
type WiFiPuckConfig struct {
	AdminIP          string         `json:"admin_ip"`
	AdminUser        string         `json:"admin_user"`
	AdminPass        string         `json:"admin_pass"`
	NewUser          string         `json:"new_user"`
	NewPass          string         `json:"new_pass"`
	SSID             string         `json:"ssid"`
	SSIDHidden       bool           `json:"ssid_hidden"`
	WiFiPassword     string         `json:"wifi_password"`
	Encryption       string         `json:"encryption"` // WPA3, WPA2-AES
	Channel          int            `json:"channel"`
	Subnet           string         `json:"subnet"`
	DHCPRange        string         `json:"dhcp_range"`
	DNSServers       []string       `json:"dns_servers"`
	DoHEnabled       bool           `json:"doh_enabled"`
	DoHServer        string         `json:"doh_server"`
	MACWhitelist     []string       `json:"mac_whitelist"`
	MACFilterEnabled bool           `json:"mac_filter_enabled"`
	UPnPDisabled     bool           `json:"upnp_disabled"`
	WPSDisabled      bool           `json:"wps_disabled"`
	FirewallEnabled  bool           `json:"firewall_enabled"`
	FirewallRules    []FirewallRule `json:"firewall_rules"`
}

// FirewallRule represents a firewall rule for the hotspot
type FirewallRule struct {
	Name       string `json:"name"`
	Direction  string `json:"direction"` // INBOUND, OUTBOUND
	Protocol   string `json:"protocol"`  // TCP, UDP, ICMP, ALL
	SourceIP   string `json:"source_ip"`
	SourcePort string `json:"source_port"`
	DestIP     string `json:"dest_ip"`
	DestPort   string `json:"dest_port"`
	Action     string `json:"action"` // ALLOW, DENY, DROP
}

// =============================================================================
// SECURE CONFIGURATION GENERATOR
// =============================================================================

// NewSecureWiFiPuckConfig generates a secure configuration for the OYEALINK
func NewSecureWiFiPuckConfig() *WiFiPuckConfig {
	// Generate cryptographically secure passwords
	adminPass := generateSecurePassword(24)
	wifiPass := generateSecurePassword(32)

	// Generate random SSID that doesn't reveal device type
	ssid := generateRandomSSID()

	return &WiFiPuckConfig{
		AdminIP:      "192.168.8.1",
		AdminUser:    "phantom_admin",
		AdminPass:    "admin", // Current password (to login)
		NewUser:      "phantom_admin",
		NewPass:      adminPass,
		SSID:         ssid,
		SSIDHidden:   true,
		WiFiPassword: wifiPass,
		Encryption:   "WPA2-AES", // WPA3 if supported
		Channel:      0,          // Auto
		Subnet:       "192.168.8.0/24",
		DHCPRange:    "192.168.8.100-192.168.8.199",
		DNSServers:   []string{"1.1.1.1", "8.8.8.8"}, // Will use DoH
		DoHEnabled:   true,
		DoHServer:    "https://cloudflare-dns.com/dns-query",
		MACWhitelist: []string{
			// Add your device MACs here
			// Pixel 9 WiFi MAC
			// Watch BT MAC (if it has WiFi)
		},
		MACFilterEnabled: true,
		UPnPDisabled:     true,
		WPSDisabled:      true,
		FirewallEnabled:  true,
		FirewallRules:    generateDefaultFirewallRules(),
	}
}

// generateSecurePassword creates a cryptographically secure password
func generateSecurePassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	b := make([]byte, length)
	rand.Read(b)
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}

// generateRandomSSID creates a random SSID that doesn't reveal the device type
func generateRandomSSID() string {
	// Use common router prefixes to blend in
	prefixes := []string{"NETGEAR", "Linksys", "ASUS", "TP-Link", "Spectrum", "ATT"}
	b := make([]byte, 4)
	rand.Read(b)

	prefix := prefixes[int(b[0])%len(prefixes)]
	suffix := hex.EncodeToString(b[1:4])

	return fmt.Sprintf("%s_%s", prefix, strings.ToUpper(suffix))
}

// generateDefaultFirewallRules creates restrictive firewall rules
func generateDefaultFirewallRules() []FirewallRule {
	return []FirewallRule{
		// Allow DHCP
		{Name: "Allow DHCP", Direction: "INBOUND", Protocol: "UDP", DestPort: "67-68", Action: "ALLOW"},

		// Allow DNS (for DoH bootstrap)
		{Name: "Allow DNS", Direction: "OUTBOUND", Protocol: "UDP", DestPort: "53", Action: "ALLOW"},

		// Allow HTTPS (for DoH and Phantom)
		{Name: "Allow HTTPS", Direction: "OUTBOUND", Protocol: "TCP", DestPort: "443", Action: "ALLOW"},

		// Allow Phantom Node (Tailscale)
		{Name: "Allow Tailscale", Direction: "OUTBOUND", Protocol: "UDP", DestPort: "41641", Action: "ALLOW"},

		// Allow Phantom API
		{Name: "Allow Phantom API", Direction: "OUTBOUND", Protocol: "TCP", DestPort: "8080", Action: "ALLOW"},

		// Block all incoming by default
		{Name: "Block Inbound", Direction: "INBOUND", Protocol: "ALL", Action: "DROP"},

		// Block common malicious ports
		{Name: "Block Telnet", Direction: "OUTBOUND", Protocol: "TCP", DestPort: "23", Action: "DROP"},
		{Name: "Block SMB", Direction: "OUTBOUND", Protocol: "TCP", DestPort: "445", Action: "DROP"},
		{Name: "Block RDP", Direction: "OUTBOUND", Protocol: "TCP", DestPort: "3389", Action: "DROP"},
	}
}

// =============================================================================
// WIFI PUCK CONTROLLER
// =============================================================================

// WiFiPuckController manages the OYEALINK hotspot
type WiFiPuckController struct {
	Config      *WiFiPuckConfig
	httpClient  *http.Client
	authToken   string
	isConnected bool
}

// NewWiFiPuckController creates a new controller
func NewWiFiPuckController(config *WiFiPuckConfig) *WiFiPuckController {
	return &WiFiPuckController{
		Config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Connect authenticates with the hotspot admin interface
func (wpc *WiFiPuckController) Connect() error {
	// Login to admin interface
	loginURL := fmt.Sprintf("http://%s/api/user/login", wpc.Config.AdminIP)

	loginData := url.Values{
		"username": {wpc.Config.AdminUser},
		"password": {wpc.Config.AdminPass},
	}

	resp, err := wpc.httpClient.PostForm(loginURL, loginData)
	if err != nil {
		return fmt.Errorf("failed to connect to hotspot: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login failed: status %d", resp.StatusCode)
	}

	// Extract auth token from response/cookies
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "session" || cookie.Name == "token" {
			wpc.authToken = cookie.Value
			break
		}
	}

	wpc.isConnected = true
	return nil
}

// ApplySecurityHardening applies all security settings
func (wpc *WiFiPuckController) ApplySecurityHardening() error {
	if !wpc.isConnected {
		if err := wpc.Connect(); err != nil {
			return err
		}
	}

	// 1. Change admin credentials
	if err := wpc.changeAdminCredentials(); err != nil {
		return fmt.Errorf("failed to change admin credentials: %w", err)
	}

	// 2. Configure WiFi settings
	if err := wpc.configureWiFi(); err != nil {
		return fmt.Errorf("failed to configure WiFi: %w", err)
	}

	// 3. Disable UPnP
	if err := wpc.disableUPnP(); err != nil {
		return fmt.Errorf("failed to disable UPnP: %w", err)
	}

	// 4. Disable WPS
	if err := wpc.disableWPS(); err != nil {
		return fmt.Errorf("failed to disable WPS: %w", err)
	}

	// 5. Configure MAC filtering
	if err := wpc.configureMACFilter(); err != nil {
		return fmt.Errorf("failed to configure MAC filter: %w", err)
	}

	// 6. Configure firewall
	if err := wpc.configureFirewall(); err != nil {
		return fmt.Errorf("failed to configure firewall: %w", err)
	}

	// 7. Configure DNS over HTTPS
	if err := wpc.configureDNS(); err != nil {
		return fmt.Errorf("failed to configure DNS: %w", err)
	}

	return nil
}

// changeAdminCredentials changes the admin username and password
func (wpc *WiFiPuckController) changeAdminCredentials() error {
	apiURL := fmt.Sprintf("http://%s/api/user/change_password", wpc.Config.AdminIP)

	data := map[string]string{
		"old_password": wpc.Config.AdminPass,
		"new_password": wpc.Config.NewPass,
		"new_username": wpc.Config.NewUser,
	}

	return wpc.postJSON(apiURL, data)
}

// configureWiFi sets up WiFi with hidden SSID and strong encryption
func (wpc *WiFiPuckController) configureWiFi() error {
	apiURL := fmt.Sprintf("http://%s/api/wifi/settings", wpc.Config.AdminIP)

	data := map[string]interface{}{
		"ssid":        wpc.Config.SSID,
		"ssid_hidden": wpc.Config.SSIDHidden,
		"password":    wpc.Config.WiFiPassword,
		"encryption":  wpc.Config.Encryption,
		"channel":     wpc.Config.Channel,
	}

	return wpc.postJSON(apiURL, data)
}

// disableUPnP turns off automatic port forwarding
func (wpc *WiFiPuckController) disableUPnP() error {
	apiURL := fmt.Sprintf("http://%s/api/upnp/disable", wpc.Config.AdminIP)
	return wpc.postJSON(apiURL, map[string]bool{"enabled": false})
}

// disableWPS turns off WiFi Protected Setup
func (wpc *WiFiPuckController) disableWPS() error {
	apiURL := fmt.Sprintf("http://%s/api/wps/disable", wpc.Config.AdminIP)
	return wpc.postJSON(apiURL, map[string]bool{"enabled": false})
}

// configureMACFilter sets up MAC address whitelist
func (wpc *WiFiPuckController) configureMACFilter() error {
	apiURL := fmt.Sprintf("http://%s/api/mac_filter/settings", wpc.Config.AdminIP)

	data := map[string]interface{}{
		"enabled":   wpc.Config.MACFilterEnabled,
		"mode":      "whitelist",
		"addresses": wpc.Config.MACWhitelist,
	}

	return wpc.postJSON(apiURL, data)
}

// configureFirewall sets up firewall rules
func (wpc *WiFiPuckController) configureFirewall() error {
	apiURL := fmt.Sprintf("http://%s/api/firewall/rules", wpc.Config.AdminIP)

	data := map[string]interface{}{
		"enabled": wpc.Config.FirewallEnabled,
		"rules":   wpc.Config.FirewallRules,
	}

	return wpc.postJSON(apiURL, data)
}

// configureDNS sets up DNS over HTTPS
func (wpc *WiFiPuckController) configureDNS() error {
	apiURL := fmt.Sprintf("http://%s/api/dns/settings", wpc.Config.AdminIP)

	data := map[string]interface{}{
		"doh_enabled": wpc.Config.DoHEnabled,
		"doh_server":  wpc.Config.DoHServer,
		"dns_servers": wpc.Config.DNSServers,
	}

	return wpc.postJSON(apiURL, data)
}

// postJSON sends a POST request with JSON body
func (wpc *WiFiPuckController) postJSON(url string, data interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	if wpc.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+wpc.authToken)
	}

	resp, err := wpc.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API error: status %d", resp.StatusCode)
	}

	return nil
}

// =============================================================================
// MAC ADDRESS MANAGEMENT
// =============================================================================

// AddMACToWhitelist adds a device MAC to the whitelist
func (wpc *WiFiPuckController) AddMACToWhitelist(mac string) {
	// Normalize MAC format
	mac = strings.ToUpper(strings.ReplaceAll(mac, "-", ":"))
	wpc.Config.MACWhitelist = append(wpc.Config.MACWhitelist, mac)
}

// RemoveMACFromWhitelist removes a device MAC from the whitelist
func (wpc *WiFiPuckController) RemoveMACFromWhitelist(mac string) {
	mac = strings.ToUpper(strings.ReplaceAll(mac, "-", ":"))
	var newList []string
	for _, m := range wpc.Config.MACWhitelist {
		if m != mac {
			newList = append(newList, m)
		}
	}
	wpc.Config.MACWhitelist = newList
}

// =============================================================================
// PHANTOM RELAY MODE
// =============================================================================

// EnablePhantomRelayMode configures the puck as a Phantom Network relay
func (wpc *WiFiPuckController) EnablePhantomRelayMode(phantomNodeIP string) error {
	// Add firewall rules for Phantom traffic
	phantomRules := []FirewallRule{
		{
			Name:      "Phantom Node Access",
			Direction: "OUTBOUND",
			Protocol:  "TCP",
			DestIP:    phantomNodeIP,
			DestPort:  "8080",
			Action:    "ALLOW",
		},
		{
			Name:      "Phantom Steganographic",
			Direction: "OUTBOUND",
			Protocol:  "TCP",
			DestPort:  "80,443",
			Action:    "ALLOW",
		},
	}

	wpc.Config.FirewallRules = append(wpc.Config.FirewallRules, phantomRules...)
	return wpc.configureFirewall()
}

// GetPuckStatus returns the current status of the WiFi puck
func (wpc *WiFiPuckController) GetPuckStatus() map[string]interface{} {
	return map[string]interface{}{
		"admin_ip":        wpc.Config.AdminIP,
		"connected":       wpc.isConnected,
		"ssid":            wpc.Config.SSID,
		"ssid_hidden":     wpc.Config.SSIDHidden,
		"encryption":      wpc.Config.Encryption,
		"mac_filter":      wpc.Config.MACFilterEnabled,
		"whitelist_count": len(wpc.Config.MACWhitelist),
		"firewall":        wpc.Config.FirewallEnabled,
		"firewall_rules":  len(wpc.Config.FirewallRules),
		"doh_enabled":     wpc.Config.DoHEnabled,
		"upnp_disabled":   wpc.Config.UPnPDisabled,
		"wps_disabled":    wpc.Config.WPSDisabled,
	}
}

// =============================================================================
// SECURITY HARDENING SCRIPT (for manual execution)
// =============================================================================

// GenerateHardeningScript generates a shell script for manual hardening
// Use this if the API approach doesn't work
func GenerateHardeningScript(config *WiFiPuckConfig) string {
	script := `#!/bin/bash
# =============================================================================
# OYEALINK SRT873 MiFi SECURITY HARDENING SCRIPT
# Generated by Phantom Network
# =============================================================================

echo "=== PHANTOM NETWORK - WiFi Puck Hardening ==="
echo ""

# Device Info
ADMIN_IP="%s"
CURRENT_USER="%s"
CURRENT_PASS="%s"
NEW_USER="%s"
NEW_PASS="%s"
NEW_SSID="%s"
WIFI_PASS="%s"

echo "[1/7] Changing admin credentials..."
curl -s -X POST "http://$ADMIN_IP/api/user/change_password" \
    -u "$CURRENT_USER:$CURRENT_PASS" \
    -d "new_username=$NEW_USER&new_password=$NEW_PASS"

echo "[2/7] Configuring WiFi (hidden SSID, WPA2-AES)..."
curl -s -X POST "http://$ADMIN_IP/api/wifi/settings" \
    -u "$NEW_USER:$NEW_PASS" \
    -d "ssid=$NEW_SSID&password=$WIFI_PASS&hidden=1&encryption=WPA2-AES"

echo "[3/7] Disabling UPnP..."
curl -s -X POST "http://$ADMIN_IP/api/upnp/disable" \
    -u "$NEW_USER:$NEW_PASS" \
    -d "enabled=false"

echo "[4/7] Disabling WPS..."
curl -s -X POST "http://$ADMIN_IP/api/wps/disable" \
    -u "$NEW_USER:$NEW_PASS" \
    -d "enabled=false"

echo "[5/7] Enabling MAC filter (whitelist mode)..."
curl -s -X POST "http://$ADMIN_IP/api/mac_filter/settings" \
    -u "$NEW_USER:$NEW_PASS" \
    -d "enabled=true&mode=whitelist"

echo "[6/7] Enabling firewall..."
curl -s -X POST "http://$ADMIN_IP/api/firewall/enable" \
    -u "$NEW_USER:$NEW_PASS" \
    -d "enabled=true"

echo "[7/7] Configuring DNS over HTTPS..."
curl -s -X POST "http://$ADMIN_IP/api/dns/settings" \
    -u "$NEW_USER:$NEW_PASS" \
    -d "doh_enabled=true&doh_server=https://cloudflare-dns.com/dns-query"

echo ""
echo "=== HARDENING COMPLETE ==="
echo ""
echo "New Credentials:"
echo "  Admin URL: http://$ADMIN_IP"
echo "  Username:  $NEW_USER"
echo "  Password:  $NEW_PASS"
echo ""
echo "WiFi Settings:"
echo "  SSID:      $NEW_SSID (hidden)"
echo "  Password:  $WIFI_PASS"
echo ""
echo "SAVE THESE CREDENTIALS SECURELY!"
`

	return fmt.Sprintf(script,
		config.AdminIP,
		config.AdminUser,
		config.AdminPass,
		config.NewUser,
		config.NewPass,
		config.SSID,
		config.WiFiPassword,
	)
}

// PrintHardeningInstructions prints manual hardening instructions
func PrintHardeningInstructions(config *WiFiPuckConfig) string {
	return fmt.Sprintf(`
================================================================================
OYEALINK SRT873 MiFi - MANUAL SECURITY HARDENING
================================================================================

If automatic configuration fails, follow these steps in the web interface:

1. OPEN ADMIN INTERFACE
   - Connect to the puck's WiFi
   - Open browser: http://%s
   - Login with: %s / %s

2. CHANGE ADMIN PASSWORD (CRITICAL!)
   - Settings → Administration → Change Password
   - New Username: %s
   - New Password: %s

3. CONFIGURE WIFI
   - Settings → WiFi → Basic
   - SSID: %s
   - Hide SSID: ON
   - Security: WPA2-AES (or WPA3 if available)
   - Password: %s

4. DISABLE UPNP
   - Settings → Network → UPnP
   - Enable: OFF

5. DISABLE WPS
   - Settings → WiFi → WPS
   - Enable: OFF

6. ENABLE MAC FILTERING
   - Settings → WiFi → MAC Filter
   - Mode: Whitelist
   - Add your devices' MAC addresses

7. ENABLE FIREWALL
   - Settings → Security → Firewall
   - Enable: ON
   - Default Policy: DROP

8. CONFIGURE DNS
   - Settings → Network → DNS
   - Enable DoH: ON
   - DoH Server: https://cloudflare-dns.com/dns-query

================================================================================
CREDENTIALS (SAVE SECURELY!)
================================================================================

Admin URL:     http://%s
Admin User:    %s
Admin Pass:    %s

WiFi SSID:     %s (hidden network)
WiFi Pass:     %s

================================================================================
`,
		config.AdminIP, config.AdminUser, config.AdminPass,
		config.NewUser, config.NewPass,
		config.SSID, config.WiFiPassword,
		config.AdminIP, config.NewUser, config.NewPass,
		config.SSID, config.WiFiPassword,
	)
}
