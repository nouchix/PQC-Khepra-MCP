// Package phantom - Device Configuration for Phantom Network Mesh
//
// Integrates multiple devices into a cohesive counter-surveillance network:
// - Pixel 9 (Primary Mobile) - VPN routing, GPS spoofing, IMSI rotation
// - KLGO SmartWatch - Dead man's switch, 2FA display, panic button
// - OYEALINK WiFi Puck - Air-gapped relay, mobile mesh node
//
// All devices authenticate via Adinkhepra-PQC signatures
package phantom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// =============================================================================
// DEVICE TYPES
// =============================================================================

// DeviceType represents the category of device in the mesh
type DeviceType string

const (
	DeviceMobile    DeviceType = "MOBILE"    // Smartphone (Pixel 9)
	DeviceWearable  DeviceType = "WEARABLE"  // SmartWatch (KLGO)
	DeviceHotspot   DeviceType = "HOTSPOT"   // WiFi Puck (OYEALINK)
	DeviceCompute   DeviceType = "COMPUTE"   // WSL/Server
	DeviceRelay     DeviceType = "RELAY"     // Mesh relay node
)

// DeviceStatus represents the current state of a device
type DeviceStatus string

const (
	StatusOnline      DeviceStatus = "ONLINE"
	StatusOffline     DeviceStatus = "OFFLINE"
	StatusPanic       DeviceStatus = "PANIC"       // Emergency mode activated
	StatusCompromised DeviceStatus = "COMPROMISED" // Possible breach detected
	StatusStealth     DeviceStatus = "STEALTH"     // Full stealth active
)

// =============================================================================
// DEVICE CONFIGURATION
// =============================================================================

// PhantomDevice represents a device in the Phantom mesh network
type PhantomDevice struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Type            DeviceType        `json:"type"`
	Symbol          string            `json:"symbol"`           // Adinkra symbol
	Status          DeviceStatus      `json:"status"`

	// Network identifiers
	MACAddress      string            `json:"mac_address,omitempty"`
	BTAddress       string            `json:"bt_address,omitempty"`
	TailscaleIP     string            `json:"tailscale_ip,omitempty"`
	LocalIP         string            `json:"local_ip,omitempty"`

	// Security
	PublicKeyID     string            `json:"public_key_id"`
	TrustScore      int               `json:"trust_score"`      // 0-100
	LastSeen        time.Time         `json:"last_seen"`
	HeartbeatInterval time.Duration   `json:"heartbeat_interval"`

	// Capabilities
	Capabilities    []string          `json:"capabilities"`
	StealthFeatures map[string]bool   `json:"stealth_features"`

	// Device-specific config
	Config          map[string]interface{} `json:"config"`
}

// PhantomMesh represents the complete device mesh configuration
type PhantomMesh struct {
	MeshID          string                    `json:"mesh_id"`
	MasterSymbol    string                    `json:"master_symbol"`
	CreatedAt       time.Time                 `json:"created_at"`
	Devices         map[string]*PhantomDevice `json:"devices"`

	// Security policies
	DeadManTimeout  time.Duration             `json:"dead_man_timeout"`
	PanicAction     string                    `json:"panic_action"`
	AutoDestruct    bool                      `json:"auto_destruct"`

	// Stealth configuration
	StealthMode     bool                      `json:"stealth_mode"`
	GPSSpoofTarget  string                    `json:"gps_spoof_target"`
	IMSIRotation    bool                      `json:"imsi_rotation"`
	VPNMode         bool                      `json:"vpn_mode"`

	mutex           sync.RWMutex
}

// =============================================================================
// DEVICE CONFIGURATIONS FOR YOUR DEVICES
// =============================================================================

// NewPixel9Config creates configuration for Google Pixel 9
func NewPixel9Config() *PhantomDevice {
	return &PhantomDevice{
		ID:              "pixel9-spectral",
		Name:            "Pixel 9 Pro",
		Type:            DeviceMobile,
		Symbol:          "Eban", // Security symbol
		Status:          StatusOnline,
		TailscaleIP:     "100.72.58.3", // Your Tailscale IP
		HeartbeatInterval: 30 * time.Second,
		TrustScore:      100, // Primary device
		Capabilities: []string{
			"gps_spoof",
			"imsi_rotation",
			"vpn_routing",
			"stealth_mode",
			"panic_button",
			"biometric_auth",
		},
		StealthFeatures: map[string]bool{
			"gps_spoof":       true,
			"imsi_rotation":   true,
			"face_defeat":     true,
			"thermal_mask":    false, // Phone can't do thermal
			"em_spread":       true,
		},
		Config: map[string]interface{}{
			"carrier":           "T-Mobile",
			"real_ip":           "172.59.176.209",
			"real_ipv6":         "2607:fb90:df8c:d620:ad2:f757:5058:c659",
			"location_exposed":  "Syracuse, NY",
			"spoof_location":    "Berlin, Germany", // Appear in Berlin
			"imsi_rotation_sec": 300,               // 5 minute rotation
			"vpn_endpoint":      "100.72.58.3:8080", // Phantom Node
		},
	}
}

// NewKLGOWatchConfig creates configuration for KLGO SmartWatch
func NewKLGOWatchConfig() *PhantomDevice {
	return &PhantomDevice{
		ID:              "klgo-watch",
		Name:            "KLGO SmartWatch",
		Type:            DeviceWearable,
		Symbol:          "Fawohodie", // Freedom symbol
		Status:          StatusOffline,
		BTAddress:       "41:42:5A:9C:91:BC",
		HeartbeatInterval: 10 * time.Second, // Fast heartbeat for dead man's switch
		TrustScore:      90,
		Capabilities: []string{
			"dead_man_switch",
			"panic_button",
			"2fa_display",
			"heartbeat_monitor",
			"bluetooth_relay",
		},
		StealthFeatures: map[string]bool{
			"silent_mode":     true,
			"vibrate_only":    true,
			"screen_off":      true,
		},
		Config: map[string]interface{}{
			"firmware_version":    "v1.5",
			"dead_man_timeout":    300,    // 5 minutes without heartbeat = wipe
			"panic_hold_duration": 3,      // 3 second hold = panic
			"hr_threshold_low":    30,     // Below 30 BPM = possible distress
			"hr_threshold_high":   180,    // Above 180 BPM = possible distress
			"auto_disconnect_min": 5,      // Auto-disconnect if away > 5 min
		},
	}
}

// NewOyealinkHotspotConfig creates configuration for OYEALINK WiFi Puck
func NewOyealinkHotspotConfig() *PhantomDevice {
	return &PhantomDevice{
		ID:              "oyealink-puck",
		Name:            "OYEALINK SRT873 MiFi",
		Type:            DeviceHotspot,
		Symbol:          "Nkyinkyim", // Adaptability symbol
		Status:          StatusOffline,
		LocalIP:         "192.168.8.1",
		HeartbeatInterval: 60 * time.Second,
		TrustScore:      80,
		Capabilities: []string{
			"wifi_relay",
			"mobile_mesh",
			"air_gap_bridge",
			"traffic_routing",
			"4g_lte_backup",
		},
		StealthFeatures: map[string]bool{
			"hidden_ssid":     true,
			"mac_randomize":   true,
			"traffic_obfuscate": true,
		},
		Config: map[string]interface{}{
			"model":             "SRT873",
			"default_user":      "admin",
			"default_pass":      "admin", // MUST CHANGE!
			"new_user":          "phantom",
			"subnet":            "192.168.8.0/24",
			"dns_over_https":    true,
			"firewall_enabled":  true,
			"upnp_disabled":     true,
			"wps_disabled":      true,
		},
	}
}

// =============================================================================
// MESH INITIALIZATION
// =============================================================================

// NewPhantomMesh creates a new device mesh with all your devices
func NewPhantomMesh(masterSymbol string) *PhantomMesh {
	meshID := generateMeshID(masterSymbol)

	mesh := &PhantomMesh{
		MeshID:         meshID,
		MasterSymbol:   masterSymbol,
		CreatedAt:      time.Now(),
		Devices:        make(map[string]*PhantomDevice),
		DeadManTimeout: 5 * time.Minute,
		PanicAction:    "wipe_keys",
		AutoDestruct:   true,
		StealthMode:    false,
		GPSSpoofTarget: "Berlin",
		IMSIRotation:   true,
		VPNMode:        true,
	}

	// Add your devices
	pixel9 := NewPixel9Config()
	watch := NewKLGOWatchConfig()
	hotspot := NewOyealinkHotspotConfig()

	mesh.Devices[pixel9.ID] = pixel9
	mesh.Devices[watch.ID] = watch
	mesh.Devices[hotspot.ID] = hotspot

	return mesh
}

func generateMeshID(symbol string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", symbol, time.Now().UnixNano())))
	return hex.EncodeToString(h[:8])
}

// =============================================================================
// MESH OPERATIONS
// =============================================================================

// ActivateFullStealth enables all stealth features across the mesh
func (m *PhantomMesh) ActivateFullStealth(targetCity string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.StealthMode = true
	m.GPSSpoofTarget = targetCity
	m.IMSIRotation = true
	m.VPNMode = true

	// Update all devices
	for _, device := range m.Devices {
		device.Status = StatusStealth
		for feature := range device.StealthFeatures {
			device.StealthFeatures[feature] = true
		}
	}

	return nil
}

// TriggerPanic activates emergency protocols
func (m *PhantomMesh) TriggerPanic(source string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for _, device := range m.Devices {
		device.Status = StatusPanic
	}

	// Execute panic action
	switch m.PanicAction {
	case "wipe_keys":
		return m.wipeAllKeys()
	case "disconnect":
		return m.disconnectAll()
	case "decoy":
		return m.activateDecoy()
	}

	return nil
}

func (m *PhantomMesh) wipeAllKeys() error {
	// Securely destroy all cryptographic material
	// This would zero out all key material in memory
	return nil
}

func (m *PhantomMesh) disconnectAll() error {
	// Disconnect all devices from network
	for _, device := range m.Devices {
		device.Status = StatusOffline
	}
	return nil
}

func (m *PhantomMesh) activateDecoy() error {
	// Generate false trail of activity
	return nil
}

// UpdateDeviceStatus updates a device's status based on heartbeat
func (m *PhantomMesh) UpdateDeviceStatus(deviceID string, status DeviceStatus) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if device, ok := m.Devices[deviceID]; ok {
		device.Status = status
		device.LastSeen = time.Now()
	}
}

// CheckDeadManSwitch checks if any device has missed heartbeats
func (m *PhantomMesh) CheckDeadManSwitch() []string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var missedDevices []string

	for id, device := range m.Devices {
		if device.Type == DeviceWearable {
			timeSinceLastSeen := time.Since(device.LastSeen)
			if timeSinceLastSeen > m.DeadManTimeout {
				missedDevices = append(missedDevices, id)
			}
		}
	}

	return missedDevices
}

// =============================================================================
// CONFIGURATION PERSISTENCE
// =============================================================================

// SaveConfig saves mesh configuration to file
func (m *PhantomMesh) SaveConfig(filepath string) error {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath, data, 0600)
}

// LoadConfig loads mesh configuration from file
func LoadConfig(filepath string) (*PhantomMesh, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var mesh PhantomMesh
	if err := json.Unmarshal(data, &mesh); err != nil {
		return nil, err
	}

	return &mesh, nil
}

// GetMeshStatus returns the current status of all devices
func (m *PhantomMesh) GetMeshStatus() map[string]interface{} {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	deviceStatuses := make(map[string]interface{})
	for id, device := range m.Devices {
		deviceStatuses[id] = map[string]interface{}{
			"name":       device.Name,
			"type":       device.Type,
			"status":     device.Status,
			"last_seen":  device.LastSeen,
			"trust":      device.TrustScore,
			"stealth":    device.StealthFeatures,
		}
	}

	return map[string]interface{}{
		"mesh_id":       m.MeshID,
		"master_symbol": m.MasterSymbol,
		"stealth_mode":  m.StealthMode,
		"vpn_mode":      m.VPNMode,
		"gps_spoof":     m.GPSSpoofTarget,
		"imsi_rotation": m.IMSIRotation,
		"devices":       deviceStatuses,
	}
}
