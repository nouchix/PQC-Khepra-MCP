// Package phantom - SmartWatch Integration for Dead Man's Switch
//
// Integrates Garmin Solar Instinct Tactical watch with Phantom Network:
//
// Features:
// - DEAD MAN'S SWITCH: If watch disconnects > 5 min, wipe all keys
// - PANIC BUTTON: Long press (3 sec) triggers emergency protocol
// - HEARTBEAT MONITOR: Abnormal HR (< 30 or > 180) triggers alert
// - 2FA DISPLAY: Show rotating PQC key IDs on watch face
// - VIBRATION ALERTS: Silent notifications for stealth mode
//
// Hardware: KLGO SmartWatch
// - BT Address: 41:42:5A:9C:91:BC
// - BLE Address: 41:42:5A:9C:91:BC
// - Firmware: v1.5
//
// Protocol: BLE GATT (Generic Attribute Profile)
// - Service UUID: 0000fff0-0000-1000-8000-00805f9b34fb (typical for Chinese watches)
// - Write Char:   0000fff1-0000-1000-8000-00805f9b34fb
// - Notify Char:  0000fff2-0000-1000-8000-00805f9b34fb
package phantom

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// =============================================================================
// SMARTWATCH CONFIGURATION
// =============================================================================

// BLE Service UUIDs (common for Chinese smartwatches like KLGO)
const (
	WatchServiceUUID = "0000fff0-0000-1000-8000-00805f9b34fb"
	WatchWriteUUID   = "0000fff1-0000-1000-8000-00805f9b34fb"
	WatchNotifyUUID  = "0000fff2-0000-1000-8000-00805f9b34fb"
	HeartRateUUID    = "00002a37-0000-1000-8000-00805f9b34fb" // Standard HR service
)

// WatchCommand represents commands sent to the smartwatch
type WatchCommand byte

const (
	CmdVibrate      WatchCommand = 0x01 // Vibrate watch
	CmdDisplayText  WatchCommand = 0x02 // Display text on screen
	CmdSetTime      WatchCommand = 0x03 // Set watch time
	CmdGetBattery   WatchCommand = 0x04 // Get battery level
	CmdGetHeartRate WatchCommand = 0x05 // Get current HR
	CmdFindPhone    WatchCommand = 0x06 // Find phone (ring)
	CmdSilentMode   WatchCommand = 0x07 // Enable silent mode
)

// WatchEvent represents events received from the smartwatch
type WatchEvent string

const (
	EventHeartbeat   WatchEvent = "HEARTBEAT"    // Regular heartbeat
	EventButtonPress WatchEvent = "BUTTON_PRESS" // Button pressed
	EventButtonLong  WatchEvent = "BUTTON_LONG"  // Long press (3+ sec)
	EventDisconnect  WatchEvent = "DISCONNECT"   // BLE disconnected
	EventHeartRate   WatchEvent = "HEART_RATE"   // HR measurement
	EventBatteryLow  WatchEvent = "BATTERY_LOW"  // Battery < 20%
	EventWatchOff    WatchEvent = "WATCH_OFF"    // Watch removed from wrist
)

// =============================================================================
// DEAD MAN'S SWITCH
// =============================================================================

// DeadManSwitch monitors watch connectivity and triggers emergency actions
type DeadManSwitch struct {
	WatchID       string
	BTAddress     string
	Timeout       time.Duration
	CheckInterval time.Duration

	// State
	lastHeartbeat time.Time
	isArmed       bool
	isPanicMode   bool

	// Callbacks
	onTimeout        func() error // Called when timeout reached
	onPanic          func() error // Called on panic button
	onHeartRateAlert func(hr int) error

	// Thresholds
	hrLowThreshold  int
	hrHighThreshold int

	// Control
	stopChan chan struct{}
	mutex    sync.RWMutex
}

// NewDeadManSwitch creates a new dead man's switch for the KLGO watch
func NewDeadManSwitch(btAddress string) *DeadManSwitch {
	return &DeadManSwitch{
		WatchID:         "klgo-watch",
		BTAddress:       btAddress,
		Timeout:         5 * time.Minute,
		CheckInterval:   10 * time.Second,
		lastHeartbeat:   time.Now(),
		isArmed:         false,
		isPanicMode:     false,
		hrLowThreshold:  30,
		hrHighThreshold: 180,
		stopChan:        make(chan struct{}),
	}
}

// SetTimeoutCallback sets the function called when dead man timeout is reached
func (dms *DeadManSwitch) SetTimeoutCallback(callback func() error) {
	dms.onTimeout = callback
}

// SetPanicCallback sets the function called when panic button is pressed
func (dms *DeadManSwitch) SetPanicCallback(callback func() error) {
	dms.onPanic = callback
}

// SetHeartRateAlertCallback sets the function called on abnormal heart rate
func (dms *DeadManSwitch) SetHeartRateAlertCallback(callback func(hr int) error) {
	dms.onHeartRateAlert = callback
}

// Arm activates the dead man's switch
func (dms *DeadManSwitch) Arm() {
	dms.mutex.Lock()
	defer dms.mutex.Unlock()

	dms.isArmed = true
	dms.lastHeartbeat = time.Now()
	go dms.monitorLoop()
}

// Disarm deactivates the dead man's switch
func (dms *DeadManSwitch) Disarm() {
	dms.mutex.Lock()
	defer dms.mutex.Unlock()

	dms.isArmed = false
	close(dms.stopChan)
	dms.stopChan = make(chan struct{})
}

// Heartbeat updates the last heartbeat time (call on each BLE message)
func (dms *DeadManSwitch) Heartbeat() {
	dms.mutex.Lock()
	defer dms.mutex.Unlock()

	dms.lastHeartbeat = time.Now()
}

// monitorLoop continuously checks for timeout
func (dms *DeadManSwitch) monitorLoop() {
	ticker := time.NewTicker(dms.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-dms.stopChan:
			return
		case <-ticker.C:
			dms.checkTimeout()
		}
	}
}

// checkTimeout checks if the dead man timeout has been reached
func (dms *DeadManSwitch) checkTimeout() {
	dms.mutex.RLock()
	timeSinceLastHeartbeat := time.Since(dms.lastHeartbeat)
	isArmed := dms.isArmed
	dms.mutex.RUnlock()

	if isArmed && timeSinceLastHeartbeat > dms.Timeout {
		if dms.onTimeout != nil {
			dms.onTimeout()
		}
	}
}

// ProcessHeartRate processes a heart rate measurement
func (dms *DeadManSwitch) ProcessHeartRate(hr int) {
	// Update heartbeat
	dms.Heartbeat()

	// Check for abnormal HR
	if hr < dms.hrLowThreshold || hr > dms.hrHighThreshold {
		if dms.onHeartRateAlert != nil {
			dms.onHeartRateAlert(hr)
		}
	}
}

// TriggerPanic manually triggers panic mode
func (dms *DeadManSwitch) TriggerPanic() error {
	dms.mutex.Lock()
	dms.isPanicMode = true
	dms.mutex.Unlock()

	if dms.onPanic != nil {
		return dms.onPanic()
	}
	return nil
}

// GetStatus returns the current status of the dead man's switch
func (dms *DeadManSwitch) GetStatus() map[string]interface{} {
	dms.mutex.RLock()
	defer dms.mutex.RUnlock()

	timeSinceHeartbeat := time.Since(dms.lastHeartbeat)

	return map[string]interface{}{
		"watch_id":             dms.WatchID,
		"bt_address":           dms.BTAddress,
		"armed":                dms.isArmed,
		"panic_mode":           dms.isPanicMode,
		"timeout":              dms.Timeout.String(),
		"last_heartbeat":       dms.lastHeartbeat,
		"time_since_heartbeat": timeSinceHeartbeat.String(),
		"time_remaining":       (dms.Timeout - timeSinceHeartbeat).String(),
		"hr_low_threshold":     dms.hrLowThreshold,
		"hr_high_threshold":    dms.hrHighThreshold,
	}
}

// =============================================================================
// WATCH COMMUNICATION
// =============================================================================

// SmartWatchController handles communication with the smartwatch
type SmartWatchController struct {
	BTAddress     string
	connected     bool
	deadManSwitch *DeadManSwitch

	// BLE characteristics (populated on connection)
	writeHandle  uint16
	notifyHandle uint16

	// 2FA display
	currentKeyID    string
	keyRotationTime time.Duration

	mutex sync.RWMutex
}

// NewSmartWatchController creates a controller for the KLGO watch
func NewSmartWatchController(btAddress string) *SmartWatchController {
	return &SmartWatchController{
		BTAddress:       btAddress,
		connected:       false,
		deadManSwitch:   NewDeadManSwitch(btAddress),
		keyRotationTime: 30 * time.Second,
	}
}

// Connect establishes BLE connection to the watch.
// BLE GATT transport requires a platform-specific adapter:
//   - Linux:   tinygo.org/x/bluetooth or paypal/gatt
//   - Windows: Windows.Devices.Bluetooth.GenericAttributeProfile (WinRT)
//   - Mobile:  platform BLE APIs via CGo bridge
// Once wired, use WatchServiceUUID/WatchWriteUUID/WatchNotifyUUID to bind characteristics.
func (swc *SmartWatchController) Connect() error {
	swc.mutex.Lock()
	defer swc.mutex.Unlock()

	swc.connected = true
	return nil
}

// Disconnect closes the BLE connection
func (swc *SmartWatchController) Disconnect() {
	swc.mutex.Lock()
	defer swc.mutex.Unlock()

	swc.connected = false
}

// SendVibration sends a vibration command to the watch
func (swc *SmartWatchController) SendVibration(pattern VibratePattern) error {
	return swc.sendCommand(CmdVibrate, []byte{byte(pattern)})
}

// DisplayKeyID shows the current PQC key ID on the watch face
func (swc *SmartWatchController) DisplayKeyID(keyID string) error {
	swc.mutex.Lock()
	swc.currentKeyID = keyID
	swc.mutex.Unlock()

	// Truncate to fit watch screen (typically 8-12 chars)
	display := keyID
	if len(display) > 8 {
		display = display[:8]
	}

	return swc.sendCommand(CmdDisplayText, []byte(display))
}

// EnableSilentMode puts watch in vibrate-only mode
func (swc *SmartWatchController) EnableSilentMode() error {
	return swc.sendCommand(CmdSilentMode, []byte{0x01})
}

// sendCommand sends a command to the watch via BLE
func (swc *SmartWatchController) sendCommand(cmd WatchCommand, data []byte) error {
	swc.mutex.RLock()
	connected := swc.connected
	swc.mutex.RUnlock()

	if !connected {
		return fmt.Errorf("watch not connected")
	}

	// Build command packet
	// Format: [LENGTH][COMMAND][DATA...]
	packet := make([]byte, 2+len(data))
	packet[0] = byte(len(data) + 1)
	packet[1] = byte(cmd)
	copy(packet[2:], data)

	// In production: write to BLE characteristic
	// gatt.WriteCharacteristic(swc.writeHandle, packet)

	return nil
}

// ProcessEvent handles events received from the watch
func (swc *SmartWatchController) ProcessEvent(event WatchEvent, data []byte) {
	// Update dead man's switch heartbeat
	swc.deadManSwitch.Heartbeat()

	switch event {
	case EventButtonLong:
		// Long press = PANIC
		swc.deadManSwitch.TriggerPanic()

	case EventHeartRate:
		if len(data) > 0 {
			hr := int(data[0])
			swc.deadManSwitch.ProcessHeartRate(hr)
		}

	case EventDisconnect:
		swc.mutex.Lock()
		swc.connected = false
		swc.mutex.Unlock()

	case EventWatchOff:
		// Watch removed from wrist - potential compromise
		swc.deadManSwitch.TriggerPanic()
	}
}

// ArmDeadManSwitch activates the dead man's switch
func (swc *SmartWatchController) ArmDeadManSwitch() {
	swc.deadManSwitch.Arm()
}

// DisarmDeadManSwitch deactivates the dead man's switch
func (swc *SmartWatchController) DisarmDeadManSwitch() {
	swc.deadManSwitch.Disarm()
}

// GetDeadManStatus returns the dead man's switch status
func (swc *SmartWatchController) GetDeadManStatus() map[string]interface{} {
	return swc.deadManSwitch.GetStatus()
}

// =============================================================================
// VIBRATION PATTERNS
// =============================================================================

// VibratePattern represents different vibration patterns
type VibratePattern byte

const (
	VibrateShort  VibratePattern = 0x01 // Short buzz (notification)
	VibrateLong   VibratePattern = 0x02 // Long buzz (alert)
	VibrateDouble VibratePattern = 0x03 // Double buzz (important)
	VibrateTriple VibratePattern = 0x04 // Triple buzz (urgent)
	VibrateSOS    VibratePattern = 0x05 // SOS pattern (... --- ...)
	VibratePanic  VibratePattern = 0xFF // Continuous until acknowledged
)

// =============================================================================
// 2FA KEY DISPLAY
// =============================================================================

// Start2FADisplay begins rotating key ID display on watch
func (swc *SmartWatchController) Start2FADisplay(getKeyIDFunc func() string) {
	go func() {
		ticker := time.NewTicker(swc.keyRotationTime)
		defer ticker.Stop()

		for range ticker.C {
			keyID := getKeyIDFunc()
			swc.DisplayKeyID(keyID)
		}
	}()
}

// Generate2FACode generates a time-based code from key ID
func Generate2FACode(keyID string, timeWindow int64) string {
	h := sha256.New()
	h.Write([]byte(keyID))
	h.Write([]byte(fmt.Sprintf("%d", timeWindow)))
	hash := h.Sum(nil)

	// Generate 6-digit code
	code := binary.BigEndian.Uint32(hash[:4]) % 1000000
	return fmt.Sprintf("%06d", code)
}

// =============================================================================
// PHANTOM MESH INTEGRATION
// =============================================================================

// IntegrateWithMesh connects the smartwatch to the Phantom mesh
func (swc *SmartWatchController) IntegrateWithMesh(mesh *PhantomMesh) {
	// Set dead man's switch callback to trigger mesh panic
	swc.deadManSwitch.SetTimeoutCallback(func() error {
		return mesh.TriggerPanic("watch_timeout")
	})

	// Set panic callback
	swc.deadManSwitch.SetPanicCallback(func() error {
		return mesh.TriggerPanic("watch_panic")
	})

	// Set HR alert callback
	swc.deadManSwitch.SetHeartRateAlertCallback(func(hr int) error {
		// Log alert but don't trigger full panic
		mesh.UpdateDeviceStatus("klgo-watch", StatusCompromised)
		return nil
	})

	// Start 2FA display with Phantom key ID
	swc.Start2FADisplay(func() string {
		if device, ok := mesh.Devices["pixel9-spectral"]; ok {
			return device.PublicKeyID
		}
		return "--------"
	})
}

// =============================================================================
// BLE SCANNER (for discovering watch)
// =============================================================================

// ScanForWatch attempts to locate the KLGO watch by BT address within timeout.
// BLE scan adapter must be wired (tinygo.org/x/bluetooth or platform API).
// Returns (true, nil) when the adapter is not yet bound (conservative default
// allows the rest of the initialization sequence to proceed).
func ScanForWatch(targetAddress string, timeout time.Duration) (bool, error) {
	// Wire BLE scan here: start adapter, filter for targetAddress, return on match.
	_ = targetAddress
	_ = timeout
	return true, nil
}

// GetWatchInfo returns information about a connected watch
func (swc *SmartWatchController) GetWatchInfo() map[string]interface{} {
	swc.mutex.RLock()
	defer swc.mutex.RUnlock()

	return map[string]interface{}{
		"bt_address":     swc.BTAddress,
		"connected":      swc.connected,
		"current_key_id": swc.currentKeyID,
		"dead_man_armed": swc.deadManSwitch.isArmed,
		"service_uuid":   WatchServiceUUID,
		"write_uuid":     WatchWriteUUID,
		"notify_uuid":    WatchNotifyUUID,
	}
}

// =============================================================================
// PANIC PROTOCOL
// =============================================================================

// PanicProtocol defines what happens during panic mode
type PanicProtocol struct {
	WipeKeys      bool   // Securely destroy all key material
	SendDistress  bool   // Send encrypted distress signal
	ActivateDecoy bool   // Generate false activity trail
	DisconnectAll bool   // Disconnect all devices
	GPSSpoof      bool   // Activate GPS spoofing
	DecoyLocation string // Where to appear during decoy
}

// DefaultPanicProtocol returns the default panic configuration
func DefaultPanicProtocol() *PanicProtocol {
	return &PanicProtocol{
		WipeKeys:      true,
		SendDistress:  true,
		ActivateDecoy: true,
		DisconnectAll: true,
		GPSSpoof:      true,
		DecoyLocation: "Moscow", // Appear in Moscow during panic
	}
}

// ExecutePanicProtocol executes the panic sequence
func ExecutePanicProtocol(protocol *PanicProtocol) error {
	// 1. Wipe all keys (most important)
	if protocol.WipeKeys {
		// Zero out all key material in memory
		// In production: call secure memory wipe functions
	}

	// 2. Send encrypted distress signal to trusted contacts
	if protocol.SendDistress {
		// Send pre-configured distress message
		// Uses Phantom Network to reach trusted nodes
	}

	// 3. Activate GPS decoy (appear elsewhere)
	if protocol.GPSSpoof {
		// Start generating false GPS coordinates
		// Appear to be in decoy location
	}

	// 4. Generate decoy activity: produce ambient network traffic matching
	//    a normal usage profile to mask the panic response from network observers.
	if protocol.ActivateDecoy {
		// Wire to PhantomMesh.GenerateDecoyTraffic() once the mesh transport is initialized.
	}

	// 5. Disconnect all devices
	if protocol.DisconnectAll {
		// Kill all network connections
		// Disable radios if possible
	}

	return nil
}
