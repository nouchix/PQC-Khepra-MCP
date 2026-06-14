package fingerprint

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/audit"
)

// CollectDeviceFingerprint generates a comprehensive hardware fingerprint
// for license enforcement and anti-spoofing protection.
// NUCLEAR-GRADE: Collects immutable hardware identifiers that cannot be easily spoofed.
func CollectDeviceFingerprint() (audit.DeviceFingerprint, error) {
	fp := audit.DeviceFingerprint{
		TPMPresent: false,
	}

	// Collect MAC addresses from all physical network interfaces
	macs, err := collectMACAddresses()
	if err != nil {
		return fp, fmt.Errorf("failed to collect MAC addresses: %v", err)
	}
	fp.MACAddresses = macs

	// Collect CPU signature (CPUID + model info)
	cpuSig, err := collectCPUSignature()
	if err != nil {
		// Non-fatal, continue with empty value
		fmt.Printf("[WARN] Failed to collect CPU signature: %v\n", err)
	}
	fp.CPUSignature = cpuSig

	// Collect disk serial numbers
	diskSerials, err := collectDiskSerials()
	if err != nil {
		fmt.Printf("[WARN] Failed to collect disk serials: %v\n", err)
	}
	fp.DiskSerials = diskSerials

	// Collect BIOS/SMBIOS UUID (Windows/Linux)
	biosSerial, err := collectBIOSSerial()
	if err != nil {
		fmt.Printf("[WARN] Failed to collect BIOS serial: %v\n", err)
	}
	fp.BIOSSerial = biosSerial

	// Collect motherboard ID
	mbID, err := collectMotherboardID()
	if err != nil {
		fmt.Printf("[WARN] Failed to collect motherboard ID: %v\n", err)
	}
	fp.MotherboardID = mbID

	// Check for TPM and collect TPM fingerprint
	tpmPresent, tpmVersion, tpmFP := collectTPMInfo()
	fp.TPMPresent = tpmPresent
	fp.TPMVersion = tpmVersion
	fp.TPMFingerprint = tpmFP

	// Generate composite hash from all identifiers
	fp.CompositeHash = generateCompositeHash(fp)

	// Detect anti-spoofing indicators
	fp.SpoofingIndicators = detectSpoofingIndicators(fp)

	return fp, nil
}

// collectMACAddresses retrieves MAC addresses from all physical network interfaces
func collectMACAddresses() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var macs []string
	for _, iface := range interfaces {
		// Skip loopback and virtual interfaces
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// Only collect from interfaces with valid hardware addresses
		if len(iface.HardwareAddr) > 0 {
			mac := iface.HardwareAddr.String()
			// Skip all-zeros MAC (virtual interfaces)
			if mac != "" && mac != "00:00:00:00:00:00" {
				macs = append(macs, mac)
			}
		}
	}

	// Sort for deterministic ordering
	sort.Strings(macs)
	return macs, nil
}

// collectCPUSignature collects CPU identification information
func collectCPUSignature() (string, error) {
	switch runtime.GOOS {
	case "linux":
		return collectCPUSignatureLinux()
	case "windows":
		return collectCPUSignatureWindows()
	case "darwin":
		return collectCPUSignatureDarwin()
	default:
		return "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func collectCPUSignatureLinux() (string, error) {
	// Read /proc/cpuinfo for CPU model and features
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(data), "\n")
	var modelName, vendorID, stepping, microcode string

	for _, line := range lines {
		if strings.HasPrefix(line, "model name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				modelName = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "vendor_id") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				vendorID = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "stepping") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				stepping = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "microcode") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				microcode = strings.TrimSpace(parts[1])
			}
		}
	}

	return fmt.Sprintf("%s|%s|%s|%s", vendorID, modelName, stepping, microcode), nil
}

func collectCPUSignatureWindows() (string, error) {
	// Use WMIC to get CPU information
	cmd := exec.Command("wmic", "cpu", "get", "ProcessorId,Name,Manufacturer", "/format:list")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	var manufacturer, name, processorID string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Manufacturer=") {
			manufacturer = strings.TrimPrefix(line, "Manufacturer=")
		} else if strings.HasPrefix(line, "Name=") {
			name = strings.TrimPrefix(line, "Name=")
		} else if strings.HasPrefix(line, "ProcessorId=") {
			processorID = strings.TrimPrefix(line, "ProcessorId=")
		}
	}

	return fmt.Sprintf("%s|%s|%s", manufacturer, name, processorID), nil
}

func collectCPUSignatureDarwin() (string, error) {
	// Use sysctl to get CPU information on macOS
	cmd := exec.Command("sysctl", "-n", "machdep.cpu.brand_string")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(output)), nil
}

// collectDiskSerials collects physical disk serial numbers
func collectDiskSerials() ([]string, error) {
	switch runtime.GOOS {
	case "linux":
		return collectDiskSerialsLinux()
	case "windows":
		return collectDiskSerialsWindows()
	case "darwin":
		return collectDiskSerialsDarwin()
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func collectDiskSerialsLinux() ([]string, error) {
	var serials []string

	// Use lsblk to get disk serial numbers
	cmd := exec.Command("lsblk", "-ndo", "SERIAL", "-e", "7,11") // Exclude loop and optical devices
	output, err := cmd.Output()
	if err != nil {
		// Fallback: try reading from /sys/block/*/device/serial
		return collectDiskSerialsLinuxFallback()
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		serial := strings.TrimSpace(line)
		if serial != "" && serial != "0" {
			serials = append(serials, serial)
		}
	}

	sort.Strings(serials)
	return serials, nil
}

func collectDiskSerialsLinuxFallback() ([]string, error) {
	var serials []string

	// Read from /sys/block/*/device/serial
	devices, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil, err
	}

	for _, dev := range devices {
		if strings.HasPrefix(dev.Name(), "loop") || strings.HasPrefix(dev.Name(), "sr") {
			continue
		}

		serialPath := fmt.Sprintf("/sys/block/%s/device/serial", dev.Name())
		data, err := os.ReadFile(serialPath)
		if err == nil {
			serial := strings.TrimSpace(string(data))
			if serial != "" {
				serials = append(serials, serial)
			}
		}
	}

	sort.Strings(serials)
	return serials, nil
}

func collectDiskSerialsWindows() ([]string, error) {
	var serials []string

	// Use WMIC to get disk serial numbers
	cmd := exec.Command("wmic", "diskdrive", "get", "SerialNumber", "/format:list")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "SerialNumber=") {
			serial := strings.TrimPrefix(line, "SerialNumber=")
			serial = strings.TrimSpace(serial)
			if serial != "" {
				serials = append(serials, serial)
			}
		}
	}

	sort.Strings(serials)
	return serials, nil
}

func collectDiskSerialsDarwin() ([]string, error) {
	var serials []string

	// Use diskutil to get disk serial numbers
	cmd := exec.Command("diskutil", "list")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Parse output
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "/dev/disk") && !strings.Contains(line, "disk image") {
			// Extract disk identifier
			fields := strings.Fields(line)
			if len(fields) > 0 {
				diskID := fields[0]
				// Get info for this disk
				infoCmd := exec.Command("diskutil", "info", diskID)
				infoOutput, err := infoCmd.Output()
				if err == nil {
					// Extract serial from info output
					infoLines := strings.Split(string(infoOutput), "\n")
					for _, infoLine := range infoLines {
						if strings.Contains(infoLine, "Disk / Partition UUID:") || strings.Contains(infoLine, "Volume UUID:") {
							parts := strings.SplitN(infoLine, ":", 2)
							if len(parts) == 2 {
								serial := strings.TrimSpace(parts[1])
								if serial != "" {
									serials = append(serials, serial)
									break
								}
							}
						}
					}
				}
			}
		}
	}

	sort.Strings(serials)
	return serials, nil
}

// collectBIOSSerial collects SMBIOS/BIOS UUID
func collectBIOSSerial() (string, error) {
	switch runtime.GOOS {
	case "linux":
		return collectBIOSSerialLinux()
	case "windows":
		return collectBIOSSerialWindows()
	case "darwin":
		return collectBIOSSerialDarwin()
	default:
		return "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func collectBIOSSerialLinux() (string, error) {
	// Try dmidecode first (requires root)
	cmd := exec.Command("dmidecode", "-s", "system-uuid")
	output, err := cmd.Output()
	if err == nil {
		uuid := strings.TrimSpace(string(output))
		if uuid != "" && uuid != "Not Settable" {
			return uuid, nil
		}
	}

	// Fallback: Read from /sys/class/dmi/id/product_uuid
	data, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(data)), nil
}

func collectBIOSSerialWindows() (string, error) {
	// Use WMIC to get BIOS serial number
	cmd := exec.Command("wmic", "bios", "get", "SerialNumber", "/format:list")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "SerialNumber=") {
			return strings.TrimPrefix(line, "SerialNumber="), nil
		}
	}

	return "", fmt.Errorf("BIOS serial not found")
}

func collectBIOSSerialDarwin() (string, error) {
	// Use ioreg to get hardware UUID on macOS
	cmd := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "IOPlatformUUID") {
			// Extract UUID from line like: "IOPlatformUUID" = "12345678-1234-1234-1234-123456789012"
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				uuid := strings.Trim(strings.TrimSpace(parts[1]), "\"")
				return uuid, nil
			}
		}
	}

	return "", fmt.Errorf("IOPlatformUUID not found")
}

// collectMotherboardID collects motherboard/baseboard serial number
func collectMotherboardID() (string, error) {
	switch runtime.GOOS {
	case "linux":
		return collectMotherboardIDLinux()
	case "windows":
		return collectMotherboardIDWindows()
	default:
		return "", nil // Not critical, return empty
	}
}

func collectMotherboardIDLinux() (string, error) {
	// Try dmidecode first (requires root)
	cmd := exec.Command("dmidecode", "-s", "baseboard-serial-number")
	output, err := cmd.Output()
	if err == nil {
		serial := strings.TrimSpace(string(output))
		if serial != "" && serial != "Not Specified" {
			return serial, nil
		}
	}

	// Fallback: Read from /sys/class/dmi/id/board_serial
	data, err := os.ReadFile("/sys/class/dmi/id/board_serial")
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(data)), nil
}

func collectMotherboardIDWindows() (string, error) {
	// Use WMIC to get baseboard serial number
	cmd := exec.Command("wmic", "baseboard", "get", "SerialNumber", "/format:list")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "SerialNumber=") {
			return strings.TrimPrefix(line, "SerialNumber="), nil
		}
	}

	return "", fmt.Errorf("motherboard serial not found")
}

// collectTPMInfo checks for TPM and collects TPM fingerprint
func collectTPMInfo() (bool, string, string) {
	switch runtime.GOOS {
	case "linux":
		return collectTPMInfoLinux()
	case "windows":
		return collectTPMInfoWindows()
	default:
		return false, "", ""
	}
}

func collectTPMInfoLinux() (bool, string, string) {
	// Check if TPM device exists
	if _, err := os.Stat("/dev/tpm0"); err == nil {
		// TPM 2.0 is present
		// Try to get TPM version
		cmd := exec.Command("tpm2_getcap", "properties-fixed")
		_, err := cmd.Output()
		if err == nil {
			// TPM 2.0 detected
			// Generate TPM fingerprint from EK (Endorsement Key) if available
			ekCmd := exec.Command("tpm2_readpublic", "-c", "0x81010001")
			ekOutput, err := ekCmd.Output()
			if err == nil {
				// Hash the EK output for fingerprint
				hash := sha512.Sum512(ekOutput)
				fingerprint := hex.EncodeToString(hash[:])[:32]
				return true, "2.0", fingerprint
			}
			return true, "2.0", ""
		}

		// Check for TPM 1.2
		if _, err := os.Stat("/sys/class/tpm/tpm0"); err == nil {
			return true, "1.2", ""
		}

		return true, "unknown", ""
	}

	return false, "", ""
}

func collectTPMInfoWindows() (bool, string, string) {
	// Use PowerShell to check TPM status
	cmd := exec.Command("powershell", "-Command", "Get-Tpm | Select-Object -ExpandProperty TpmPresent")
	output, err := cmd.Output()
	if err != nil {
		return false, "", ""
	}

	present := strings.TrimSpace(string(output))
	if strings.ToLower(present) == "true" {
		// Get TPM version
		versionCmd := exec.Command("powershell", "-Command", "Get-Tpm | Select-Object -ExpandProperty ManufacturerVersion")
		versionOutput, err := versionCmd.Output()
		version := "2.0" // Default to 2.0 for modern Windows systems
		if err == nil {
			version = strings.TrimSpace(string(versionOutput))
		}

		// Get TPM EK certificate hash for fingerprint
		ekCmd := exec.Command("powershell", "-Command", "(Get-TpmEndorsementKeyInfo).EndorsementKey")
		ekOutput, err := ekCmd.Output()
		if err == nil && len(ekOutput) > 0 {
			hash := sha512.Sum512(ekOutput)
			fingerprint := hex.EncodeToString(hash[:])[:32]
			return true, version, fingerprint
		}

		return true, version, ""
	}

	return false, "", ""
}

// generateCompositeHash creates a SHA3-512 hash of all hardware identifiers
// This hash is used for license node binding and cannot be spoofed
func generateCompositeHash(fp audit.DeviceFingerprint) string {
	// Combine all identifiers in a deterministic way
	var components []string

	// Add all MACs (already sorted)
	components = append(components, fp.MACAddresses...)

	// Add CPU signature
	if fp.CPUSignature != "" {
		components = append(components, fp.CPUSignature)
	}

	// Add disk serials (already sorted)
	components = append(components, fp.DiskSerials...)

	// Add BIOS serial
	if fp.BIOSSerial != "" {
		components = append(components, fp.BIOSSerial)
	}

	// Add motherboard ID
	if fp.MotherboardID != "" {
		components = append(components, fp.MotherboardID)
	}

	// Add TPM fingerprint if available
	if fp.TPMFingerprint != "" {
		components = append(components, fp.TPMFingerprint)
	}

	// Join all components
	composite := strings.Join(components, "|")

	// Use Adinkra Hash (PQC-ready SHA3-based hash)
	return adinkra.Hash([]byte(composite))
}

// detectSpoofingIndicators analyzes the fingerprint for signs of spoofing
func detectSpoofingIndicators(fp audit.DeviceFingerprint) []string {
	var indicators []string

	// Check for virtual MAC addresses (common spoofing technique)
	for _, mac := range fp.MACAddresses {
		// Check for common virtualization vendor prefixes
		virtualPrefixes := []string{
			"00:05:69", // VMware
			"00:0c:29", // VMware
			"00:1c:14", // VMware
			"00:50:56", // VMware
			"00:15:5d", // Hyper-V
			"00:1c:42", // Parallels
			"08:00:27", // VirtualBox
		}

		for _, prefix := range virtualPrefixes {
			if strings.HasPrefix(strings.ToLower(mac), prefix) {
				indicators = append(indicators, fmt.Sprintf("virtual_mac_detected:%s", mac))
			}
		}

		// Check for locally administered MACs (2nd bit of first octet is 1)
		parts := strings.Split(mac, ":")
		if len(parts) > 0 {
			firstOctet := parts[0]
			if len(firstOctet) == 2 {
				// Convert first character from hex
				if val, err := hex.DecodeString(string(firstOctet[1])); err == nil {
					if val[0]&0x02 != 0 {
						indicators = append(indicators, fmt.Sprintf("locally_administered_mac:%s", mac))
					}
				}
			}
		}
	}

	// Check for missing critical identifiers
	if len(fp.MACAddresses) == 0 {
		indicators = append(indicators, "no_mac_addresses")
	}

	if fp.CPUSignature == "" {
		indicators = append(indicators, "no_cpu_signature")
	}

	if len(fp.DiskSerials) == 0 {
		indicators = append(indicators, "no_disk_serials")
	}

	if fp.BIOSSerial == "" {
		indicators = append(indicators, "no_bios_serial")
	}

	// Check for TPM absence on modern systems (suspicious for DoD environments)
	if !fp.TPMPresent {
		indicators = append(indicators, "tpm_absent")
	}

	return indicators
}
