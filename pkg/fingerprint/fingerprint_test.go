package fingerprint

import (
    "testing"

    "github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/audit"
)

func TestGenerateCompositeHashDeterministic(t *testing.T) {
    fp := audit.DeviceFingerprint{
        MACAddresses: []string{"00:11:22:33:44:55"},
        CPUSignature: "Intel|TestCPU",
        DiskSerials:  []string{"SN12345"},
        BIOSSerial:   "BIOS-UUID-TEST",
        MotherboardID: "MB-TEST",
        TPMPresent:   false,
        TPMFingerprint: "",
    }

    h1 := generateCompositeHash(fp)
    h2 := generateCompositeHash(fp)
    if h1 != h2 {
        t.Fatalf("composite hash not deterministic: %s != %s", h1, h2)
    }
}

func TestDetectSpoofingIndicatorsBasic(t *testing.T) {
    fp := audit.DeviceFingerprint{}
    ind := detectSpoofingIndicators(fp)
    // With empty fingerprint we expect at least the tpm_absent indicator
    found := false
    for _, v := range ind {
        if v == "tpm_absent" || v == "no_mac_addresses" {
            found = true
            break
        }
    }
    if !found {
        t.Fatalf("expected spoofing indicators for empty fingerprint, got: %v", ind)
    }
}
