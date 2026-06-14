package packet

import (
	"os"
	"testing"
)

func TestAnalyzeWiresharkJSON(t *testing.T) {
	// Create sample TShark JSON
	jsonContent := `[
		{
			"_source": {
				"layers": {
					"frame": {
						"frame.time": "Dec 16, 2025 10:00:00.000000000",
						"frame.number": "1"
					},
					"ip": {
						"ip.src": "192.168.1.1",
						"ip.dst": "192.168.1.2"
					},
					"tcp": {
						"tcp.srcport": "443",
						"tcp.dstport": "50000"
					},
					"tls": {
						"tls.record.version": "0x0303",
						"tls.handshake.ciphersuite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
					}
				}
			}
		},
		{
			"_source": {
				"layers": {
					"frame": {
						"frame.number": "2"
					},
					"http": {}
				}
			}
		}
	]`

	tmpfile, err := os.CreateTemp("", "test_packets_*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(jsonContent)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	res, err := AnalyzeWiresharkJSON(tmpfile.Name())
	if err != nil {
		t.Fatalf("AnalyzeWiresharkJSON failed: %v", err)
	}

	if res.TotalPackets != 2 {
		t.Errorf("Expected 2 packets, got %d", res.TotalPackets)
	}

	if res.CleartextCount != 1 {
		t.Errorf("Expected 1 cleartext packet, got %d", res.CleartextCount)
	}

	if res.QuantumRiskyCount != 1 {
		t.Errorf("Expected 1 quantum risky packet, got %d", res.QuantumRiskyCount)
	}
}
