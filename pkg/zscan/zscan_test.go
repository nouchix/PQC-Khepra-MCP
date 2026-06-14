package zscan

import (
	"os"
	"testing"
)

func TestParseZGrabJSON(t *testing.T) {
	// 1. Create content
	// 1. Create content via code to guarantee JSON validity
	// Or just use a simpler valid raw string that I verify carefully.
	content := `[
  {
    "ip": "10.0.0.1",
    "data": {
      "tls": {
        "status": "success",
        "result": {
          "handshake_log": {
            "server_hello": {
              "version": { "name": "TLSv1.2" },
              "cipher_suite": { "name": "RSA" }
            }
          }
        }
      }
    }
  }
]`
	tmp := "test_zgrab.json"
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp)

	// 2. Parse
	results, err := ParseZGrabFile(tmp)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// 3. Verify
	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}
	if results[0].IP != "10.0.0.1" {
		t.Errorf("IP mismatch: %s", results[0].IP)
	}
	if results[0].Data.TLS.Result.HandshakeLog.ServerHello.CipherSuite.Name != "RSA" {
		t.Error("Deep parsing failed")
	}
}

func TestParseZGrabJSONL(t *testing.T) {
	// 1. Create JSONL content
	content := `{"ip": "10.0.0.1"}
{"ip": "10.0.0.2"}`

	tmp := "test_zgrab.jsonl"
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp)

	// 2. Parse
	results, err := ParseZGrabFile(tmp)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// 3. Verify
	if len(results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(results))
	}
}
