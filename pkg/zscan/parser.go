package zscan

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ZGrabResult represents a single host record from ZGrab2 JSON output.
// ZGrab2 output is typically one JSON object per line (JSONL).
type ZGrabResult struct {
	IP     string `json:"ip"`
	Domain string `json:"domain,omitempty"`
	Data   struct {
		HTTP struct {
			Status string `json:"status"` // "success" or "unknown-error"
			Result struct {
				Response struct {
					StatusCode int                 `json:"status_code"`
					Headers    map[string][]string `json:"headers"`
				} `json:"response"`
			} `json:"result"`
		} `json:"http"`
		TLS struct {
			Status string `json:"status"`
			Result struct {
				HandshakeLog struct {
					ServerHello struct {
						Version struct {
							Name string `json:"name"` // e.g. "TLSv1.2"
						} `json:"version"`
						CipherSuite struct {
							Name string `json:"name"` // e.g. "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
						} `json:"cipher_suite"`
					} `json:"server_hello"`
				} `json:"handshake_log"`
			} `json:"result"`
		} `json:"tls"`
	} `json:"data"`
}

// ParseZGrabFile reads a ZGrab2 JSON output file.
// It detects whether it's a JSON array or JSON Lines (NDJSON).
func ParseZGrabFile(path string) ([]ZGrabResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var results []ZGrabResult

	// Try parsing as efficient JSONL first (common for ZGrab)
	lines := strings.Split(string(data), "\n")
	isJSONL := false
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "{") {
			var r ZGrabResult
			if err := json.Unmarshal([]byte(line), &r); err == nil {
				results = append(results, r)
				isJSONL = true
			}
		}
	}

	if isJSONL && len(results) > 0 {
		return results, nil
	}

	// Fallback to standard JSON array
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("failed to parse as JSON or JSONL: %v", err)
	}

	return results, nil
}
