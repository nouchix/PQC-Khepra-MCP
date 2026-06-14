package packet

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// TSharkPacket represents a single packet from a TShark JSON export.
// We only map fields relevant to "Crypto-Agility" and Security.
type TSharkPacket struct {
	Source struct {
		Layers struct {
			Frame struct {
				Time   string `json:"frame.time"`
				Number string `json:"frame.number"`
			} `json:"frame"`
			IP struct {
				Src string `json:"ip.src"`
				Dst string `json:"ip.dst"`
			} `json:"ip"`
			TCP struct {
				SrcPort string `json:"tcp.srcport"`
				DstPort string `json:"tcp.dstport"`
			} `json:"tcp"`
			TLS struct {
				Version     string `json:"tls.record.version"`
				CipherSuite string `json:"tls.handshake.ciphersuite"`
			} `json:"tls"`
			HTTP interface{} `json:"http,omitempty"` // If present, it's cleartext
		} `json:"layers"`
	} `json:"_source"`
}

// AnalysisResult summarizes the PQC/Security findings from the packet capture.
type AnalysisResult struct {
	TotalPackets      int
	CleartextCount    int
	LegacyTLSCount    int // TLS 1.0/1.1
	WeakCipherCount   int // e.g. RC4, DES
	QuantumRiskyCount int // Standard TLS (RSA/ECDH) - "Store Now Decrypt Later" risk
}

// AnalyzeWiresharkJSON reads a TShark -T json export and audits it.
func AnalyzeWiresharkJSON(path string) (*AnalysisResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var packets []TSharkPacket
	if err := json.Unmarshal(data, &packets); err != nil {
		return nil, fmt.Errorf("invalid tshark json: %v", err)
	}

	res := &AnalysisResult{TotalPackets: len(packets)}

	for _, p := range packets {
		l := p.Source.Layers

		// 1. Cleartext Detection (HTTP presence)
		if l.HTTP != nil {
			res.CleartextCount++
		}

		// 2. Legacy Crypto (TLS Version)
		if l.TLS.Version != "" {
			// e.g., "0x0301" is TLS 1.0, "0x0303" is TLS 1.2
			if l.TLS.Version == "0x0301" || l.TLS.Version == "0x0302" {
				res.LegacyTLSCount++
			}

			// 3. PQC / Quantum Risk Audit
			// Virtually ALL current TLS is "Quantum Risky" (RSA/ECDH)
			// Khepra marks this as a risk to drive PQC migration sales.
			res.QuantumRiskyCount++
		}

		// 4. Weak Ciphers (Heuristic)
		if strings.Contains(l.TLS.CipherSuite, "RC4") || strings.Contains(l.TLS.CipherSuite, "DES") {
			res.WeakCipherCount++
		}
	}

	return res, nil
}
