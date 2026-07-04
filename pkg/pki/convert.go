package pki

import (
	"fmt"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/crypto"
)

// ToCryptoAssets converts every certificate captured during a TLS probe into
// CryptoAsset records, reusing pkg/crypto's risk classification and PQC
// migration-path logic so live network discoveries feed the same CBOM/SPDX
// export and Godfather-report pipeline as static filesystem scans.
func (r *TLSProbeResult) ToCryptoAssets() []crypto.CryptoAsset {
	if !r.Reachable {
		return nil
	}
	assets := make([]crypto.CryptoAsset, 0, len(r.Certificates))
	for i, cert := range r.Certificates {
		location := fmt.Sprintf("tls://%s", r.Target)
		if i > 0 {
			location = fmt.Sprintf("tls://%s#chain-%d", r.Target, i)
		}
		asset := crypto.AnalyzeCertificateAsset(cert, location)
		if r.WeakCipher && asset.ReviewNotes == "" {
			asset.ReviewNotes = "Negotiated weak cipher suite or legacy TLS version (" + r.TLSVersion + "/" + r.CipherSuite + ")"
			asset.ManualReview = true
		}
		if r.SelfSigned && i == 0 {
			asset.ReviewNotes = appendNote(asset.ReviewNotes, "Self-signed leaf certificate")
			asset.ManualReview = true
		}
		if r.HostnameMismatch && i == 0 {
			asset.ReviewNotes = appendNote(asset.ReviewNotes, "Certificate does not match requested hostname")
			asset.ManualReview = true
		}
		assets = append(assets, asset)
	}
	return assets
}

func appendNote(existing, addition string) string {
	if existing == "" {
		return addition
	}
	return existing + "; " + addition
}
