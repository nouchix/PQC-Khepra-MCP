package pki

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

// RevocationStatus reports whether a leaf certificate has been revoked,
// checked via OCSP (preferred) and falling back to CRL.
type RevocationStatus struct {
	Subject     string `json:"subject"`
	Method      string `json:"method"` // "ocsp" | "crl" | "none_available"
	Revoked     bool   `json:"revoked"`
	RevokedAt   string `json:"revoked_at,omitempty"`
	Reason      string `json:"reason,omitempty"`
	CheckedAt   string `json:"checked_at"`
	Error       string `json:"error,omitempty"`
}

// CheckRevocation checks leaf (chain[0]) against its issuer (chain[1], if
// present) using OCSP, falling back to CRL distribution points.
func CheckRevocation(chain []*x509.Certificate, timeout time.Duration) RevocationStatus {
	status := RevocationStatus{CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	if len(chain) == 0 {
		status.Method = "none_available"
		status.Error = "no certificate provided"
		return status
	}
	leaf := chain[0]
	status.Subject = leaf.Subject.String()
	if timeout <= 0 {
		timeout = 8 * time.Second
	}

	if len(chain) > 1 && len(leaf.OCSPServer) > 0 {
		if ok, revoked, revokedAt, reason, err := checkOCSP(leaf, chain[1], timeout); err == nil && ok {
			status.Method = "ocsp"
			status.Revoked = revoked
			if revoked {
				status.RevokedAt = revokedAt
				status.Reason = reason
			}
			return status
		}
	}

	if len(leaf.CRLDistributionPoints) > 0 {
		if revoked, err := checkCRL(leaf, timeout); err == nil {
			status.Method = "crl"
			status.Revoked = revoked
			return status
		} else {
			status.Error = err.Error()
		}
	}

	status.Method = "none_available"
	return status
}

func checkOCSP(leaf, issuer *x509.Certificate, timeout time.Duration) (ok, revoked bool, revokedAt, reason string, err error) {
	reqBytes, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return false, false, "", "", err
	}

	client := &http.Client{Timeout: timeout}
	for _, server := range leaf.OCSPServer {
		req, herr := http.NewRequest(http.MethodPost, server, bytes.NewReader(reqBytes))
		if herr != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/ocsp-request")
		resp, herr := client.Do(req)
		if herr != nil {
			continue
		}
		body, herr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if herr != nil {
			continue
		}
		parsed, perr := ocsp.ParseResponseForCert(body, leaf, issuer)
		if perr != nil {
			continue
		}
		switch parsed.Status {
		case ocsp.Revoked:
			return true, true, parsed.RevokedAt.Format(time.RFC3339), fmt.Sprintf("reason_code=%d", parsed.RevocationReason), nil
		case ocsp.Good:
			return true, false, "", "", nil
		default:
			return true, false, "", "unknown", nil
		}
	}
	return false, false, "", "", fmt.Errorf("no reachable OCSP responder")
}

func checkCRL(leaf *x509.Certificate, timeout time.Duration) (bool, error) {
	client := &http.Client{Timeout: timeout}
	for _, url := range leaf.CRLDistributionPoints {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		crl, err := x509.ParseRevocationList(body)
		if err != nil {
			continue
		}
		for _, rev := range crl.RevokedCertificateEntries {
			if rev.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
				return true, nil
			}
		}
		return false, nil
	}
	return false, fmt.Errorf("no reachable CRL distribution point")
}
