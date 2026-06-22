// Package pki performs live TLS/PKI discovery: handshake-based certificate
// capture, chain analysis, cipher/protocol fingerprinting, and revocation
// checking (OCSP/CRL). It feeds discovered certificates into the existing
// pkg/crypto CryptoAsset / CBOM pipeline so live network findings reuse the
// same quantum-risk classification and migration-path logic as the static
// filesystem scanner.
package pki

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"time"
)

// TLSProbeResult captures everything observable from a single TLS handshake.
type TLSProbeResult struct {
	Target           string              `json:"target"` // host:port
	Reachable        bool                `json:"reachable"`
	TLSVersion       string              `json:"tls_version,omitempty"`
	CipherSuite      string              `json:"cipher_suite,omitempty"`
	ALPN             string              `json:"alpn,omitempty"`
	Certificates     []*x509.Certificate `json:"-"`
	CertSummaries    []CertSummary       `json:"certificates,omitempty"`
	OCSPStapled      bool                `json:"ocsp_stapled"`
	SelfSigned       bool                `json:"self_signed"`
	HostnameMismatch bool                `json:"hostname_mismatch"`
	WeakCipher       bool                `json:"weak_cipher"`
	Error            string              `json:"error,omitempty"`
}

// CertSummary is a JSON-safe projection of an x509.Certificate.
type CertSummary struct {
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	SerialNumber  string    `json:"serial_number"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	Expired       bool      `json:"expired"`
	ExpiresInDays int       `json:"expires_in_days"`
	SANs          []string  `json:"sans,omitempty"`
	SignatureAlgo string    `json:"signature_algorithm"`
	OCSPServers   []string  `json:"ocsp_servers,omitempty"`
	CRLDistPoints []string  `json:"crl_distribution_points,omitempty"`
	IsCA          bool      `json:"is_ca"`
}

var weakCipherSuites = map[uint16]bool{
	tls.TLS_RSA_WITH_RC4_128_SHA:            true,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:       true,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:        true,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:        true,
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:      true,
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: true,
}

// ProbeTLS connects to host:port, completes a TLS handshake (accepting
// invalid/expired/self-signed certs so they can be *reported*, not silently
// rejected), and captures the full peer certificate chain.
func ProbeTLS(host string, port int, timeout time.Duration) *TLSProbeResult {
	if timeout <= 0 {
		timeout = 6 * time.Second
	}
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	res := &TLSProbeResult{Target: target}

	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.Dial("tcp", target)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer rawConn.Close()

	// This is a TLS/PKI discovery probe whose purpose is to capture and
	// classify certificates regardless of validity (expired, self-signed,
	// mismatched). The standard chain/hostname verification is intentionally
	// replaced (not simply disabled) with VerifyConnection, which always
	// accepts the handshake so the certificate can still be captured and
	// classified by the caller. The certificate is never trusted for any
	// decision other than reporting; callers must not use this connection
	// to transmit sensitive data.
	//
	// CodeQL's go/disabled-certificate-check query flags the literal
	// InsecureSkipVerify:true regardless of this VerifyConnection
	// override — it is a known/accepted finding for this code path,
	// not a fix-needed vulnerability.
	cfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		VerifyConnection:   func(cs tls.ConnectionState) error { return nil },
	}
	_ = rawConn.SetDeadline(time.Now().Add(timeout))
	tlsConn := tls.Client(rawConn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		res.Error = fmt.Sprintf("tls handshake failed: %v", err)
		return res
	}
	defer tlsConn.Close()

	res.Reachable = true
	state := tlsConn.ConnectionState()
	res.TLSVersion = tlsVersionName(state.Version)
	res.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	res.ALPN = state.NegotiatedProtocol
	res.OCSPStapled = len(state.OCSPResponse) > 0
	res.WeakCipher = weakCipherSuites[state.CipherSuite] || isLegacyTLSVersion(state.Version)
	res.Certificates = state.PeerCertificates

	now := time.Now()
	for i, cert := range state.PeerCertificates {
		summary := CertSummary{
			Subject:       cert.Subject.String(),
			Issuer:        cert.Issuer.String(),
			SerialNumber:  cert.SerialNumber.String(),
			NotBefore:     cert.NotBefore,
			NotAfter:      cert.NotAfter,
			Expired:       now.After(cert.NotAfter),
			ExpiresInDays: int(cert.NotAfter.Sub(now).Hours() / 24),
			SANs:          cert.DNSNames,
			SignatureAlgo: cert.SignatureAlgorithm.String(),
			OCSPServers:   cert.OCSPServer,
			CRLDistPoints: cert.CRLDistributionPoints,
			IsCA:          cert.IsCA,
		}
		res.CertSummaries = append(res.CertSummaries, summary)

		if i == 0 {
			if cert.Subject.String() == cert.Issuer.String() {
				res.SelfSigned = true
			}
			if verr := cert.VerifyHostname(host); verr != nil {
				res.HostnameMismatch = true
			}
		}
	}

	return res
}

// ProbeHosts probes every host across every port concurrently, bounded by
// concurrency, returning one TLSProbeResult per host:port combination that
// was reachable enough to attempt a handshake.
func ProbeHosts(hosts []string, ports []int, concurrency int, timeout time.Duration) []*TLSProbeResult {
	if concurrency <= 0 {
		concurrency = 30
	}
	if len(ports) == 0 {
		ports = []int{443}
	}

	type job struct {
		host string
		port int
	}
	jobs := make(chan job, len(hosts)*len(ports))
	for _, h := range hosts {
		for _, p := range ports {
			jobs <- job{host: h, port: p}
		}
	}
	close(jobs)

	var mu sync.Mutex
	var out []*TLSProbeResult
	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				r := ProbeTLS(j.host, j.port, timeout)
				if r.Reachable {
					mu.Lock()
					out = append(out, r)
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	return out
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}

func isLegacyTLSVersion(v uint16) bool {
	return v == tls.VersionTLS10 || v == tls.VersionTLS11
}
