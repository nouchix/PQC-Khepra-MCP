package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// The gateway must not pin CurvePreferences: an explicit list replaces Go's
// defaults and drops the hybrid post-quantum key exchanges.
func TestConfigureTLS_LeavesPostQuantumGroupsEnabled(t *testing.T) {
	g := &Gateway{config: DefaultConfig()}
	if err := g.configureTLS(); err != nil {
		t.Fatalf("configureTLS: %v", err)
	}
	if len(g.tlsConfig.CurvePreferences) != 0 {
		t.Fatalf("CurvePreferences is pinned to %v; this disables hybrid ML-KEM key exchange", g.tlsConfig.CurvePreferences)
	}
}

// A default Go client handshaking with the gateway's TLS config must
// negotiate the hybrid X25519MLKEM768 group.
func TestConfigureTLS_NegotiatesHybridMLKEM(t *testing.T) {
	g := &Gateway{config: DefaultConfig()}
	if err := g.configureTLS(); err != nil {
		t.Fatalf("configureTLS: %v", err)
	}

	cert, pool := selfSignedCert(t)
	serverCfg := g.tlsConfig.Clone()
	serverCfg.Certificates = []tls.Certificate{cert}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	server := tls.Server(serverConn, serverCfg)
	errc := make(chan error, 1)
	go func() { errc <- server.Handshake() }()

	client := tls.Client(clientConn, &tls.Config{RootCAs: pool, ServerName: "gateway.test"})
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	if got := client.ConnectionState().CurveID; got != tls.X25519MLKEM768 {
		t.Fatalf("negotiated key exchange %v, want %v", got, tls.X25519MLKEM768)
	}
}

func selfSignedCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "gateway.test"},
		DNSNames:     []string{"gateway.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}
