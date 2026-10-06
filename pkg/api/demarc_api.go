package api

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
)

// =============================================================================
// MITOCHONDRIAL DEMARC API — BOUNDARY GATEWAY
// Patent §3.2/3.5: The "cell membrane" between external and internal services.
// Every environment crossing carries ML-DSA-87 signed DEMARCCredentials.
// Unrecognised or unsigned crossings are rejected and logged to the DAG.
// =============================================================================

// DEMARCCredential is an ML-DSA-87 signed boundary-crossing credential.
type DEMARCCredential struct {
	AgentID   string                `json:"agent_id"`
	Symbol    string                `json:"symbol"`
	PublicKey []byte                `json:"public_key"` // Serialized AdinkhepraPQC public key
	Token     *adinkra.ZeroTrustToken `json:"zt_token"`
	IssuedAt  int64                 `json:"issued_at"`
	ExpiresAt int64                 `json:"expires_at"`
	Signature []byte                `json:"signature"` // ML-DSA-87 over canonical fields
}

// IsExpired returns true if the credential has expired.
func (c *DEMARCCredential) IsExpired() bool {
	return time.Now().UnixNano() > c.ExpiresAt
}

// DEMARCGateway enforces boundary authentication at the Mitochondrial DEMARC layer.
type DEMARCGateway struct {
	Engine       *PolymorphicEngine
	AllowedCIDRs []*net.IPNet // Permitted source IP ranges (nil = allow all)
	auditLog     *adinkra.DAGAuditChain

	// authSecret is the server-held secret that zero-trust token keys are
	// derived from. It never leaves the gateway, so only the gateway can
	// mint or verify its tokens.
	authSecret []byte
}

// NewDEMARCGateway wraps a PolymorphicEngine with boundary enforcement.
func NewDEMARCGateway(engine *PolymorphicEngine) *DEMARCGateway {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic(fmt.Sprintf("DEMARC: cannot generate auth secret: %v", err))
	}
	return &DEMARCGateway{
		Engine:     engine,
		auditLog:   engine.AuditChain,
		authSecret: secret,
	}
}

// tokenKeys derives the zero-trust token keys for an agent from the gateway's
// server-held secret.
func (dg *DEMARCGateway) tokenKeys(agentID, symbol string) (*adinkra.KHEPRASessionKeys, error) {
	return adinkra.DeriveKHEPRASessionKeys(dg.authSecret, symbol, "Eban", []byte(agentID))
}

// VerifyToken checks a zero-trust token this gateway issued.
func (dg *DEMARCGateway) VerifyToken(token *adinkra.ZeroTrustToken) error {
	if token == nil {
		return fmt.Errorf("DEMARC: token is nil")
	}
	keys, err := dg.tokenKeys(token.AgentID, token.Symbol)
	if err != nil {
		return err
	}
	defer keys.SecureDestroySessionKeys()
	return adinkra.VerifyZeroTrustToken(token, keys.KAuth)
}

// Issue creates a new DEMARCCredential for a crossing agent.
func (dg *DEMARCGateway) Issue(agentID, symbol string, priv *adinkra.AdinkhepraPQCPrivateKey) (*DEMARCCredential, error) {
	if _, ok := adinkra.AdinkraPrecedence[symbol]; !ok {
		symbol = "Nkyinkyim"
	}

	if priv == nil {
		return nil, fmt.Errorf("DEMARC: no signing key supplied")
	}
	// The credential carries the caller's own public key, and the caller signs
	// it to prove possession of the matching private key.
	pub, err := priv.Public()
	if err != nil {
		return nil, fmt.Errorf("DEMARC: invalid signing key: %w", err)
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("DEMARC: public key encoding failed: %w", err)
	}

	// The token key comes from the gateway's server-held secret, never from
	// public data such as the agent's public key.
	sessionKeys, err := dg.tokenKeys(agentID, symbol)
	if err != nil {
		return nil, fmt.Errorf("DEMARC: session key derivation failed: %w", err)
	}
	defer sessionKeys.SecureDestroySessionKeys()

	ztToken, err := adinkra.IssueZeroTrustToken(agentID, symbol, 1.0, sessionKeys.KAuth)
	if err != nil {
		return nil, fmt.Errorf("DEMARC: ZT token issuance failed: %w", err)
	}

	now := time.Now().UnixNano()
	exp := now + adinkra.ZTTokenTTL.Nanoseconds()

	cred := &DEMARCCredential{
		AgentID:   agentID,
		Symbol:    symbol,
		PublicKey: pubBytes,
		Token:     ztToken,
		IssuedAt:  now,
		ExpiresAt: exp,
	}

	// Sign the credential with the caller's private key.
	canonical, err := json.Marshal(struct {
		AgentID   string `json:"agent_id"`
		Symbol    string `json:"symbol"`
		PublicKey []byte `json:"public_key"`
		IssuedAt  int64  `json:"issued_at"`
		ExpiresAt int64  `json:"expires_at"`
	}{cred.AgentID, cred.Symbol, cred.PublicKey, cred.IssuedAt, cred.ExpiresAt})
	if err != nil {
		return nil, fmt.Errorf("DEMARC: credential serialisation failed: %w", err)
	}

	sig, err := adinkra.SignAdinkhepraPQC(priv, canonical)
	if err != nil {
		return nil, fmt.Errorf("DEMARC: credential signing failed: %w", err)
	}
	cred.Signature = sig

	// Log issuance.
	_, _ = dg.auditLog.Append(
		[]byte(fmt.Sprintf("DEMARC:ISSUE:%s:%s", agentID, symbol)),
		symbol, agentID, nil,
		dg.Engine.KeyPair.AdinkhepraPQCPrivate,
	)

	adinkra.AuditSensitiveOperation(fmt.Sprintf("DEMARC:Issue:%s:%s", agentID, symbol), true)
	return cred, nil
}

// Authenticate verifies a DEMARCCredential presented at the boundary.
func (dg *DEMARCGateway) Authenticate(cred *DEMARCCredential) error {
	if cred == nil {
		return fmt.Errorf("DEMARC: nil credential")
	}
	if cred.IsExpired() {
		adinkra.AuditSensitiveOperation(fmt.Sprintf("DEMARC:ExpiredCredential:%s", cred.AgentID), false)
		return fmt.Errorf("DEMARC: credential expired for agent %s", cred.AgentID)
	}

	// The zero-trust token is what this gateway vouches for: it is keyed by
	// the gateway's server-held secret and bound to the agent and symbol.
	if cred.Token == nil || cred.Token.AgentID != cred.AgentID || cred.Token.Symbol != cred.Symbol {
		adinkra.AuditSensitiveOperation(fmt.Sprintf("DEMARC:AuthFailed:%s", cred.AgentID), false)
		return fmt.Errorf("DEMARC: credential token does not match agent %s", cred.AgentID)
	}
	if err := dg.VerifyToken(cred.Token); err != nil {
		adinkra.AuditSensitiveOperation(fmt.Sprintf("DEMARC:AuthFailed:%s", cred.AgentID), false)
		return fmt.Errorf("DEMARC: credential token invalid: %w", err)
	}

	// Reconstruct the signed payload and verify.
	canonical, err := json.Marshal(struct {
		AgentID   string `json:"agent_id"`
		Symbol    string `json:"symbol"`
		PublicKey []byte `json:"public_key"`
		IssuedAt  int64  `json:"issued_at"`
		ExpiresAt int64  `json:"expires_at"`
	}{cred.AgentID, cred.Symbol, cred.PublicKey, cred.IssuedAt, cred.ExpiresAt})
	if err != nil {
		return fmt.Errorf("DEMARC: serialisation failed: %w", err)
	}

	pub := &adinkra.AdinkhepraPQCPublicKey{}
	if err := pub.UnmarshalBinary(cred.PublicKey); err != nil {
		return fmt.Errorf("DEMARC: invalid public key: %w", err)
	}

	if err := adinkra.VerifyAdinkhepraPQC(pub, canonical, cred.Signature); err != nil {
		adinkra.AuditSensitiveOperation(fmt.Sprintf("DEMARC:AuthFailed:%s", cred.AgentID), false)
		return fmt.Errorf("DEMARC: credential signature invalid: %w", err)
	}

	// Log successful crossing.
	_, _ = dg.auditLog.Append(
		[]byte(fmt.Sprintf("DEMARC:CROSS:%s:%s", cred.AgentID, cred.Symbol)),
		"Eban", cred.AgentID, nil,
		dg.Engine.KeyPair.AdinkhepraPQCPrivate,
	)

	adinkra.AuditSensitiveOperation(fmt.Sprintf("DEMARC:Authenticate:%s", cred.AgentID), true)
	return nil
}

// checkIPAllowed verifies the source IP is within AllowedCIDRs (if configured).
func (dg *DEMARCGateway) checkIPAllowed(r *http.Request) bool {
	if len(dg.AllowedCIDRs) == 0 {
		return true // No restriction configured
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	for _, cidr := range dg.AllowedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// HTTPHandler returns an http.Handler implementing the DEMARC boundary checkpoint.
func (dg *DEMARCGateway) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !dg.checkIPAllowed(r) {
			adinkra.AuditSensitiveOperation(fmt.Sprintf("DEMARC:IPBlocked:%s", r.RemoteAddr), false)
			http.Error(w, "DEMARC: access denied — IP not in allowlist", http.StatusForbidden)
			return
		}

		// Parse credential from JSON body.
		var cred DEMARCCredential
		if err := json.NewDecoder(r.Body).Decode(&cred); err != nil {
			http.Error(w, "DEMARC: invalid credential format", http.StatusBadRequest)
			return
		}

		if err := dg.Authenticate(&cred); err != nil {
			http.Error(w, fmt.Sprintf("DEMARC: %v", err), http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Khepra-DEMARC", "authenticated")
		w.Header().Set("X-Khepra-Symbol", cred.Symbol)
		json.NewEncoder(w).Encode(map[string]string{
			"status":   "authenticated",
			"agent_id": cred.AgentID,
			"symbol":   cred.Symbol,
		})
	})
}
