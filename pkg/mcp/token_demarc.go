// Package mcp — token_demarc.go
//
// TokenDemarcGateway authenticates HTTP callers by bearer token. Tokens come
// from configuration (KHEPRA_HTTP_TOKENS), must be at least 32 bytes, and
// are kept only as SHA-256 digests compared in constant time. There is no
// anonymous or stdio fallback: a request without a configured token fails.
//
// IP: SOUHIMBOU DOH KONE LLC, exclusively licensed to SecRed Knowledge Inc.
package mcp

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// HTTPTokensEnv lists, comma-separated, the bearer tokens accepted by the
// HTTP transport.
const HTTPTokensEnv = "KHEPRA_HTTP_TOKENS"

// MinHTTPTokenLen is the minimum bearer token length in bytes.
const MinHTTPTokenLen = 32

// TokenDemarcGateway is the DemarcGateway for the HTTP transport.
type TokenDemarcGateway struct {
	digests [][sha256.Size]byte
	scopes  []string
	// AllowedCIDRs restricts remote addresses (exact matches); empty = any.
	AllowedCIDRs []string
}

// HTTPTokensFromEnv returns the tokens listed in HTTPTokensEnv.
func HTTPTokensFromEnv() []string {
	var out []string
	for _, t := range strings.Split(os.Getenv(HTTPTokensEnv), ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// NewTokenDemarcGateway accepts the given tokens and grants scopes to any
// caller presenting one of them. It fails if no token is usable.
func NewTokenDemarcGateway(tokens []string, scopes []string) (*TokenDemarcGateway, error) {
	g := &TokenDemarcGateway{scopes: scopes}
	for _, t := range tokens {
		if len(t) < MinHTTPTokenLen {
			return nil, fmt.Errorf("demarc: HTTP tokens must be at least %d bytes", MinHTTPTokenLen)
		}
		g.digests = append(g.digests, sha256.Sum256([]byte(t)))
	}
	if len(g.digests) == 0 {
		return nil, fmt.Errorf("demarc: no HTTP tokens configured (set %s)", HTTPTokensEnv)
	}
	return g, nil
}

// Authenticate accepts only a configured bearer token.
func (g *TokenDemarcGateway) Authenticate(_ context.Context, cred any) (Identity, error) {
	token, ok := cred.(string)
	if !ok || token == "" || token == "stdio" {
		return Identity{}, errors.New("demarc: bearer token required")
	}
	d := sha256.Sum256([]byte(token))
	match := 0
	for i := range g.digests {
		match |= subtle.ConstantTimeCompare(d[:], g.digests[i][:])
	}
	if match != 1 {
		return Identity{}, errors.New("demarc: invalid bearer token")
	}
	return Identity{
		Subject:   "token:" + hex.EncodeToString(d[:8]),
		Issuer:    "demarc-http",
		AgentID:   "http-client-" + hex.EncodeToString(d[:4]),
		SessionID: hex.EncodeToString(d[:16]),
		Scopes:    g.scopes,
	}, nil
}

// CheckCIDR applies AllowedCIDRs (exact remote-address matches).
func (g *TokenDemarcGateway) CheckCIDR(_ context.Context, _ Identity, remoteAddr string) error {
	if len(g.AllowedCIDRs) == 0 {
		return nil
	}
	for _, a := range g.AllowedCIDRs {
		if a == remoteAddr {
			return nil
		}
	}
	return fmt.Errorf("demarc: remote address %q not allowed", remoteAddr)
}
