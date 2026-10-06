// Package upstream — the Mitochondrial broker: KHEPRA as an MCP *client*.
//
// Everything in pkg/mcp treats KHEPRA as the server an agent talks to. This
// package is the other direction: KHEPRA dials a third-party MCP server
// (UptimeRobot, GitHub, …), authenticates with OAuth 2.1 + PKCE, discovers
// its tools, and re-exposes them through the Router so every brokered call
// inherits the full admission chain (DEMARC → manifest pin → polymorphic
// wrap → gateway → risk-classified exec → ML-DSA-65 attestation → flight
// recording).
//
// store.go: PQC-sealed on-disk state. Holds the OAuth token set and the
// pinned upstream tool schemas. Nothing in here is ever written in the clear.
package upstream

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/nouchix/khepra-pqc/envelope"
	"github.com/nouchix/khepra-pqc/kem"
)

// ─── Sealed state ─────────────────────────────────────────────────────────────

// TokenSet is the OAuth 2.1 token material for one upstream server.
type TokenSet struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type"`
	Scope        string    `json:"scope,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Expired reports whether the access token is (about to be) unusable.
// A 60s skew keeps a call from racing the upstream clock.
func (t *TokenSet) Expired() bool {
	if t == nil || t.AccessToken == "" {
		return true
	}
	if t.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().Add(60 * time.Second).After(t.ExpiresAt)
}

// ClientRegistration is the RFC 7591 dynamic-client-registration result.
// Kept sealed because client_secret, when issued, is a credential.
type ClientRegistration struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	RedirectURI  string `json:"redirect_uri"`
}

// PinnedTool is the trust-on-first-use record for one upstream tool.
// SchemaHash is SHA-256 over the canonical (name, description, inputSchema)
// bytes exactly as the upstream advertised them the first time we connected.
// A later tools/list that disagrees is a tool-rug / description-poisoning
// attempt (AgentHound SHADOWS / POISONED_DESCRIPTION) and is refused.
type PinnedTool struct {
	Name        string    `json:"name"`
	SchemaHash  string    `json:"schema_hash"`
	PinnedAt    time.Time `json:"pinned_at"`
	RiskClass   string    `json:"risk_class"`
	Description string    `json:"description"`
}

// ServerState is everything KHEPRA remembers about one upstream, sealed.
type ServerState struct {
	URL          string                `json:"url"`
	Registration *ClientRegistration   `json:"registration,omitempty"`
	Tokens       *TokenSet             `json:"tokens,omitempty"`
	Pins         map[string]PinnedTool `json:"pins,omitempty"`
	PinnedAt     time.Time             `json:"pinned_at,omitempty"`
}

// ─── Store ────────────────────────────────────────────────────────────────────

// Store persists ServerState under a per-machine Kyber-1024 KEM keypair.
//
// Seal path:  Kyber-1024 encapsulate → shared secret → HKDF-SHA256 → AES-256-GCM.
// The KEM private key lives at <dir>/kem.key, mode 0600, and is the only
// thing that can open the sealed blobs. On POSIX the directory is created
// 0700 and the store refuses to run if it finds it world-readable — the
// AgentHound AH-001 finding was exactly this class of omission.
//
// State is sealed with the KHQ3 envelope from github.com/nouchix/khepra-pqc:
// ML-KEM-1024 (FIPS 203) to this machine's key, HKDF-SHA-384, AES-256-GCM.
type Store struct {
	dir string
	dk  *kem.DecapsulationKey
}

const (
	// kemKeyFile holds the ML-KEM-1024 decapsulation key (64-byte seed).
	kemKeyFile    = "mlkem1024.key"
	stateSuffix   = ".sealed"
	envelopeLabel = "khepra-mcp/upstream/v3"
	sealedMagic   = "KHEPRA-SEAL-3"
	// retiredMagic marks state sealed by the pre-standard Kyber store.
	retiredMagic = "KHEPRA-SEAL-1"
)

// DefaultDir returns the broker's state directory: $KHEPRA_DATA_DIR/upstream
// or ~/.khepra/upstream. Same root as the flight recorder, so one permission
// audit covers both.
func DefaultDir() string {
	if d := os.Getenv("KHEPRA_DATA_DIR"); d != "" {
		return filepath.Join(d, "upstream")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".khepra", "upstream")
}

// OpenStore loads or creates the KEM keypair under dir.
func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("upstream/store: mkdir %s: %w", dir, err)
	}
	if err := checkDirPerms(dir); err != nil {
		return nil, err
	}
	s := &Store{dir: dir}

	privPath := filepath.Join(dir, kemKeyFile)
	seed, err := os.ReadFile(privPath)
	switch {
	case err == nil:
		dk, err := kem.NewDecapsulationKey(seed)
		if err != nil {
			return nil, fmt.Errorf("upstream/store: %s: %w", kemKeyFile, err)
		}
		s.dk = dk
		return s, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("upstream/store: read kem key: %w", err)
	}

	dk, err := kem.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("upstream/store: ML-KEM-1024 keygen: %w", err)
	}
	if err := writeFile0600(privPath, dk.Bytes()); err != nil {
		return nil, err
	}
	s.dk = dk
	return s, nil
}

// Dir returns the state directory.
func (s *Store) Dir() string { return s.dir }

// statePath maps an upstream URL to a stable filename.
func (s *Store) statePath(url string) string {
	h := sha256.Sum256([]byte(strings.TrimRight(url, "/")))
	return filepath.Join(s.dir, fmt.Sprintf("%x%s", h[:12], stateSuffix))
}

// Load returns the sealed state for url, or an empty state if none exists.
func (s *Store) Load(url string) (*ServerState, error) {
	blob, err := os.ReadFile(s.statePath(url))
	if errors.Is(err, os.ErrNotExist) {
		return &ServerState{URL: url, Pins: map[string]PinnedTool{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("upstream/store: read: %w", err)
	}
	plain, err := s.unseal(blob)
	if err != nil {
		return nil, err
	}
	var st ServerState
	if err := json.Unmarshal(plain, &st); err != nil {
		return nil, fmt.Errorf("upstream/store: decode: %w", err)
	}
	if st.Pins == nil {
		st.Pins = map[string]PinnedTool{}
	}
	return &st, nil
}

// Save seals and atomically writes state.
func (s *Store) Save(st *ServerState) error {
	plain, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("upstream/store: encode: %w", err)
	}
	blob, err := s.seal(plain)
	if err != nil {
		return err
	}
	path := s.statePath(st.URL)
	tmp := path + ".tmp"
	if err := writeFile0600(tmp, blob); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("upstream/store: rename: %w", err)
	}
	return nil
}

// Forget removes all sealed state for url (logout).
func (s *Store) Forget(url string) error {
	err := os.Remove(s.statePath(url))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// ─── Seal / unseal ────────────────────────────────────────────────────────────

// sealed wire format (JSON for auditability):
//
//	{"magic":"KHEPRA-SEAL-3","envelope":<b64 KHQ3 envelope>}
type sealedBlob struct {
	Magic    string `json:"magic"`
	Envelope []byte `json:"envelope"`
}

func (s *Store) seal(plain []byte) ([]byte, error) {
	env, err := envelope.Seal(s.dk.EncapsulationKey(), envelopeLabel, plain)
	if err != nil {
		return nil, fmt.Errorf("upstream/store: seal: %w", err)
	}
	return json.Marshal(sealedBlob{Magic: sealedMagic, Envelope: env})
}

func (s *Store) unseal(blob []byte) ([]byte, error) {
	var sb sealedBlob
	if err := json.Unmarshal(blob, &sb); err != nil {
		return nil, fmt.Errorf("upstream/store: sealed blob malformed: %w", err)
	}
	switch sb.Magic {
	case sealedMagic:
	case retiredMagic:
		return nil, errors.New("upstream/store: state was sealed with the retired pre-standard format; run Forget and re-authorize this upstream")
	default:
		return nil, fmt.Errorf("upstream/store: unknown seal format %q", sb.Magic)
	}
	plain, err := envelope.Open(s.dk, envelopeLabel, sb.Envelope)
	if err != nil {
		return nil, errors.New("upstream/store: seal integrity check failed (tampered or wrong machine key)")
	}
	return plain, nil
}

// ─── Filesystem hygiene ───────────────────────────────────────────────────────

func writeFile0600(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("upstream/store: write %s: %w", filepath.Base(path), err)
	}
	return nil
}

// checkDirPerms fails closed if the state dir is readable by others.
// Windows ACLs aren't expressed in the mode bits, so the check is POSIX-only;
// on Windows the per-user %USERPROFILE% ACL is the boundary.
func checkDirPerms(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("upstream/store: %s is group/world accessible (%04o) — refusing to store credentials; chmod 700 it",
			dir, fi.Mode().Perm())
	}
	return nil
}
