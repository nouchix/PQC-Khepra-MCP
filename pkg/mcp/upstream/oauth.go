package upstream

// oauth.go: OAuth 2.1 client for MCP servers, as specified by the MCP
// authorization spec (2025-06-18): RFC 9728 protected-resource discovery →
// RFC 8414 authorization-server metadata → RFC 7591 dynamic client
// registration → authorization-code grant with PKCE (S256) → RFC 8707
// resource indicator on both the authorize and token requests.
//
// The redirect target is a loopback listener on 127.0.0.1 with a random
// port (RFC 8252 §7.3). The literal IP is deliberate: "localhost" can be
// repointed by a hosts-file or resolver, 127.0.0.1 cannot.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// ─── Discovery documents ──────────────────────────────────────────────────────

type protectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}

type authServerMetadata struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	RegistrationEndpoint          string   `json:"registration_endpoint"`
	ScopesSupported               []string `json:"scopes_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
}

// OAuthConfig tunes the flow. Zero value is usable.
type OAuthConfig struct {
	// ClientName is sent in dynamic client registration and shown on the
	// upstream's consent screen. Default "KHEPRA MCP Broker".
	ClientName string
	// Scope, if set, is requested explicitly. Otherwise the server's default
	// applies — for UptimeRobot that's the consent-screen access-level picker.
	Scope string
	// Timeout bounds how long we wait for the human to complete consent.
	Timeout time.Duration
	// OpenBrowser launches the system browser. Set false in headless CI; the
	// URL is always logged so it can be opened manually.
	OpenBrowser bool
	// HTTPClient overrides the client used for discovery/token calls.
	HTTPClient *http.Client
	Logger     *log.Logger
}

func (c OAuthConfig) withDefaults() OAuthConfig {
	if c.ClientName == "" {
		c.ClientName = "KHEPRA MCP Broker"
	}
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Minute
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if c.Logger == nil {
		c.Logger = log.Default()
	}
	return c
}

// ─── Discovery ────────────────────────────────────────────────────────────────

var resourceMetadataRe = regexp.MustCompile(`resource_metadata="([^"]+)"`)

// discover resolves the authorization server for an MCP endpoint.
//
// Order, per the MCP spec:
//  1. Probe the MCP URL unauthenticated; a 401 may carry
//     WWW-Authenticate: Bearer resource_metadata="…" (RFC 9728 §5.1).
//  2. Else try <origin>/.well-known/oauth-protected-resource[/<path>].
//  3. From the protected-resource doc, take authorization_servers[0] and
//     fetch its RFC 8414 metadata; fall back to OIDC discovery.
//  4. If no protected-resource doc exists at all, assume the MCP origin is
//     its own authorization server (pre-2025-06-18 servers do this).
func discover(ctx context.Context, cfg OAuthConfig, mcpURL string) (*authServerMetadata, string, error) {
	u, err := url.Parse(mcpURL)
	if err != nil {
		return nil, "", fmt.Errorf("upstream/oauth: bad mcp url: %w", err)
	}
	origin := u.Scheme + "://" + u.Host

	var prmURLs []string
	// Step 1: the 401 hint.
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, mcpURL, strings.NewReader(`{"jsonrpc":"2.0","id":0,"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if resp, err := cfg.HTTPClient.Do(req); err == nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			if m := resourceMetadataRe.FindStringSubmatch(resp.Header.Get("WWW-Authenticate")); len(m) == 2 {
				prmURLs = append(prmURLs, m[1])
			}
		}
	}
	// Step 2: well-known fallbacks (path-scoped first, then root).
	if p := strings.TrimSuffix(u.Path, "/"); p != "" {
		prmURLs = append(prmURLs, origin+"/.well-known/oauth-protected-resource"+p)
	}
	prmURLs = append(prmURLs, origin+"/.well-known/oauth-protected-resource")

	asIssuer := ""
	for _, prmURL := range prmURLs {
		var prm protectedResourceMetadata
		if err := getJSON(ctx, cfg.HTTPClient, prmURL, &prm); err != nil {
			continue
		}
		if len(prm.AuthorizationServers) > 0 {
			asIssuer = prm.AuthorizationServers[0]
			break
		}
	}
	if asIssuer == "" {
		asIssuer = origin // Step 4
		cfg.Logger.Printf("[UPSTREAM:OAUTH] no protected-resource metadata at %s — assuming origin is its own AS", mcpURL)
	}

	// Step 3: AS metadata.
	asURL, err := url.Parse(asIssuer)
	if err != nil {
		return nil, "", fmt.Errorf("upstream/oauth: bad authorization_server %q: %w", asIssuer, err)
	}
	asOrigin := asURL.Scheme + "://" + asURL.Host
	candidates := []string{}
	if p := strings.TrimSuffix(asURL.Path, "/"); p != "" {
		candidates = append(candidates,
			asOrigin+"/.well-known/oauth-authorization-server"+p,
			asOrigin+p+"/.well-known/openid-configuration",
		)
	}
	candidates = append(candidates,
		asOrigin+"/.well-known/oauth-authorization-server",
		asOrigin+"/.well-known/openid-configuration",
	)
	for _, c := range candidates {
		var meta authServerMetadata
		if err := getJSON(ctx, cfg.HTTPClient, c, &meta); err == nil && meta.AuthorizationEndpoint != "" && meta.TokenEndpoint != "" {
			return &meta, asIssuer, nil
		}
	}
	return nil, "", fmt.Errorf("upstream/oauth: no authorization-server metadata found for %s", asIssuer)
}

func getJSON(ctx context.Context, c *http.Client, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// ─── Dynamic client registration (RFC 7591) ───────────────────────────────────

func registerClient(ctx context.Context, cfg OAuthConfig, meta *authServerMetadata, redirectURI string) (*ClientRegistration, error) {
	if meta.RegistrationEndpoint == "" {
		return nil, errors.New("upstream/oauth: authorization server does not support dynamic client registration; set KHEPRA_UPSTREAM_CLIENT_ID")
	}
	body, _ := json.Marshal(map[string]any{
		"client_name":                cfg.ClientName,
		"redirect_uris":              []string{redirectURI},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none", // public client + PKCE, per OAuth 2.1 for native apps
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.RegistrationEndpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upstream/oauth: register: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream/oauth: register: %s: %s", resp.Status, redactSecrets(truncate(raw, 300)))
	}
	var reg struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal(raw, &reg); err != nil || reg.ClientID == "" {
		return nil, fmt.Errorf("upstream/oauth: register: malformed response")
	}
	return &ClientRegistration{ClientID: reg.ClientID, ClientSecret: reg.ClientSecret, RedirectURI: redirectURI}, nil
}

// ─── PKCE ─────────────────────────────────────────────────────────────────────

// pkcePair returns (verifier, S256 challenge). 32 random bytes → 43-char
// base64url verifier, the RFC 7636 minimum.
func pkcePair() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", "", err
	}
	verifier := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func randomState() (string, error) {
	raw := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// ─── Loopback redirect listener ───────────────────────────────────────────────

type callbackResult struct {
	code string
	err  error
}

// startLoopback binds 127.0.0.1:0 and serves exactly one callback.
func startLoopback(expectedState string) (redirectURI string, wait func(context.Context) (string, error), stop func(), err error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, nil, fmt.Errorf("upstream/oauth: loopback listen: %w", err)
	}
	const path = "/oauth/callback"
	redirectURI = fmt.Sprintf("http://%s%s", ln.Addr().String(), path)
	ch := make(chan callbackResult, 1)

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			http.Error(w, "Authorization denied: "+e, http.StatusBadRequest)
			ch <- callbackResult{err: fmt.Errorf("upstream/oauth: authorization denied: %s (%s)", e, q.Get("error_description"))}
			return
		}
		// Constant-time state comparison — CSRF defense (RFC 6749 §10.12).
		if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(expectedState)) != 1 {
			http.Error(w, "State mismatch", http.StatusBadRequest)
			ch <- callbackResult{err: errors.New("upstream/oauth: state mismatch on callback")}
			return
		}
		code := q.Get("code")
		if code == "" {
			http.Error(w, "Missing code", http.StatusBadRequest)
			ch <- callbackResult{err: errors.New("upstream/oauth: callback without code")}
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><title>KHEPRA</title><body style="font-family:system-ui;padding:2em">
<h2>Consent received</h2><p>KHEPRA is now exchanging the code for a token and sealing it under this machine's Kyber-1024 key. The CLI reports the final result &mdash; check it before assuming success. You can close this window.</p></body>`)
		ch <- callbackResult{code: code}
	})
	// Anything else on this port (including "/") is a 404 — there is nothing
	// to see, and the listener dies as soon as the callback lands.
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln) //nolint:errcheck

	wait = func(ctx context.Context) (string, error) {
		select {
		case r := <-ch:
			return r.code, r.err
		case <-ctx.Done():
			return "", fmt.Errorf("upstream/oauth: timed out waiting for consent: %w", ctx.Err())
		}
	}
	stop = func() {
		c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(c)
	}
	return redirectURI, wait, stop, nil
}

// ─── Token endpoint ───────────────────────────────────────────────────────────

func tokenRequest(ctx context.Context, cfg OAuthConfig, meta *authServerMetadata, reg *ClientRegistration, form url.Values) (*TokenSet, error) {
	form.Set("client_id", reg.ClientID)
	// client_secret_post. Some MCP authorization servers (UptimeRobot, as of
	// 2026-09) issue a secret from DCR and then require it in the token
	// request body even for a PKCE public client — a deviation from OAuth 2.1
	// native-app guidance, but harmless to satisfy: the secret is sealed at
	// rest like the tokens, and PKCE still binds the code to this process.
	if reg.ClientSecret != "" {
		form.Set("client_secret", reg.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upstream/oauth: token: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	// 200 per RFC 6749 §5.1; some servers (UptimeRobot) answer 201.
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("upstream/oauth: token: %s: %s", resp.Status, redactSecrets(truncate(raw, 300)))
	}
	var tr struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(raw, &tr); err != nil || tr.AccessToken == "" {
		return nil, errors.New("upstream/oauth: token: malformed response")
	}
	ts := &TokenSet{AccessToken: tr.AccessToken, RefreshToken: tr.RefreshToken, TokenType: tr.TokenType, Scope: tr.Scope}
	if tr.ExpiresIn > 0 {
		ts.ExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	return ts, nil
}

// Authorize runs the full interactive flow and returns fresh tokens plus the
// client registration that must be persisted for refresh.
func Authorize(ctx context.Context, cfg OAuthConfig, mcpURL string, existing *ClientRegistration) (*TokenSet, *ClientRegistration, error) {
	cfg = cfg.withDefaults()
	meta, issuer, err := discover(ctx, cfg, mcpURL)
	if err != nil {
		return nil, nil, err
	}
	cfg.Logger.Printf("[UPSTREAM:OAUTH] authorization server: %s", issuer)

	state, err := randomState()
	if err != nil {
		return nil, nil, err
	}
	redirectURI, wait, stop, err := startLoopback(state)
	if err != nil {
		return nil, nil, err
	}
	defer stop()

	// DCR binds redirect_uri to client_id, and the loopback port is random,
	// so a saved registration is only reusable if its redirect still matches.
	// Public clients registering fresh each time is normal for native apps.
	reg := existing
	if reg == nil || reg.RedirectURI != redirectURI {
		reg, err = registerClient(ctx, cfg, meta, redirectURI)
		if err != nil {
			return nil, nil, err
		}
		cfg.Logger.Printf("[UPSTREAM:OAUTH] registered client id=%s secret_issued=%t", reg.ClientID, reg.ClientSecret != "")
	}

	verifier, challenge, err := pkcePair()
	if err != nil {
		return nil, nil, err
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {reg.ClientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
		"resource":              {mcpURL}, // RFC 8707 — binds the token to this MCP server
	}
	if cfg.Scope != "" {
		q.Set("scope", cfg.Scope)
	}
	authURL := meta.AuthorizationEndpoint
	if strings.Contains(authURL, "?") {
		authURL += "&" + q.Encode()
	} else {
		authURL += "?" + q.Encode()
	}

	cfg.Logger.Printf("[UPSTREAM:OAUTH] consent required — open this URL if the browser did not launch:\n  %s", authURL)
	if cfg.OpenBrowser {
		openBrowser(authURL)
	}

	waitCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	code, err := wait(waitCtx)
	if err != nil {
		return nil, nil, err
	}

	tokens, err := tokenRequest(ctx, cfg, meta, reg, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
		"resource":      {mcpURL},
	})
	if err != nil {
		return nil, nil, err
	}
	cfg.Logger.Printf("[UPSTREAM:OAUTH] token issued scope=%q expires=%s", tokens.Scope, tokens.ExpiresAt.Format(time.RFC3339))
	return tokens, reg, nil
}

// Refresh exchanges a refresh token. Returns ErrReauthRequired if the
// upstream rejects it, so the caller can fall back to Authorize.
func Refresh(ctx context.Context, cfg OAuthConfig, mcpURL string, reg *ClientRegistration, old *TokenSet) (*TokenSet, error) {
	cfg = cfg.withDefaults()
	if reg == nil || old == nil || old.RefreshToken == "" {
		return nil, ErrReauthRequired
	}
	meta, _, err := discover(ctx, cfg, mcpURL)
	if err != nil {
		return nil, err
	}
	ts, err := tokenRequest(ctx, cfg, meta, reg, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {old.RefreshToken},
		"resource":      {mcpURL},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReauthRequired, err)
	}
	if ts.RefreshToken == "" {
		ts.RefreshToken = old.RefreshToken // servers may not rotate
	}
	return ts, nil
}

// ErrReauthRequired means the stored credential is unusable and a human
// must complete consent again.
var ErrReauthRequired = errors.New("upstream/oauth: re-authorization required")

// ─── Helpers ──────────────────────────────────────────────────────────────────

func openBrowser(u string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	case "darwin":
		cmd = exec.Command("open", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	_ = cmd.Start()
}

// redactSecrets scrubs bearer/refresh material from text destined for logs
// or error strings. Error paths must never echo a credential — the first
// live run of this broker did exactly that, which is why this exists.
var secretFieldRe = regexp.MustCompile(`("?(access_token|refresh_token|client_secret|id_token)"?\s*[:=]\s*"?)[^",\s}]+`)

func redactSecrets(s string) string {
	return secretFieldRe.ReplaceAllString(s, "${1}[REDACTED]")
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
