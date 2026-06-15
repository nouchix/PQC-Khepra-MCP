## Security Review Checklist

> This PR template enforces the OWASP Application Security Wayfinder SDLC process.
> Every PR **must** complete Section A. Sections B-D apply based on change type.

---

### A. Required for All PRs

- [ ] I have read the [OWASP Top 10](https://owasp.org/Top10/) and my changes do not introduce any of these risks
- [ ] I have run `go build ./...` locally — build is green
- [ ] No hardcoded credentials, API keys, or secrets (TruffleHog will block if present)
- [ ] No `fmt.Sprintf` / `log.Printf` with `%s` for user-controlled strings — use `%q` instead
- [ ] `filepath.Clean()` + confinement check used for all file paths from user input
- [ ] Error messages do not expose stack traces or internal implementation details

---

### B. For Changes to API / HTTP Handlers

*Applies to: `pkg/api/`, `pkg/gateway/`, `cmd/webhook/`, `pkg/mcp/router.go`*

- [ ] `middleware.SecureHeaders()` is applied at the handler entry point
- [ ] All state-changing endpoints (POST/PUT/DELETE) have CSRF protection or are token-authenticated
- [ ] Input is validated before use (length, type, allowed values)
- [ ] Output is content-type correct and never reflects raw user input as HTML
- [ ] Rate limiting is applied to public endpoints
- [ ] OWASP API Top 10 risks reviewed:
  - [ ] API1: Broken Object Level Authorization — user can only access their own resources
  - [ ] API2: Broken Authentication — JWT/mTLS enforced
  - [ ] API3: Broken Object Property Level Authorization — no mass-assignment
  - [ ] API4: Unrestricted Resource Consumption — rate limiting + size limits
  - [ ] API5: Function Level Authorization — admin endpoints require elevated roles
  - [ ] API8: Security Misconfiguration — no debug endpoints exposed

---

### C. For Changes to Cryptographic Code

*Applies to: `pkg/adinkra/`, `pkg/license/`, any PQC-related files*

- [ ] No MD5, SHA-1, RC4, DES, or 3DES used for security purposes
- [ ] No `math/rand` used for security-sensitive randomness — use `crypto/rand`
- [ ] No modulo bias in random number generation — rejection-sampling used
- [ ] Keys are not logged, stored in plain text, or embedded in source
- [ ] PQC algorithms are NIST-standardized (Kyber/ML-KEM, Dilithium/ML-DSA)

---

### D. For Changes to Go File Operations

*Applies to any `os.Open`, `os.ReadFile`, `os.Create`, `filepath.Join`*

- [ ] All paths from user/external input go through `filepath.Clean()` + prefix confinement check
- [ ] File handles are closed with error checking (not `defer f.Close()` alone)
- [ ] No zip/tar extraction without zip-slip protection (`strings.HasPrefix` after `filepath.Join`)
- [ ] Temp files use `os.CreateTemp()` with appropriate permissions

---

### E. For Changes to Authentication / Session Management

*Applies to: `pkg/gateway/layer2_auth.go`, `pkg/sekhem/`, session-related code*

- [ ] Tokens are generated with `crypto/rand` (not `math/rand`)
- [ ] Session IDs have sufficient entropy (>= 128 bits)
- [ ] Login failures do not reveal whether the username or password was wrong
- [ ] Account lockout or rate limiting prevents brute force

---

### F. For Dependency Changes (`go.mod`, `package.json`)

- [ ] New dependency has been reviewed for known CVEs (run `go mod audit` or check Grype output)
- [ ] New dependency license is compatible with project license
- [ ] Dependency is actively maintained (check last commit date)
- [ ] Dependency does not introduce a transitive GPL dependency into proprietary code

---

### Reviewer Security Checklist

Before approving:

- [ ] Reviewed for OWASP Top 10 risks
- [ ] Verified no secrets or PII in code or test fixtures
- [ ] Confirmed CodeQL / Trivy CI gates are green
- [ ] Security-sensitive changes (crypto, auth, file ops) have a second security reviewer

---

**References:**
- [OWASP Top 10](https://owasp.org/Top10/)
- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP Proactive Controls](https://owasp.org/www-project-proactive-controls/)
- [Go Secure Coding Practices](https://github.com/OWASP/Go-SCP)
- [ASVS Level 2 Requirements](https://owasp.org/www-project-application-security-verification-standard/)
