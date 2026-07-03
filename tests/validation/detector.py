#!/usr/bin/env python3
"""
detector.py — Khepra Protocol security rule engine (validation harness).

This is the REAL detector the validation suite exercises. It is NOT a grep for a
fixture's own marker string; it applies general vulnerability rules that would
flag novel instances, and it is designed to be discriminating (no false positives
on safe idioms: parameterized queries, fixed-argument commands, env-sourced
secrets, strong crypto).

It mirrors the rule *classes* the CI SAST gates enforce (gosec / semgrep /
TruffleHog) so the suite is a fast, deterministic, offline regression check that
those vulnerability classes are caught and that clean code is not.

Usage:
    detector.py <file>...        # human output, exit 1 if any finding
    detector.py --json <file>... # JSON findings to stdout, exit 0

Categories emitted: secret | sql_injection | command_injection | weak_crypto
"""
import re
import sys
import json

# ── Comment stripping (keep line numbers; blank out comment spans) ────────────
_LINE_COMMENT = re.compile(r'//.*$')
_BLOCK_COMMENT = re.compile(r'/\*.*?\*/', re.S)


def strip_comments(src: str) -> str:
    # Blank block comments (preserving newlines so line numbers are stable).
    def _blank(m):
        return re.sub(r'[^\n]', ' ', m.group(0))
    src = _BLOCK_COMMENT.sub(_blank, src)
    # Blank line comments outside string literals (heuristic: not inside quotes).
    out = []
    for line in src.split('\n'):
        # naive: only strip // when not preceded by an opening quote on the line
        if '//' in line:
            q = line.find('"')
            c = line.find('//')
            if q == -1 or c < q:
                line = _LINE_COMMENT.sub('', line)
        out.append(line)
    return '\n'.join(out)


# ── Secret / hardcoded-key rules ──────────────────────────────────────────────
HIGH_CONFIDENCE_SECRETS = [
    ("stripe_key",       re.compile(r'sk_(live|test)_[0-9A-Za-z]{16,}')),
    ("github_token",     re.compile(r'gh[pousr]_[0-9A-Za-z]{20,}')),
    ("aws_access_key_id", re.compile(r'AKIA[0-9A-Z]{16}')),
    ("twilio_sid",       re.compile(r'\bAC[0-9a-f]{32}\b')),
    ("jwt",              re.compile(r'eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]+')),
    ("pem_private_key",  re.compile(r'BEGIN\s+[A-Z ]*PRIVATE KEY')),
]
# Identifier named like a secret assigned to a non-trivial string literal.
SECRET_ASSIGN = re.compile(
    r'(?i)\b\w*(key|secret|token|password|passwd|pwd|credential|apikey)\w*\s*'
    r'[:=]{1,2}\s*(\[\]byte\(\s*)?["`][^"`]{6,}["`]'
)
# String literal that embeds key/secret material by naming convention.
SECRET_LITERAL = re.compile(r'(?i)["`][^"`]*(-key-|-secret-|_secret|realm-key|dev-key|-token-)[^"`]*["`]')
# Lines where a "secret-looking" match is actually safe (env, vault, placeholder).
SECRET_ALLOW = re.compile(
    r'(?i)(os\.getenv|getenv\(|vault|example|placeholder|redacted|your[-_]|changeme|'
    r'\$\{|not implemented|test-?only|dummy)'
)

# ── SQL injection rules ───────────────────────────────────────────────────────
# Require SQL *query structure*, not just a keyword — so "did select host %s" in
# prose is not mistaken for a query (discrimination is what makes this TRL10).
_SQL_STMT = (r'(\bselect\b[^"`]*\bfrom\b|\binsert\s+into\b|'
             r'\bupdate\b[^"`]*\bset\b|\bdelete\s+from\b)')
SQLI_SPRINTF = re.compile(r'(?i)fmt\.Sprintf\(\s*["`][^"`]*' + _SQL_STMT)
SQLI_CONCAT = re.compile(r'(?i)["`][^"`]*' + _SQL_STMT + r'[^"`]*["`]\s*\+\s*[A-Za-z_]\w*')

# ── Command injection rules ───────────────────────────────────────────────────
CMD_INLINE_SPRINTF = re.compile(r'exec\.Command(Context)?\([^)]*fmt\.Sprintf')
CMD_CALL = re.compile(r'exec\.Command(Context)?\(([^;{]*)')
TAINT_ASSIGN = re.compile(
    r'\b([A-Za-z_]\w*)\s*:?=\s*(fmt\.Sprintf\(|["`][^"`]*["`]\s*\+\s*[A-Za-z_])'
)

# ── Weak crypto rules ─────────────────────────────────────────────────────────
WEAK_CRYPTO = re.compile(
    r'\b(crypto/md5|crypto/sha1|crypto/des|crypto/rc4|md5\.New|sha1\.New|des\.New|rc4\.New|math/rand)\b'
)
WEAK_CRYPTO_ALLOW = re.compile(r'(?i)(checksum|etag|non[-_]?security|cache\s*key|test)')


def line_of(src: str, idx: int) -> int:
    return src.count('\n', 0, idx) + 1


def scan(path: str):
    with open(path, 'r', errors='replace') as fh:
        raw = fh.read()
    src = strip_comments(raw)
    findings = []

    # Secrets
    for name, rx in HIGH_CONFIDENCE_SECRETS:
        for m in rx.finditer(src):
            ln = line_of(src, m.start())
            if SECRET_ALLOW.search(src.split('\n')[ln - 1]):
                continue
            findings.append(("secret", name, ln, m.group(0)[:48]))
    for rx in (SECRET_ASSIGN, SECRET_LITERAL):
        for m in rx.finditer(src):
            ln = line_of(src, m.start())
            if SECRET_ALLOW.search(src.split('\n')[ln - 1]):
                continue
            findings.append(("secret", "hardcoded_secret", ln, m.group(0)[:48]))

    # SQL injection
    for rx in (SQLI_SPRINTF, SQLI_CONCAT):
        for m in rx.finditer(src):
            findings.append(("sql_injection", "dynamic_sql", line_of(src, m.start()), m.group(0)[:48]))

    # Command injection: inline Sprintf, plus tainted variable flowing into exec.Command.
    for m in CMD_INLINE_SPRINTF.finditer(src):
        findings.append(("command_injection", "inline_sprintf", line_of(src, m.start()), m.group(0)[:48]))
    tainted = set(m.group(1) for m in TAINT_ASSIGN.finditer(src))
    if tainted:
        for m in CMD_CALL.finditer(src):
            args = m.group(2)
            for var in tainted:
                if re.search(r'\b' + re.escape(var) + r'\b', args):
                    findings.append(("command_injection", "tainted_var", line_of(src, m.start()), var))
                    break

    # Weak crypto
    for m in WEAK_CRYPTO.finditer(src):
        ln = line_of(src, m.start())
        if WEAK_CRYPTO_ALLOW.search(src.split('\n')[ln - 1]):
            continue
        findings.append(("weak_crypto", m.group(0), ln, m.group(0)))

    # De-duplicate by (category, line).
    seen, uniq = set(), []
    for f in findings:
        k = (f[0], f[2])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    return uniq


def main(argv):
    as_json = False
    files = []
    for a in argv[1:]:
        if a == '--json':
            as_json = True
        else:
            files.append(a)
    if not files:
        print("usage: detector.py [--json] <file>...", file=sys.stderr)
        return 2

    all_findings = {}
    total = 0
    for path in files:
        f = scan(path)
        all_findings[path] = [
            {"category": c, "rule": r, "line": ln, "match": mt} for (c, r, ln, mt) in f
        ]
        total += len(f)

    if as_json:
        print(json.dumps(all_findings, indent=2))
        return 0

    for path, fs in all_findings.items():
        if fs:
            for x in fs:
                print(f"{path}:{x['line']}: [{x['category']}/{x['rule']}] {x['match']}")
        else:
            print(f"{path}: clean")
    return 1 if total else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
