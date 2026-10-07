# Issuer certificates

Signed issuer certificates (`*.json`) placed here are compiled into the
binary. Each delegates license or API-key signing to an online issuer key.
They are public. Every certificate is verified against the pinned root
(`MasterPublicKey`) before use, so a file here cannot widen trust on its own.

Create one with `go run ./cmd/root-ceremony delegate ...` on the offline
ceremony machine; see `cmd/root-ceremony`.
