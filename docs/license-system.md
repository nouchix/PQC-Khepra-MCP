# KHEPRA License System — Deployment Guide

## Quick Start

### 1. Supabase — Apply Migration
```bash
# Option A: Supabase CLI
supabase db push --db-url postgresql://...

# Option B: Paste into Supabase SQL editor
# → supabase/migrations/20260615000001_licenses.sql
```

### 2. Supabase — Set Secrets
```bash
supabase secrets set \
  STRIPE_SECRET_KEY=sk_live_... \
  STRIPE_WEBHOOK_SECRET=whsec_... \
  KHEPRA_SIGNING_KEY_B64=$(base64 -w0 pkg/license/keys/khepra_signing.priv) \
  RESEND_API_KEY=re_...
```

### 3. Deploy Edge Function
```bash
supabase functions deploy generate-license --no-verify-jwt
```

### 4. Register Stripe Webhook
In Stripe Dashboard → Webhooks → Add endpoint:
- URL: `https://<your-project>.supabase.co/functions/v1/generate-license`
- Events:
  - `checkout.session.completed`
  - `invoice.payment_succeeded`
  - `customer.subscription.deleted`
  - `customer.subscription.updated`

### 5. Generate Signing Keypair (one-time)
```bash
# TODO: implement once cloudflare/circl is integrated
go run ./cmd/khepra-admin keygen --output pkg/license/keys/khepra_signing

# Then update the embedded key in the binary:
# pkg/license/keys/khepra_signing.pub → committed to repo (public key only)
# pkg/license/keys/khepra_signing.priv → NEVER commit, store in secrets vault
```

### 6. Build Admin CLI
```bash
go build -o bin/khepra-admin ./cmd/khepra-admin

# Usage:
export SUPABASE_URL=https://xxx.supabase.co
export SUPABASE_SERVICE_ROLE_KEY=eyJ...

./bin/khepra-admin license list --tier sovereign
./bin/khepra-admin license revoke --key KHRPA-XXXX-XXXX-XXXX-XXXX --reason "payment_dispute"
```

### 7. Local Stripe Webhook Testing
```bash
# Install Stripe CLI: https://stripe.com/docs/stripe-cli
stripe login
stripe listen --forward-to https://<project>.supabase.co/functions/v1/generate-license

# Trigger test events:
stripe trigger checkout.session.completed
stripe trigger invoice.payment_succeeded
stripe trigger customer.subscription.deleted
```

## What Happens When a Customer Buys

1. Customer completes Stripe Checkout
2. Stripe fires `checkout.session.completed` webhook
3. Edge Function generates and signs the license with ML-DSA-65 private key
4. **API key** (`kphr_{tier}_{base64url-payload}`) is emailed to customer via Resend
   — `.adinkhepra` file is attached for air-gap / SCIF customers
5. Connected customers: add to `.env`:
   ```
   KHEPRA_LICENSE_KEY=kphr_sov_eyJ...
   ```
6. Air-gap / SCIF customers: transfer `.adinkhepra` via approved media, then:
   ```
   KHEPRA_LICENSE_PATH=/etc/khepra/license.adinkhepra
   ```
7. `khepra-mcp` validates signature against embedded public key at startup
   — `KHEPRA_LICENSE_KEY` is checked first; `KHEPRA_LICENSE_PATH` is the fallback

## Air-Gap / SCIF Delivery

For classified environments that can't receive email:
```bash
# Admin generates and downloads the license file manually:
./bin/khepra-admin license status --key KHRPA-XXXX-XXXX-XXXX-XXXX

# Transfer via approved media to the air-gapped system
```

## Revocation

```bash
# Immediate revocation (e.g., payment dispute)
./bin/khepra-admin license revoke \
  --key KHRPA-XXXX-XXXX-XXXX-XXXX \
  --reason "chargeback"

# Stripe cancellation auto-revokes via webhook
# (customer.subscription.deleted event)
```

Revoked licenses still pass signature validation but online mode
additionally checks the revocation endpoint. Air-gapped systems
rely on natural expiry — do not renew the license file.

## TODO: Replace HMAC with ML-DSA-65

The current implementation uses HMAC-SHA256 as a placeholder.
To upgrade to real ML-DSA-65:

```bash
go get github.com/cloudflare/circl
```

Then update `pkg/license/validator.go`:
```go
import "github.com/cloudflare/circl/sign/mldsa/mldsa65"

// Replace verifySignature():
scheme := mldsa65.Scheme()
pub, err := scheme.UnmarshalBinaryPublicKey(embeddedPublicKey)
if err != nil { return err }
if !scheme.Verify(pub, payloadJSON, sig, nil) {
    return fmt.Errorf("signature mismatch")
}
```
