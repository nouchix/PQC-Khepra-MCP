-- Migration: KHEPRA License Registry
-- Apply via: supabase db push  OR  paste in Supabase SQL editor

-- License table
CREATE TABLE IF NOT EXISTS public.licenses (
  id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  customer_id       text        NOT NULL,         -- Stripe customer ID (cus_...)
  stripe_sub_id     text        UNIQUE,            -- Stripe subscription ID (sub_...)
  stripe_product_id text,                          -- Stripe product ID for tier lookup
  tier              text        NOT NULL CHECK (tier IN ('community','sovereign','pharaoh')),
  machine_id        text,                          -- optional: hardware fingerprint lock
  license_key       text        UNIQUE NOT NULL,   -- KHRPA-XXXX-XXXX-XXXX
  signed_payload    text        NOT NULL,          -- base64-encoded .adinkhepra JSON
  issued_at         timestamptz NOT NULL DEFAULT now(),
  expires_at        timestamptz NOT NULL,
  revoked_at        timestamptz,                   -- NULL = active
  revoke_reason     text,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now()
);

-- Audit trail
CREATE TABLE IF NOT EXISTS public.license_events (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  license_id  uuid        REFERENCES public.licenses(id) ON DELETE CASCADE,
  event       text        NOT NULL,  -- issued | renewed | revoked | expired | reissued
  actor       text,                  -- 'stripe-webhook' | 'admin' | 'system'
  metadata    jsonb,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_licenses_customer   ON public.licenses(customer_id);
CREATE INDEX IF NOT EXISTS idx_licenses_stripe_sub ON public.licenses(stripe_sub_id);
CREATE INDEX IF NOT EXISTS idx_licenses_key        ON public.licenses(license_key);
CREATE INDEX IF NOT EXISTS idx_license_events_lic  ON public.license_events(license_id);

-- Auto-update updated_at
CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END; $$;

CREATE TRIGGER licenses_updated_at
  BEFORE UPDATE ON public.licenses
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- RLS: service role only for writes; no public reads
ALTER TABLE public.licenses       ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.license_events ENABLE ROW LEVEL SECURITY;

-- No policies = deny all (service role bypasses RLS)
-- Add read policy only if you want a customer portal to query their own license:
-- CREATE POLICY "customers_own_license" ON public.licenses
--   FOR SELECT USING (customer_id = current_setting('request.jwt.claims')::json->>'sub');
