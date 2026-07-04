-- Migration: Scan Lead Capture
-- Captures email + scan context from the onboarding funnel
-- Apply via: supabase db push  OR  paste in Supabase SQL editor

CREATE TABLE IF NOT EXISTS public.scan_leads (
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  email           text        NOT NULL,
  target_url      text,
  risk_score      numeric(5,2),
  findings_count  integer,
  source          text        NOT NULL DEFAULT 'onboarding',
  converted       boolean     NOT NULL DEFAULT false,   -- true after Stripe checkout
  stripe_session  text,                                  -- checkout session ID on convert
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);

-- Deduplicate by email (upsert on email)
CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_leads_email ON public.scan_leads(email);

-- For pipeline queries
CREATE INDEX IF NOT EXISTS idx_scan_leads_source    ON public.scan_leads(source);
CREATE INDEX IF NOT EXISTS idx_scan_leads_converted ON public.scan_leads(converted);
CREATE INDEX IF NOT EXISTS idx_scan_leads_created   ON public.scan_leads(created_at DESC);

-- Auto-update updated_at
CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END; $$;

CREATE TRIGGER scan_leads_updated_at
  BEFORE UPDATE ON public.scan_leads
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- RLS: service role writes; no anonymous reads
ALTER TABLE public.scan_leads ENABLE ROW LEVEL SECURITY;

-- No public policies = deny all (service role bypasses RLS for API writes)
