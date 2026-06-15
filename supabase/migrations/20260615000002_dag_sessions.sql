-- Migration: DAG Sessions, Nodes, and Edges for SouHimBou Flight Recorder
-- Extends the licenses schema from 20260615000001_licenses.sql
-- RLS: tenants see only their own data
-- Realtime: dag_nodes and dag_edges are published for live SSE fallback

-- ── Tables ──────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.dag_sessions (
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid        NOT NULL,
  license_key     text        REFERENCES public.licenses(license_key) ON DELETE SET NULL,
  session_ref     text        UNIQUE NOT NULL,
  status          text        NOT NULL DEFAULT 'running'
                              CHECK (status IN ('running', 'complete', 'failed')),
  tool_calls      int         NOT NULL DEFAULT 0,
  findings        int         NOT NULL DEFAULT 0,
  attestations    int         NOT NULL DEFAULT 0,
  controls_mapped int         NOT NULL DEFAULT 0,
  asaf_mode       text        NOT NULL DEFAULT 'cloud'
                              CHECK (asaf_mode IN ('cloud', 'sovereign')),
  metadata        jsonb,
  started_at      timestamptz NOT NULL DEFAULT now(),
  completed_at    timestamptz
);

CREATE TABLE IF NOT EXISTS public.dag_nodes (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id uuid        NOT NULL REFERENCES public.dag_sessions(id) ON DELETE CASCADE,
  node_ref   text        NOT NULL,
  label      text        NOT NULL,
  type       text        NOT NULL CHECK (type IN ('prompt', 'tool', 'finding', 'control', 'attest')),
  severity   text        CHECK (severity IN ('CAT_I', 'CAT_II', 'CAT_III')),
  payload    jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (session_id, node_ref)
);

CREATE TABLE IF NOT EXISTS public.dag_edges (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id uuid        NOT NULL REFERENCES public.dag_sessions(id) ON DELETE CASCADE,
  source_ref text        NOT NULL,
  target_ref text        NOT NULL,
  weight     int         NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- ── Indexes ──────────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_dag_nodes_session  ON public.dag_nodes(session_id);
CREATE INDEX IF NOT EXISTS idx_dag_edges_session  ON public.dag_edges(session_id);
CREATE INDEX IF NOT EXISTS idx_dag_sessions_tenant ON public.dag_sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_dag_sessions_license ON public.dag_sessions(license_key);
CREATE INDEX IF NOT EXISTS idx_dag_sessions_status  ON public.dag_sessions(status);

-- ── RLS ───────────────────────────────────────────────────────────────────────

ALTER TABLE public.dag_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dag_nodes    ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dag_edges    ENABLE ROW LEVEL SECURITY;

-- Tenant isolation via JWT claim
CREATE POLICY "tenant_own_sessions" ON public.dag_sessions
  FOR ALL USING (
    tenant_id = (current_setting('request.jwt.claims', true)::jsonb ->> 'tenant_id')::uuid
  );

CREATE POLICY "tenant_own_nodes" ON public.dag_nodes
  FOR ALL USING (
    session_id IN (
      SELECT id FROM public.dag_sessions
      WHERE tenant_id = (current_setting('request.jwt.claims', true)::jsonb ->> 'tenant_id')::uuid
    )
  );

CREATE POLICY "tenant_own_edges" ON public.dag_edges
  FOR ALL USING (
    session_id IN (
      SELECT id FROM public.dag_sessions
      WHERE tenant_id = (current_setting('request.jwt.claims', true)::jsonb ->> 'tenant_id')::uuid
    )
  );

-- ── Realtime publication ──────────────────────────────────────────────────────
-- Used as SSE fallback when agent.souhimbou.ai is the cloud endpoint

ALTER PUBLICATION supabase_realtime ADD TABLE public.dag_nodes;
ALTER PUBLICATION supabase_realtime ADD TABLE public.dag_edges;
ALTER PUBLICATION supabase_realtime ADD TABLE public.dag_sessions;

-- ── Helper: upsert session stats ──────────────────────────────────────────────

CREATE OR REPLACE FUNCTION public.dag_increment_stats(
  p_session_id   uuid,
  p_tool_calls   int DEFAULT 0,
  p_findings     int DEFAULT 0,
  p_attestations int DEFAULT 0,
  p_controls     int DEFAULT 0
) RETURNS void LANGUAGE sql AS $$
  UPDATE public.dag_sessions SET
    tool_calls      = tool_calls      + p_tool_calls,
    findings        = findings        + p_findings,
    attestations    = attestations    + p_attestations,
    controls_mapped = controls_mapped + p_controls
  WHERE id = p_session_id;
$$;
