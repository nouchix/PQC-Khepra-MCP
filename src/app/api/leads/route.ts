import { NextRequest, NextResponse } from 'next/server';

/**
 * POST /api/leads
 * Captures email + scan context for pipeline nurture.
 *
 * Body: { email, target_url, risk_score, findings_count, source }
 *
 * Writes to:
 *   1. Supabase (scan_leads table) — always attempted
 *   2. HubSpot contact — if HUBSPOT_API_KEY is set
 *
 * Required env vars:
 *   NEXT_PUBLIC_SUPABASE_URL        — https://xxx.supabase.co
 *   SUPABASE_SERVICE_ROLE_KEY       — service_role key (bypasses RLS)
 *
 * Optional:
 *   HUBSPOT_API_KEY                 — private app token
 */

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const HUBSPOT_KEY  = process.env.HUBSPOT_API_KEY;

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}));
  const { email, target_url, risk_score, findings_count, source = 'onboarding' } = body;

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return NextResponse.json({ error: 'valid email required' }, { status: 400 });
  }

  const results: Record<string, string> = {};

  // 1. Supabase insert
  if (SUPABASE_URL && SUPABASE_KEY) {
    try {
      const res = await fetch(`${SUPABASE_URL}/rest/v1/scan_leads`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'apikey': SUPABASE_KEY,
          'Authorization': `Bearer ${SUPABASE_KEY}`,
          'Prefer': 'resolution=merge-duplicates',
        },
        body: JSON.stringify({
          email,
          target_url: target_url || null,
          risk_score: risk_score ?? null,
          findings_count: findings_count ?? null,
          source,
        }),
      });
      results.supabase = res.ok ? 'ok' : `error:${res.status}`;
    } catch (e) {
      results.supabase = `exception:${e instanceof Error ? e.message : 'unknown'}`;
    }
  } else {
    results.supabase = 'skipped:no_config';
  }

  // 2. HubSpot contact upsert
  if (HUBSPOT_KEY) {
    try {
      const res = await fetch('https://api.hubapi.com/crm/v3/objects/contacts', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${HUBSPOT_KEY}`,
        },
        body: JSON.stringify({
          properties: {
            email,
            hs_lead_status: 'NEW',
            lifecyclestage: 'lead',
            // Custom properties (add these in HubSpot settings if needed):
            souhimbou_target_url: target_url || '',
            souhimbou_risk_score: String(risk_score ?? ''),
            souhimbou_source: source,
          },
        }),
      });
      // 409 = already exists — that's fine
      results.hubspot = (res.ok || res.status === 409) ? 'ok' : `error:${res.status}`;
    } catch (e) {
      results.hubspot = `exception:${e instanceof Error ? e.message : 'unknown'}`;
    }
  } else {
    results.hubspot = 'skipped:no_config';
  }

  return NextResponse.json({ ok: true, results });
}
