import { NextRequest, NextResponse } from 'next/server';

/**
 * POST /api/auth/reset-password
 *
 * Triggers a Supabase password reset email server-side.
 * The ASAF stub client (integrations/supabase/client.ts) is a no-op —
 * this route makes the real Supabase Auth REST call so emails actually get sent.
 *
 * Required env vars (Vercel):
 *   NEXT_PUBLIC_SUPABASE_URL     — https://xxx.supabase.co
 *   SUPABASE_SERVICE_ROLE_KEY    — service_role key (used as apikey for auth calls)
 *
 * Supabase dashboard config required:
 *   Authentication → URL Configuration → Redirect URLs:
 *     Add https://souhimbou.ai/auth/reset-password
 *     Add https://www.souhimbou.ai/auth/reset-password
 */

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL
  || process.env.VITE_SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

export async function POST(req: NextRequest) {
  if (!SUPABASE_URL || !SUPABASE_KEY) {
    // Graceful degradation: log and return success so the UI doesn't break.
    // The admin must configure Supabase env vars in Vercel for email to work.
    console.error('[reset-password] Missing NEXT_PUBLIC_SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY');
    return NextResponse.json(
      { error: 'Email service not configured. Please contact support@souhimbou.ai for a manual password reset.' },
      { status: 503 }
    );
  }

  const body = await req.json().catch(() => ({}));
  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return NextResponse.json({ error: 'A valid email address is required.' }, { status: 400 });
  }

  // Determine redirect URL — where Supabase sends the user after clicking the link.
  // This must be in Supabase's allowlist: Auth → URL Configuration → Redirect URLs.
  const origin = req.headers.get('origin')
    || process.env.NEXT_PUBLIC_APP_URL
    || 'https://souhimbou.ai';
  const redirectTo = `${origin}/auth/reset-password`;

  // POST to Supabase GoTrue /recover endpoint.
  // The service role key is accepted as the apikey header for this endpoint.
  const supabaseRes = await fetch(
    `${SUPABASE_URL}/auth/v1/recover`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': SUPABASE_KEY,
        'Authorization': `Bearer ${SUPABASE_KEY}`,
      },
      body: JSON.stringify({ email, options: { redirectTo } }),
    }
  );

  // Supabase returns 200 even if the email doesn't exist (security by design).
  // Only surface real errors.
  if (!supabaseRes.ok && supabaseRes.status !== 404) {
    const err = await supabaseRes.json().catch(() => ({}));
    const msg = (err as any)?.message || `Supabase error ${supabaseRes.status}`;
    console.error('[reset-password] Supabase error:', msg);
    return NextResponse.json({ error: msg }, { status: 502 });
  }

  return NextResponse.json({ ok: true });
}
