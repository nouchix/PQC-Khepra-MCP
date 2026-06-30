import { NextRequest, NextResponse } from 'next/server';

/**
 * POST /api/auth/update-password
 *
 * Exchanges a Supabase PKCE recovery code for a session, then updates the
 * user's password. Called from the /auth/reset-password page after the user
 * clicks the Supabase email link (which lands with ?code=xxx in query params).
 *
 * Flow:
 *   1. User clicks reset email → lands on /auth/reset-password?code=xxx
 *   2. Page calls POST /api/auth/update-password { code, password }
 *   3. This route exchanges the code for an access_token (PKCE)
 *   4. Uses access_token to PATCH the user's password
 *   5. Returns { ok: true } on success
 *
 * Required env vars:
 *   NEXT_PUBLIC_SUPABASE_URL    — https://xxx.supabase.co
 *   SUPABASE_SERVICE_ROLE_KEY   — for admin token exchange
 */

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL
  || process.env.VITE_SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

export async function POST(req: NextRequest) {
  if (!SUPABASE_URL || !SUPABASE_KEY) {
    return NextResponse.json(
      { error: 'Password update service not configured. Contact support@souhimbou.ai.' },
      { status: 503 }
    );
  }

  const body = await req.json().catch(() => ({}));
  const { code, password } = body as { code?: string; password?: string };

  if (!code || !password) {
    return NextResponse.json({ error: 'code and password are required.' }, { status: 400 });
  }

  if (password.length < 8) {
    return NextResponse.json({ error: 'Password must be at least 8 characters.' }, { status: 400 });
  }

  // Step 1: Exchange PKCE code for access_token + refresh_token
  const tokenRes = await fetch(
    `${SUPABASE_URL}/auth/v1/token?grant_type=pkce`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': SUPABASE_KEY,
      },
      body: JSON.stringify({ auth_code: code }),
    }
  );

  if (!tokenRes.ok) {
    const err = await tokenRes.json().catch(() => ({}));
    const msg = (err as any)?.message || 'Invalid or expired reset link.';
    return NextResponse.json({ error: msg }, { status: 400 });
  }

  const tokens = await tokenRes.json() as { access_token: string; refresh_token?: string };

  // Step 2: Update the user's password using the access_token
  const updateRes = await fetch(
    `${SUPABASE_URL}/auth/v1/user`,
    {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'apikey': SUPABASE_KEY,
        'Authorization': `Bearer ${tokens.access_token}`,
      },
      body: JSON.stringify({ password }),
    }
  );

  if (!updateRes.ok) {
    const err = await updateRes.json().catch(() => ({}));
    const msg = (err as any)?.message || 'Failed to update password.';
    return NextResponse.json({ error: msg }, { status: 400 });
  }

  return NextResponse.json({ ok: true });
}
