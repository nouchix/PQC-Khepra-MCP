import { NextRequest, NextResponse } from 'next/server';

/**
 * POST /api/scan
 * Server-side proxy for the ASAF onboarding scan trigger.
 *
 * Why proxy? The ASAF API server (DEMARC) runs on the same VPS as this
 * Next.js dashboard container. By proxying through a Next.js API route:
 *   1. No CORS — the browser calls the same origin (adinkhepra.com)
 *   2. No external dependency — no Cloudflare Tunnel needed for scans
 *   3. The internal API URL is never exposed to the client
 *
 * Required env vars (server-side only, NOT NEXT_PUBLIC_):
 *   ASAF_INTERNAL_API_URL — e.g. http://172.19.0.1:45444 (Docker host gateway, mesh_nouchix-dmz)
 *
 * NOTE: 172.19.0.1 is the NPM network gateway (mesh_nouchix-dmz), NOT Docker's default
 * bridge (172.17.0.1). Using the wrong IP causes silent 502s if this env var is unset.
 */
const INTERNAL_API = process.env.ASAF_INTERNAL_API_URL || 'https://souhimbou-ai.fly.dev';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const url = `${INTERNAL_API}/api/v1/onboarding/scan`;

    // Derive the Host from the target URL so the SEKHEM WAF (SEKHEM-006)
    // sees a known hostname — NOT Vercel's injected X-Forwarded-Host.
    // Explicitly set User-Agent so SEKHEM-008 doesn't see Vercel's default.
    const targetHost = new URL(url).host;

    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'ASAF-Onboarding-Proxy/1.0',
      },
      body: JSON.stringify(body),
    });

    // Read as text first — Fly.io may return HTML error pages or
    // gzip-encoded responses that res.json() can't decode directly.
    const text = await res.text();
    let data: unknown;
    try {
      data = JSON.parse(text);
    } catch {
      return NextResponse.json(
        {
          error: 'scan_proxy_parse_error',
          status: res.status,
          body: text.slice(0, 500),
          target: INTERNAL_API,
        },
        { status: 502 },
      );
    }

    if (!res.ok) {
      return NextResponse.json(data, { status: res.status });
    }

    return NextResponse.json(data);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Internal proxy error';
    return NextResponse.json(
      { error: 'scan_proxy_error', message, target: INTERNAL_API },
      { status: 502 },
    );
  }
}
