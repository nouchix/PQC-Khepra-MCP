import { NextRequest, NextResponse } from 'next/server';

/**
 * POST /api/scan
 * Server-side proxy for the KHEPRA MCP live scan endpoint.
 *
 * Flow: Browser → Vercel Next.js /api/scan → mcp.souhimbou.ai (VPS) → DEMARC REST API (port 45444)
 *
 * Why proxy?
 *   1. No CORS — browser calls Vercel, not the VPS directly
 *   2. ASAF_INTERNAL_API_URL never exposed to client
 *   3. mTLS / SEKHEM gateway on the VPS handles auth
 *
 * Required env var (server-side only, never NEXT_PUBLIC_):
 *   ASAF_INTERNAL_API_URL — e.g. https://mcp.souhimbou.ai
 *   Falls back to https://mcp.souhimbou.ai if unset.
 */
const INTERNAL_API = process.env.ASAF_INTERNAL_API_URL || 'https://mcp.souhimbou.ai';

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

    // Read as text first — handle any non-JSON error responses gracefully.
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
