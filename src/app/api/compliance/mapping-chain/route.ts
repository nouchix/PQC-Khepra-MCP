import { NextResponse } from 'next/server';

/**
 * GET /api/compliance/mapping-chain
 *
 * Vercel → Fly.io proxy for the CMMC mapping chain statistics.
 * Shows the full traceability from STIG→CCI→NIST 800-53→800-171→CMMC.
 */

const INTERNAL_API = process.env.ASAF_INTERNAL_API_URL || 'http://172.19.0.1:45444';

export async function GET(request: Request) {
  try {
    const authHeader = request.headers.get('Authorization') || '';

    const res = await fetch(`${INTERNAL_API}/api/v1/compliance/mapping-chain`, {
      method: 'GET',
      headers: {
        'Authorization': authHeader,
        'Content-Type': 'application/json',
      },
      signal: AbortSignal.timeout(10000),
    });

    if (!res.ok) {
      return NextResponse.json({ error: `Upstream: ${res.status}` }, { status: res.status });
    }

    return NextResponse.json(await res.json(), {
      headers: { 'Cache-Control': 'public, max-age=3600' }, // Cache 1hr — static data
    });
  } catch {
    return NextResponse.json({ error: 'Compliance engine unavailable' }, { status: 503 });
  }
}
