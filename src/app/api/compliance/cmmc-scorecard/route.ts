import { NextResponse } from 'next/server';

/**
 * GET /api/compliance/cmmc-scorecard
 *
 * Vercel → Fly.io proxy for the CMMC 3.0 Scorecard.
 * The Go API server (souhimbou-ai on Fly.io) runs the full
 * STIG→CCI→NIST 800-53→800-171→CMMC mapping chain and returns
 * a structured scorecard with per-domain scores.
 *
 * Deployment topology:
 *   Browser → Vercel (this route) → Fly.io Go API → embedded STIG DB
 */

const INTERNAL_API = process.env.ASAF_INTERNAL_API_URL || 'http://172.19.0.1:45444';

export async function GET(request: Request) {
  try {
    // Forward auth header from the client
    const authHeader = request.headers.get('Authorization') || '';

    const res = await fetch(`${INTERNAL_API}/api/v1/compliance/cmmc-scorecard`, {
      method: 'GET',
      headers: {
        'Authorization': authHeader,
        'Content-Type': 'application/json',
        'X-Forwarded-For': request.headers.get('x-forwarded-for') || 'vercel-proxy',
      },
      // 30s timeout for full STIG validation run
      signal: AbortSignal.timeout(30000),
    });

    if (!res.ok) {
      const errorBody = await res.text();
      return NextResponse.json(
        { error: `Upstream error: ${res.status}`, details: errorBody },
        { status: res.status }
      );
    }

    const data = await res.json();

    return NextResponse.json(data, {
      headers: {
        'Cache-Control': 'private, max-age=60', // Cache for 1 min (scorecard doesn't change every second)
        'X-Khepra-Engine': 'AdinKhepra-Vercel-Proxy/v1',
      },
    });
  } catch (error: any) {
    // If the Go server is unreachable, return a graceful fallback
    if (error?.name === 'AbortError' || error?.cause?.code === 'ECONNREFUSED') {
      return NextResponse.json(
        {
          error: 'CMMC engine unavailable',
          message: 'The compliance engine is not reachable. Ensure the SEKHEM Gateway is running.',
          fallback: true,
        },
        { status: 503 }
      );
    }

    return NextResponse.json(
      { error: 'Internal proxy error', message: error?.message },
      { status: 500 }
    );
  }
}
