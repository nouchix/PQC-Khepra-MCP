import { NextRequest, NextResponse } from 'next/server';

/**
 * GET /api/scan/[id]
 * Server-side proxy for polling scan status from the ASAF API.
 */
// NOTE: 172.19.0.1 is the NPM network gateway (mesh_nouchix-dmz), NOT Docker's default
// bridge (172.17.0.1). Using the wrong IP causes silent 502s if ASAF_INTERNAL_API_URL is unset.
const INTERNAL_API = process.env.ASAF_INTERNAL_API_URL || 'https://souhimbou-ai.fly.dev';

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const { id } = await params;
    const url = `${INTERNAL_API}/api/v1/onboarding/scan/${id}`;
    const targetHost = new URL(url).host;

    const res = await fetch(url, {
      headers: {
        'Host': targetHost,
        'User-Agent': 'ASAF-Onboarding-Proxy/1.0',
      },
    });

    const data = await res.json();

    if (!res.ok) {
      return NextResponse.json(data, { status: res.status });
    }

    return NextResponse.json(data);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Internal proxy error';
    return NextResponse.json(
      { error: 'scan_proxy_error', message },
      { status: 502 },
    );
  }
}
