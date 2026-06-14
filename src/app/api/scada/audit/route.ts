import { NextResponse } from 'next/server';

const AGENT = process.env.AGENT_URL ?? 'http://localhost:45444';

export async function GET() {
  try {
    const res = await fetch(`${AGENT}/api/scada/audit`, {
      next: { revalidate: 0 },
      signal: AbortSignal.timeout(3000),
    });
    const data = await res.json();
    return NextResponse.json(data);
  } catch (err) {
    return NextResponse.json(
      { risk_level: 'UNKNOWN', channels: [], findings: [], error: String(err) },
      { status: 503 }
    );
  }
}
