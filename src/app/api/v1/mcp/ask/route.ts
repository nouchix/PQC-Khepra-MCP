import { NextRequest, NextResponse } from 'next/server';

/**
 * POST /api/v1/mcp/ask
 * Server-side proxy for the Khepra AI chat panel.
 *
 * Flow: Browser → Vercel /api/v1/mcp/ask → mcp.souhimbou.ai/api/v1/mcp/ask
 *
 * The NLChatPanel calls this endpoint with { query, session_id, max_tools }.
 * We proxy it server-side to avoid CORS and to keep the VPS URL private.
 */
const INTERNAL_API = process.env.ASAF_INTERNAL_API_URL || 'https://mcp.souhimbou.ai';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const url = `${INTERNAL_API}/api/v1/mcp/ask`;

    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'ASAF-Chat-Proxy/1.0',
        // Forward PQC token if present
        ...(req.headers.get('X-Khepra-PQC-Token')
          ? { 'X-Khepra-PQC-Token': req.headers.get('X-Khepra-PQC-Token')! }
          : {}),
      },
      body: JSON.stringify(body),
    });

    const text = await res.text();
    let data: unknown;
    try {
      data = JSON.parse(text);
    } catch {
      // MCP backend returned non-JSON — return a friendly error
      return NextResponse.json(
        {
          answer: 'The KHEPRA intelligence layer is initializing. Please try again in a moment.',
          error: 'parse_error',
          raw: text.slice(0, 200),
        },
        { status: 200 }, // return 200 so the chat panel shows the message gracefully
      );
    }

    if (!res.ok) {
      return NextResponse.json(
        { answer: `Backend error (${res.status}). The KHEPRA MCP server may be restarting.`, ...( typeof data === 'object' ? data : {}) },
        { status: 200 },
      );
    }

    return NextResponse.json(data);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Proxy error';
    return NextResponse.json(
      { answer: `Connection error: ${message}. Ensure the KHEPRA MCP server is running.` },
      { status: 200 },
    );
  }
}
