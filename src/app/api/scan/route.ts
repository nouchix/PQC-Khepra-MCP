import { NextRequest, NextResponse } from 'next/server';

/**
 * POST /api/scan
 * Server-side proxy for the KHEPRA MCP onboarding scan endpoint.
 *
 * The MCP backend (pkg/mcp/onboarding.go) is SYNCHRONOUS — it returns the full
 * ScanResult in the POST response body. No polling is needed.
 *
 * MCP returns:
 *   { scan_id, status, timestamp, target, summary: { risk_score (0-10), exposed_tools, attestation_gap, fips_compliant }, findings: [{ id, severity, title, control }], pqc_signed, cta }
 *
 * We transform this to the shape the OnboardingOrchestrator UI expects:
 *   { scan_id, risk_score (0-100), exposed, auth_weakness, open_integrations, findings: [{ severity, text }], certified }
 *
 * Why proxy?
 *   1. No CORS — browser calls Vercel, not the VPS directly
 *   2. ASAF_INTERNAL_API_URL never exposed to client
 *   3. Caddy/SEKHEM gateway on the VPS handles auth
 */
const INTERNAL_API = process.env.ASAF_INTERNAL_API_URL || 'https://mcp.souhimbou.ai';

interface MCPScanFinding {
  id?: string;
  severity?: string;
  title?: string;
  control?: string;
}

interface MCPScanResult {
  scan_id?: string;
  status?: string;
  target?: string;
  summary?: {
    risk_score?: number;       // 0.0–10.0
    exposed_tools?: number;
    attestation_gap?: boolean;
    fips_compliant?: boolean;
  };
  findings?: MCPScanFinding[];
  pqc_signed?: boolean;
  cta?: unknown;
  // Legacy apiserver shape (in case backend is different build)
  risk_score?: number;         // 0–100
  exposed?: boolean;
  auth_weakness?: boolean;
  open_integrations?: number;
  certified?: boolean;
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const url = `${INTERNAL_API}/api/v1/onboarding/scan`;

    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'ASAF-Onboarding-Proxy/1.0',
      },
      body: JSON.stringify(body),
    });

    const text = await res.text();
    let data: MCPScanResult;
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

    // ── Transform MCP response → UI-expected shape ──────────────────────────
    // Handle both the pkg/mcp/onboarding.go response (summary.risk_score 0-10)
    // and the pkg/apiserver/handlers.go response (risk_score 0-100, certified).
    const isMCPShape = data.summary !== undefined || data.pqc_signed !== undefined;

    const transformed = isMCPShape
      ? {
          // Standard scan_id for any downstream polling attempts
          scan_id: data.scan_id ?? 'local',
          // Convert 0-10 → 0-100
          risk_score: Math.round((data.summary?.risk_score ?? 5) * 10),
          exposed: (data.summary?.exposed_tools ?? 0) > 0,
          auth_weakness: data.summary?.attestation_gap ?? false,
          open_integrations: data.summary?.exposed_tools ?? 0,
          findings: (data.findings ?? []).map((f) => ({
            severity: f.severity ?? 'medium',
            text: f.title ?? 'Unknown finding',
          })),
          // Signal to UI: result is complete — skip polling
          certified: false,
          // Extra context for upgrade CTA
          pqc_signed: data.pqc_signed ?? false,
          cta: data.cta,
          status: data.status ?? 'complete',
        }
      : data; // Already in UI shape (apiserver saas build)

    return NextResponse.json(transformed);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Internal proxy error';
    return NextResponse.json(
      { error: 'scan_proxy_error', message, target: INTERNAL_API },
      { status: 502 },
    );
  }
}
