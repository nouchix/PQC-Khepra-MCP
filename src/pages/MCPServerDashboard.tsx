import { useState, useEffect } from 'react';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ToolStatus {
  name: string;
  category: string;
  tier: 'community' | 'enterprise' | 'sovereign';
  lastCalledAt: string | null;
  callCount: number;
  lastScore?: number;
  scoreLabel?: string;
  scoreColor?: string;
  status: 'idle' | 'running' | 'pass' | 'fail' | 'warn';
  latencyMs?: number;
}

interface MCPServerInfo {
  mode: string;
  symbol: string;
  keyId: string;
  toolCount: number;
  manifestVersion: string;
  networkPolicy: string;
  uptime: string;
}

// ─── Mock data (replaced by real MCP SSE stream in edge mode) ─────────────────

const MOCK_SERVER: MCPServerInfo = {
  mode: 'sovereign',
  symbol: 'Eban',
  keyId: 'a3f7c1b2',
  toolCount: 37,
  manifestVersion: 'PQC-01-STIG-V1R1',
  networkPolicy: 'offline',
  uptime: '4h 23m',
};

const MOCK_TOOLS: ToolStatus[] = [
  // ── Scan / Assessment
  { name: 'pqc_stig', category: 'PQC Compliance', tier: 'enterprise', lastCalledAt: '2m ago', callCount: 3, lastScore: 91, scoreLabel: 'QUANTUM READY', scoreColor: '#22c55e', status: 'pass', latencyMs: 780 },
  { name: 'stig_check', category: 'STIG Compliance', tier: 'community', lastCalledAt: '5m ago', callCount: 7, lastScore: 74, scoreLabel: 'SUBSTANTIALLY COMPLIANT', scoreColor: '#f59e0b', status: 'warn', latencyMs: 1240 },
  { name: 'cmmc_assess', category: 'CMMC', tier: 'community', lastCalledAt: '12m ago', callCount: 2, lastScore: 88, scoreLabel: 'READY FOR C3PAO', scoreColor: '#22c55e', status: 'pass', latencyMs: 920 },
  { name: 'ert_readiness', category: 'ERT Package A', tier: 'community', lastCalledAt: '18m ago', callCount: 1, lastScore: 82, scoreLabel: 'LOW RISK', scoreColor: '#22c55e', status: 'pass', latencyMs: 3100 },
  { name: 'ert_architect', category: 'ERT Package B', tier: 'community', lastCalledAt: null, callCount: 0, status: 'idle' },
  { name: 'ert_crypto', category: 'ERT Package C', tier: 'community', lastCalledAt: '1h ago', callCount: 4, status: 'pass', latencyMs: 2200 },
  { name: 'ert_godfather', category: 'ERT Package D', tier: 'community', lastCalledAt: null, callCount: 0, status: 'idle' },
  // ── SBOM / Threat
  { name: 'sbom_generate', category: 'Supply Chain', tier: 'community', lastCalledAt: null, callCount: 0, status: 'idle' },
  { name: 'threat_model', category: 'Risk Modeling', tier: 'community', lastCalledAt: null, callCount: 0, status: 'idle' },
  // ── Sovereign
  { name: 'khepra_export_attestation', category: 'Evidence', tier: 'sovereign', lastCalledAt: '2h ago', callCount: 1, status: 'pass', latencyMs: 4800 },
  { name: 'khepra_export_poam', category: 'Evidence', tier: 'sovereign', lastCalledAt: null, callCount: 0, status: 'idle' },
  { name: 'dag_attestation', category: 'DAG Audit', tier: 'community', lastCalledAt: '2m ago', callCount: 3, status: 'pass', latencyMs: 45 },
  { name: 'nist_map', category: 'Control Search', tier: 'community', lastCalledAt: '8m ago', callCount: 12, status: 'pass', latencyMs: 38 },
  { name: 'dark_crypto_contribute', category: 'Intelligence', tier: 'community', lastCalledAt: null, callCount: 0, status: 'idle' },
];

// ─── Sub-components ──────────────────────────────────────────────────────────

const TierBadge = ({ tier }: { tier: ToolStatus['tier'] }) => {
  const config: Record<ToolStatus['tier'], { label: string; color: string; bg: string }> = {
    community: { label: 'COMMUNITY', color: '#60a5fa', bg: 'rgba(96,165,250,0.12)' },
    enterprise: { label: 'ENTERPRISE', color: '#a78bfa', bg: 'rgba(167,139,250,0.12)' },
    sovereign: { label: 'SOVEREIGN', color: '#f59e0b', bg: 'rgba(245,158,11,0.12)' },
  };
  const c = config[tier];
  return (
    <span style={{
      fontSize: '10px', fontWeight: 700, letterSpacing: '0.08em',
      color: c.color, background: c.bg,
      padding: '2px 6px', borderRadius: '4px', border: `1px solid ${c.color}22`,
    }}>
      {c.label}
    </span>
  );
};

const StatusDot = ({ status }: { status: ToolStatus['status'] }) => {
  const colors: Record<ToolStatus['status'], string> = {
    idle: '#475569', running: '#60a5fa', pass: '#22c55e', fail: '#ef4444', warn: '#f59e0b',
  };
  const animated = status === 'running';
  return (
    <span style={{
      display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
      background: colors[status], flexShrink: 0,
      animation: animated ? 'pulse 1.5s infinite' : 'none',
    }} />
  );
};

const ToolCard = ({ tool }: { tool: ToolStatus }) => {
  const [hovered, setHovered] = useState(false);

  return (
    <div
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        background: hovered ? 'rgba(255,255,255,0.06)' : 'rgba(255,255,255,0.03)',
        border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: 10,
        padding: '12px 14px',
        transition: 'background 0.18s, border-color 0.18s',
        borderColor: hovered ? 'rgba(139,92,246,0.3)' : 'rgba(255,255,255,0.08)',
        cursor: 'default',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
        <StatusDot status={tool.status} />
        <span style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 12, color: '#c4b5fd', fontWeight: 600 }}>
          {tool.name}
        </span>
        <span style={{ marginLeft: 'auto' }}>
          <TierBadge tier={tool.tier} />
        </span>
      </div>
      <div style={{ fontSize: 11, color: '#64748b', marginBottom: 4 }}>{tool.category}</div>
      {tool.lastScore !== undefined && (
        <div style={{ fontSize: 12, color: tool.scoreColor, fontWeight: 600, marginBottom: 2 }}>
          {tool.lastScore}% — {tool.scoreLabel}
        </div>
      )}
      <div style={{ display: 'flex', gap: 12, marginTop: 4 }}>
        {tool.latencyMs !== undefined && (
          <span style={{ fontSize: 10, color: '#475569' }}>{tool.latencyMs}ms</span>
        )}
        {tool.callCount > 0 && (
          <span style={{ fontSize: 10, color: '#475569' }}>{tool.callCount} calls</span>
        )}
        {tool.lastCalledAt && (
          <span style={{ fontSize: 10, color: '#475569' }}>{tool.lastCalledAt}</span>
        )}
        {!tool.lastCalledAt && (
          <span style={{ fontSize: 10, color: '#334155' }}>never called</span>
        )}
      </div>
    </div>
  );
};

const StatCard = ({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) => (
  <div style={{
    background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)',
    borderRadius: 12, padding: '18px 20px', flex: 1, minWidth: 120,
  }}>
    <div style={{ fontSize: 11, color: '#64748b', letterSpacing: '0.06em', marginBottom: 8 }}>{label}</div>
    <div style={{ fontSize: 24, fontWeight: 700, color: color || '#f1f5f9', lineHeight: 1 }}>{value}</div>
    {sub && <div style={{ fontSize: 11, color: '#475569', marginTop: 4 }}>{sub}</div>}
  </div>
);

// ─── Main Page ────────────────────────────────────────────────────────────────

const MCPServerDashboard = () => {
  const [server] = useState<MCPServerInfo>(MOCK_SERVER);
  const [tools] = useState<ToolStatus[]>(MOCK_TOOLS);
  const [currentTime, setCurrentTime] = useState(new Date());
  const [filter, setFilter] = useState<string>('all');

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const categories = ['all', ...Array.from(new Set(tools.map(t => t.category)))];
  const filtered = filter === 'all' ? tools : tools.filter(t => t.category === filter);

  const passCount = tools.filter(t => t.status === 'pass').length;
  const warnCount = tools.filter(t => t.status === 'warn').length;
  const idleCount = tools.filter(t => t.status === 'idle').length;

  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #0f0a1a 0%, #0a0f1e 50%, #0f1a0a 100%)',
      fontFamily: '"Inter", -apple-system, sans-serif',
      color: '#f1f5f9',
      padding: '32px',
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');
        @keyframes pulse { 0%,100% { opacity: 1 } 50% { opacity: 0.4 } }
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 4px; } 
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: rgba(139,92,246,0.3); border-radius: 4px; }
      `}</style>

      {/* ── Header ───────────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 32 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 6 }}>
            <div style={{
              width: 36, height: 36, borderRadius: 10,
              background: 'linear-gradient(135deg, #7c3aed, #4f46e5)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 18,
            }}>𓂀</div>
            <div>
              <h1 style={{ margin: 0, fontSize: 22, fontWeight: 700, letterSpacing: '-0.02em' }}>
                KHEPRA MCP Server
              </h1>
              <div style={{ fontSize: 12, color: '#64748b', marginTop: 2 }}>
                PQC-01-STIG-V1R1 · ML-DSA-65 Signed · DAG-Anchored
              </div>
            </div>
          </div>
        </div>
        <div style={{ textAlign: 'right' }}>
          <div style={{
            display: 'inline-flex', alignItems: 'center', gap: 6,
            background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.25)',
            borderRadius: 20, padding: '4px 12px', marginBottom: 6,
          }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e', animation: 'pulse 2s infinite', display: 'inline-block' }} />
            <span style={{ fontSize: 11, color: '#22c55e', fontWeight: 600 }}>SERVER ACTIVE</span>
          </div>
          <div style={{ fontSize: 11, color: '#475569', fontFamily: '"JetBrains Mono", monospace' }}>
            {currentTime.toISOString().replace('T', ' ').substring(0, 19)} UTC
          </div>
        </div>
      </div>

      {/* ── Server Info Strip ─────────────────────────────────────────────────── */}
      <div style={{
        background: 'rgba(139,92,246,0.08)', border: '1px solid rgba(139,92,246,0.2)',
        borderRadius: 12, padding: '14px 20px', marginBottom: 24,
        display: 'flex', gap: 32, flexWrap: 'wrap',
      }}>
        {[
          { label: 'Mode', value: server.mode.toUpperCase() },
          { label: 'Symbol', value: server.symbol },
          { label: 'Key ID', value: server.keyId, mono: true },
          { label: 'Network', value: server.networkPolicy },
          { label: 'PQC Standard', value: server.manifestVersion, mono: true },
          { label: 'Uptime', value: server.uptime },
          { label: 'Tools', value: `${server.toolCount} registered` },
        ].map(({ label, value, mono }) => (
          <div key={label}>
            <div style={{ fontSize: 10, color: '#64748b', letterSpacing: '0.06em' }}>{label}</div>
            <div style={{
              fontSize: 13, fontWeight: 600, color: '#c4b5fd', marginTop: 2,
              fontFamily: mono ? '"JetBrains Mono", monospace' : 'inherit',
            }}>{value}</div>
          </div>
        ))}
      </div>

      {/* ── Stats Row ─────────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 24, flexWrap: 'wrap' }}>
        <StatCard label="TOTAL TOOLS" value={tools.length} sub="registered" />
        <StatCard label="PASSING" value={passCount} color="#22c55e" sub="last assessment" />
        <StatCard label="WARNINGS" value={warnCount} color="#f59e0b" sub="need attention" />
        <StatCard label="IDLE" value={idleCount} color="#475569" sub="never invoked" />
        <StatCard label="PQC TIER" value="ML-DSA-65" color="#a78bfa" sub="FIPS 204 compliant" />
        <StatCard label="DAG NODES" value="47" color="#60a5fa" sub="this session" />
      </div>

      {/* ── Category Filter ───────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 20 }}>
        {categories.map(cat => (
          <button
            key={cat}
            onClick={() => setFilter(cat)}
            style={{
              padding: '5px 12px', borderRadius: 20, border: '1px solid',
              fontSize: 11, fontWeight: 600, cursor: 'pointer', transition: 'all 0.15s',
              background: filter === cat ? 'rgba(139,92,246,0.2)' : 'transparent',
              borderColor: filter === cat ? 'rgba(139,92,246,0.5)' : 'rgba(255,255,255,0.1)',
              color: filter === cat ? '#c4b5fd' : '#64748b',
            }}
          >
            {cat === 'all' ? 'ALL TOOLS' : cat.toUpperCase()}
          </button>
        ))}
      </div>

      {/* ── Tool Grid ─────────────────────────────────────────────────────────── */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))',
        gap: 12,
      }}>
        {filtered.map(tool => (
          <ToolCard key={tool.name} tool={tool} />
        ))}
      </div>

      {/* ── Footer ───────────────────────────────────────────────────────────── */}
      <div style={{ marginTop: 40, paddingTop: 20, borderTop: '1px solid rgba(255,255,255,0.06)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontSize: 11, color: '#334155' }}>
          Khepra MCP Server — PQC-01-STIG-V1R1 · NSA CNSA 2.0 · NIST FIPS 203/204/205
        </div>
        <div style={{ fontSize: 11, color: '#334155', fontFamily: '"JetBrains Mono", monospace' }}>
          souhimbou.ai · NouchiX
        </div>
      </div>
    </div>
  );
};

export default MCPServerDashboard;
