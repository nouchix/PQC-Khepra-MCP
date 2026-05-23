"use client";

import { useEffect, useState, useCallback } from "react";
import { Shield, Activity, Link2, Users, Key, RefreshCw, CheckCircle, XCircle } from "lucide-react";

const API = process.env.NEXT_PUBLIC_API_URL ?? "https://souhimbou-ai.fly.dev";

type RiskClass = "read-only" | "sandboxed" | "destructive";

interface ToolCall {
  id: string;
  tool_name: string;
  risk_class: RiskClass;
  attestation_id: string;
  signature: string;
  created_at: string;
  success: boolean;
}

interface DagNode {
  node_id: string;
  tool_name: string;
  parent_id: string | null;
  created_at: string;
  schema_version: string;
}

interface NhiIdentity {
  id: string;
  name: string;
  type: string;
  owner: string | null;
  risk: "low" | "medium" | "high";
  expires_at: string | null;
}

interface AcpCredential {
  id: string;
  label: string;
  algorithm: string;
  issued_at: string;
  expires_at: string | null;
  status: "active" | "revoked" | "expired";
}

type Tab = "calls" | "dag" | "nhi" | "acp";

const RISK_COLORS: Record<RiskClass, string> = {
  "read-only": "text-emerald-400 bg-emerald-900/20 border-emerald-500/30",
  "sandboxed": "text-amber-400 bg-amber-900/20 border-amber-500/30",
  "destructive": "text-red-400 bg-red-900/20 border-red-500/30",
};

function ServerStatus({ online }: { online: boolean | null }) {
  if (online === null) return (
    <span className="flex items-center gap-1.5 text-xs text-zinc-500">
      <span className="w-2 h-2 rounded-full bg-zinc-600 animate-pulse" /> Checking…
    </span>
  );
  return online ? (
    <span className="flex items-center gap-1.5 text-xs text-emerald-400">
      <span className="w-2 h-2 rounded-full bg-emerald-400" /> Online
    </span>
  ) : (
    <span className="flex items-center gap-1.5 text-xs text-red-400">
      <span className="w-2 h-2 rounded-full bg-red-400" /> Offline
    </span>
  );
}

function EmptyState({ label }: { label: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-zinc-600">
      <Shield className="w-8 h-8 mb-3 opacity-30" />
      <p className="text-sm">{label}</p>
    </div>
  );
}

function ToolCallsTab({ calls, loading }: { calls: ToolCall[]; loading: boolean }) {
  if (loading) return <div className="py-16 text-center text-zinc-600 text-sm">Loading tool calls…</div>;
  if (!calls.length) return <EmptyState label="No tool calls recorded yet. Run the smoke test to generate events." />;
  return (
    <div className="space-y-2">
      {calls.map((c) => (
        <div key={c.id} className="border border-zinc-800 bg-zinc-900/40 rounded-lg p-4 flex items-start gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <code className="text-sm font-mono text-cyan-300">{c.tool_name}</code>
              <span className={`text-[10px] font-bold uppercase tracking-widest border px-1.5 py-0.5 rounded ${RISK_COLORS[c.risk_class]}`}>
                {c.risk_class}
              </span>
              {c.success
                ? <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                : <XCircle className="w-3.5 h-3.5 text-red-400" />}
            </div>
            <p className="text-[11px] text-zinc-500 mt-1 font-mono truncate">
              sig: {c.signature.slice(0, 32)}…
            </p>
            <p className="text-[11px] text-zinc-600 mt-0.5">
              {c.attestation_id} · {new Date(c.created_at).toLocaleString()}
            </p>
          </div>
        </div>
      ))}
    </div>
  );
}

function DagTab({ nodes, loading }: { nodes: DagNode[]; loading: boolean }) {
  if (loading) return <div className="py-16 text-center text-zinc-600 text-sm">Loading DAG chain…</div>;
  if (!nodes.length) return <EmptyState label="No DAG nodes yet. Each signed tool call creates a node." />;
  return (
    <div className="space-y-0">
      {nodes.map((n, i) => (
        <div key={n.node_id} className="flex gap-4">
          <div className="flex flex-col items-center">
            <div className="w-2.5 h-2.5 rounded-full bg-cyan-400 ring-2 ring-cyan-400/20 mt-1 shrink-0" />
            {i < nodes.length - 1 && <div className="w-px flex-1 bg-zinc-800 my-1" />}
          </div>
          <div className="pb-4 min-w-0">
            <div className="flex items-center gap-2">
              <code className="text-xs font-mono text-cyan-300">{n.tool_name}</code>
              <span className="text-[10px] text-zinc-600">{n.schema_version}</span>
            </div>
            <p className="text-[11px] text-zinc-500 font-mono">{n.node_id}</p>
            {n.parent_id && (
              <p className="text-[11px] text-zinc-700 font-mono">↳ {n.parent_id}</p>
            )}
            <p className="text-[11px] text-zinc-600 mt-0.5">{new Date(n.created_at).toLocaleString()}</p>
          </div>
        </div>
      ))}
    </div>
  );
}

function NhiTab({ identities, loading }: { identities: NhiIdentity[]; loading: boolean }) {
  if (loading) return <div className="py-16 text-center text-zinc-600 text-sm">Loading NHI inventory…</div>;
  if (!identities.length) return <EmptyState label="No non-human identities found." />;
  const riskColor = (r: NhiIdentity["risk"]) =>
    r === "high" ? "text-red-400" : r === "medium" ? "text-amber-400" : "text-emerald-400";
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm text-left">
        <thead>
          <tr className="border-b border-zinc-800 text-zinc-500 uppercase text-[10px] tracking-widest">
            <th className="py-2 pr-6">Identity</th>
            <th className="py-2 pr-6">Type</th>
            <th className="py-2 pr-6">Owner</th>
            <th className="py-2 pr-6">Risk</th>
            <th className="py-2">Expires</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-800/50">
          {identities.map((id) => (
            <tr key={id.id}>
              <td className="py-2.5 pr-6 font-mono text-zinc-300 text-xs">{id.name}</td>
              <td className="py-2.5 pr-6 text-zinc-400 text-xs">{id.type}</td>
              <td className="py-2.5 pr-6 text-zinc-400 text-xs">{id.owner ?? <span className="text-amber-400">orphaned</span>}</td>
              <td className={`py-2.5 pr-6 text-xs font-semibold ${riskColor(id.risk)}`}>{id.risk}</td>
              <td className="py-2.5 text-zinc-500 text-xs">
                {id.expires_at ? new Date(id.expires_at).toLocaleDateString() : "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AcpTab({ credentials, loading }: { credentials: AcpCredential[]; loading: boolean }) {
  if (loading) return <div className="py-16 text-center text-zinc-600 text-sm">Loading ACP credentials…</div>;
  if (!credentials.length) return <EmptyState label="No ACP credentials issued yet." />;
  const statusColor = (s: AcpCredential["status"]) =>
    s === "active" ? "text-emerald-400" : s === "revoked" ? "text-red-400" : "text-zinc-500";
  return (
    <div className="space-y-2">
      {credentials.map((c) => (
        <div key={c.id} className="border border-zinc-800 bg-zinc-900/40 rounded-lg p-4 flex items-center gap-4">
          <Key className="w-4 h-4 text-zinc-600 shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-sm text-zinc-200">{c.label}</span>
              <span className={`text-xs font-semibold ${statusColor(c.status)}`}>{c.status}</span>
            </div>
            <p className="text-[11px] text-zinc-500 mt-0.5">
              {c.algorithm} · Issued {new Date(c.issued_at).toLocaleDateString()}
              {c.expires_at ? ` · Expires ${new Date(c.expires_at).toLocaleDateString()}` : ""}
            </p>
            <p className="text-[11px] text-zinc-600 font-mono">{c.id}</p>
          </div>
        </div>
      ))}
    </div>
  );
}

export default function MCPDashboard() {
  const [tab, setTab] = useState<Tab>("calls");
  const [online, setOnline] = useState<boolean | null>(null);
  const [calls, setCalls] = useState<ToolCall[]>([]);
  const [dag, setDag] = useState<DagNode[]>([]);
  const [nhi, setNhi] = useState<NhiIdentity[]>([]);
  const [acp, setAcp] = useState<AcpCredential[]>([]);
  const [loading, setLoading] = useState(false);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [pingRes, callsRes, dagRes, nhiRes, acpRes] = await Promise.allSettled([
        fetch(`${API}/api/v1/health`, { signal: AbortSignal.timeout(5000) }),
        fetch(`${API}/api/v1/mcp/tool-calls?limit=50`),
        fetch(`${API}/api/v1/mcp/dag?limit=50`),
        fetch(`${API}/api/v1/mcp/nhi`),
        fetch(`${API}/api/v1/mcp/acp`),
      ]);

      setOnline(pingRes.status === "fulfilled" && pingRes.value.ok);

      if (callsRes.status === "fulfilled" && callsRes.value.ok) {
        const j = await callsRes.value.json();
        setCalls(j.data ?? []);
      }
      if (dagRes.status === "fulfilled" && dagRes.value.ok) {
        const j = await dagRes.value.json();
        setDag(j.data ?? []);
      }
      if (nhiRes.status === "fulfilled" && nhiRes.value.ok) {
        const j = await nhiRes.value.json();
        setNhi(j.data ?? []);
      }
      if (acpRes.status === "fulfilled" && acpRes.value.ok) {
        const j = await acpRes.value.json();
        setAcp(j.data ?? []);
      }
      setLastRefresh(new Date());
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const TABS: { id: Tab; label: string; icon: React.ReactNode; count?: number }[] = [
    { id: "calls", label: "Tool Calls", icon: <Activity className="w-3.5 h-3.5" />, count: calls.length },
    { id: "dag",   label: "DAG Chain",  icon: <Link2 className="w-3.5 h-3.5" />,   count: dag.length },
    { id: "nhi",   label: "NHI",        icon: <Users className="w-3.5 h-3.5" />,   count: nhi.length },
    { id: "acp",   label: "ACP",        icon: <Key className="w-3.5 h-3.5" />,     count: acp.length },
  ];

  const nhiHighRisk = nhi.filter((n) => n.risk === "high").length;

  return (
    <div className="space-y-6">
      {/* Header row */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-semibold text-white">MCP Dashboard</h1>
          <p className="text-xs text-zinc-500 mt-0.5">
            KHEPRA · Dilithium-3 signed tool call evidence
          </p>
        </div>
        <div className="flex items-center gap-4">
          <ServerStatus online={online} />
          <button
            onClick={fetchData}
            disabled={loading}
            className="flex items-center gap-1.5 text-xs text-zinc-400 hover:text-zinc-200 transition-colors disabled:opacity-40"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          {lastRefresh && (
            <span className="text-[11px] text-zinc-600 hidden sm:block">
              {lastRefresh.toLocaleTimeString()}
            </span>
          )}
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: "Tool Calls", value: calls.length, sub: `${calls.filter(c => c.success).length} successful` },
          { label: "DAG Nodes",  value: dag.length,   sub: "tamper-evident chain" },
          { label: "NHI",        value: nhi.length,   sub: nhiHighRisk ? `${nhiHighRisk} high risk` : "all clear", warn: nhiHighRisk > 0 },
          { label: "ACP Keys",   value: acp.length,   sub: `${acp.filter(c => c.status === "active").length} active` },
        ].map(({ label, value, sub, warn }) => (
          <div key={label} className="border border-zinc-800 bg-zinc-900/30 rounded-lg p-4">
            <p className="text-xs text-zinc-500 uppercase tracking-widest">{label}</p>
            <p className="text-2xl font-semibold text-white mt-1">{value}</p>
            <p className={`text-[11px] mt-0.5 ${warn ? "text-amber-400" : "text-zinc-600"}`}>{sub}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div>
        <div className="flex gap-1 border-b border-zinc-800 mb-6">
          {TABS.map(({ id, label, icon, count }) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium transition-colors border-b-2 -mb-px ${
                tab === id
                  ? "border-cyan-400 text-cyan-300"
                  : "border-transparent text-zinc-500 hover:text-zinc-300"
              }`}
            >
              {icon}
              {label}
              {count !== undefined && count > 0 && (
                <span className="bg-zinc-800 text-zinc-400 text-[10px] px-1.5 py-0.5 rounded-full">
                  {count}
                </span>
              )}
            </button>
          ))}
        </div>

        {tab === "calls" && <ToolCallsTab calls={calls} loading={loading} />}
        {tab === "dag"   && <DagTab nodes={dag} loading={loading} />}
        {tab === "nhi"   && <NhiTab identities={nhi} loading={loading} />}
        {tab === "acp"   && <AcpTab credentials={acp} loading={loading} />}
      </div>

      {/* Server info footer */}
      <div className="border-t border-zinc-800 pt-4 flex items-center justify-between text-[11px] text-zinc-600 flex-wrap gap-2">
        <span>KHEPRA MCP · io.github.etherversecodemate/khepra-mcp · ML-DSA-65 (FIPS 204)</span>
        <a href="/mcp-quickstart" className="hover:text-zinc-400 transition-colors">
          Setup docs →
        </a>
      </div>
    </div>
  );
}
