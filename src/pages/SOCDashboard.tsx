"use client";
import { useEffect, useRef, useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import {
  Shield, AlertTriangle, Activity, Users, FileCheck,
  Zap, Lock, Eye, CheckCircle, XCircle, Clock, ChevronRight,
  Download, RefreshCw, Wifi, WifiOff
} from "lucide-react";

// ─── Types (mirrors pkg/souhimbou/agent.go) ──────────────────────────────────

type EventType =
  | "tool_call"
  | "anomaly_detected"
  | "incident_opened"
  | "playbook_executed"
  | "approval_required"
  | "incident_resolved"
  | "investigation_started";

interface AgentEvent {
  id: string;
  timestamp: string;
  agent_id: string;
  type: EventType;
  symbol: string;
  severity: "info" | "warning" | "critical";
  summary: string;
  detail?: Record<string, unknown>;
  signed: boolean;
  dag_node_id?: string;
}

interface IncidentEntry {
  id: string;
  agent_id: string;
  opened_at: string;
  severity: string;
  summary: string;
  playbook: string;
  status: "pending" | "staging" | "approved" | "resolved";
  anomaly_score?: number;
  dag_node_id?: string;
}

interface AgentFleetEntry {
  agent_id: string;
  last_seen: string;
  anomaly_score: number;
  tool_calls: number;
  blocked: number;
  status: "healthy" | "warning" | "critical" | "quarantined";
}

// ─── Hooks ───────────────────────────────────────────────────────────────────

function getAPIBase(): string {
  // Safe for both SSR and CSR — import.meta.env only accessed on client
  if (typeof window === "undefined") return "https://gateway.souhimbou.ai";
  return (import.meta as any).env?.VITE_API_URL || "https://gateway.souhimbou.ai";
}

function useSSEEventBus() {
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const esRef = useRef<EventSource | null>(null);

  const connect = useCallback(() => {
    if (esRef.current) esRef.current.close();

    const es = new EventSource(`${getAPIBase()}/api/v1/asaf/stream`, {
      withCredentials: false,
    });
    esRef.current = es;

    es.onopen = () => setConnected(true);
    es.onmessage = (e) => {
      try {
        const ev: AgentEvent = JSON.parse(e.data);
        setEvents((prev) => [ev, ...prev].slice(0, 500)); // keep last 500
      } catch {
        // malformed SSE — skip
      }
    };
    es.onerror = () => {
      setConnected(false);
      // Auto-reconnect after 5s
      setTimeout(connect, 5000);
    };
  }, []);

  useEffect(() => {
    connect();
    return () => esRef.current?.close();
  }, [connect]);

  return { events, connected };
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function ConnectionBadge({ connected }: { connected: boolean }) {
  return (
    <div className={`flex items-center gap-1.5 text-xs font-mono px-3 py-1 rounded-full border ${
      connected
        ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
        : "border-red-500/40 bg-red-500/10 text-red-400"
    }`}>
      {connected ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
      {connected ? "LIVE" : "RECONNECTING"}
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const styles = {
    critical: "bg-red-500/20 text-red-300 border-red-500/40",
    warning: "bg-amber-500/20 text-amber-300 border-amber-500/40",
    info: "bg-blue-500/20 text-blue-300 border-blue-500/40",
  } as Record<string, string>;
  return (
    <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase ${styles[severity] ?? styles.info}`}>
      {severity}
    </span>
  );
}

function ThreatScoreMeter({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  const color = pct >= 80 ? "bg-red-500" : pct >= 50 ? "bg-amber-500" : "bg-emerald-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-white/10 rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-mono text-white/60 w-8">{(score * 10).toFixed(1)}</span>
    </div>
  );
}

function FleetStatusDot({ status }: { status: AgentFleetEntry["status"] }) {
  const styles = {
    healthy: "bg-emerald-400",
    warning: "bg-amber-400",
    critical: "bg-red-400 animate-pulse",
    quarantined: "bg-purple-400",
  };
  return <span className={`inline-block w-2 h-2 rounded-full ${styles[status]}`} />;
}

function EventIcon({ type }: { type: EventType }) {
  switch (type) {
    case "incident_opened": return <AlertTriangle className="h-3.5 w-3.5 text-red-400" />;
    case "anomaly_detected": return <Zap className="h-3.5 w-3.5 text-amber-400" />;
    case "playbook_executed": return <Activity className="h-3.5 w-3.5 text-blue-400" />;
    case "approval_required": return <Clock className="h-3.5 w-3.5 text-orange-400" />;
    case "incident_resolved": return <CheckCircle className="h-3.5 w-3.5 text-emerald-400" />;
    case "tool_call": return <ChevronRight className="h-3.5 w-3.5 text-white/40" />;
    default: return <Eye className="h-3.5 w-3.5 text-white/30" />;
  }
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function SOCDashboard() {
  const { events, connected } = useSSEEventBus();

  // Derive fleet and incidents from live event stream
  const fleet = useCallback((): AgentFleetEntry[] => {
    const agentMap = new Map<string, AgentFleetEntry>();
    [...events].reverse().forEach((ev) => {
      const existing = agentMap.get(ev.agent_id) ?? {
        agent_id: ev.agent_id,
        last_seen: ev.timestamp,
        anomaly_score: 0,
        tool_calls: 0,
        blocked: 0,
        status: "healthy" as const,
      };
      existing.last_seen = ev.timestamp;
      if (ev.type === "tool_call") existing.tool_calls++;
      if (ev.type === "anomaly_detected") {
        const score = (ev.detail?.score as number) ?? 0;
        existing.anomaly_score = Math.max(existing.anomaly_score, score);
      }
      if (ev.type === "incident_opened") existing.blocked++;
      existing.status =
        existing.anomaly_score >= 0.9 ? "critical" :
        existing.anomaly_score >= 0.6 ? "warning" : "healthy";
      agentMap.set(ev.agent_id, existing);
    });
    return Array.from(agentMap.values()).sort((a, b) => b.anomaly_score - a.anomaly_score);
  }, [events]);

  const incidents = useCallback((): IncidentEntry[] => {
    return events
      .filter((e) => e.type === "incident_opened" || e.type === "approval_required")
      .slice(0, 20)
      .map((e) => ({
        id: e.id,
        agent_id: e.agent_id,
        opened_at: e.timestamp,
        severity: e.severity,
        summary: e.summary,
        playbook: (e.detail?.playbook as string) ?? "quarantine-agent",
        status: e.type === "approval_required" ? "pending" : "staging",
        anomaly_score: (e.detail?.score as number) ?? undefined,
        dag_node_id: e.dag_node_id,
      }));
  }, [events]);

  const criticalCount = events.filter((e) => e.severity === "critical").length;
  const pendingApprovals = events.filter((e) => e.type === "approval_required").length;
  const signedCount = events.filter((e) => e.signed).length;
  const fleetData = fleet();
  const incidentData = incidents();

  return (
    <div className="min-h-screen bg-[#050a14] text-white font-sans">
      {/* Header */}
      <header className="border-b border-white/5 bg-[#080f1e] px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
            <Shield className="h-4 w-4 text-white" />
          </div>
          <div>
            <h1 className="text-sm font-semibold tracking-wide">SouHimBou AI</h1>
            <p className="text-[10px] text-white/40 font-mono">AGENTIC SOC · ENTERPRISE TIER</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <ConnectionBadge connected={connected} />
          <Button variant="outline" size="sm" className="h-7 text-xs border-white/10 hover:bg-white/5">
            <Download className="h-3 w-3 mr-1.5" />
            Export Evidence
          </Button>
        </div>
      </header>

      {/* KPI Strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 px-6 py-4 border-b border-white/5">
        {[
          { label: "Live Events", value: events.length, icon: Activity, color: "text-cyan-400" },
          { label: "Critical Alerts", value: criticalCount, icon: AlertTriangle, color: "text-red-400" },
          { label: "Pending Approvals", value: pendingApprovals, icon: Clock, color: "text-amber-400" },
          { label: "Signed (ML-DSA-65)", value: signedCount, icon: Lock, color: "text-emerald-400" },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="bg-white/[0.03] border border-white/5 rounded-xl px-4 py-3 flex items-center gap-3">
            <Icon className={`h-5 w-5 ${color} shrink-0`} />
            <div>
              <p className="text-lg font-bold font-mono">{value.toLocaleString()}</p>
              <p className="text-[10px] text-white/40 uppercase tracking-wider">{label}</p>
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 p-6">
        {/* ── Live Event Feed ── */}
        <div className="lg:col-span-2 space-y-4">
          <Card className="bg-white/[0.02] border-white/5 shadow-none">
            <CardHeader className="pb-3 pt-4 px-4">
              <CardTitle className="text-xs font-mono text-white/60 uppercase tracking-wider flex items-center gap-2">
                <Activity className="h-3.5 w-3.5" />
                Live Event Bus
                <span className="ml-auto text-white/30">{events.length} events</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="px-2 pb-3">
              <ScrollArea className="h-[340px]">
                {events.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-40 text-white/20 text-xs">
                    <Wifi className="h-6 w-6 mb-2 opacity-30" />
                    Waiting for agent events…
                  </div>
                ) : (
                  <div className="space-y-px">
                    {events.slice(0, 100).map((ev) => (
                      <div
                        key={ev.id}
                        className={`flex items-start gap-2.5 px-3 py-2 rounded-lg transition-colors hover:bg-white/[0.03] ${
                          ev.severity === "critical" ? "border-l-2 border-red-500/60 bg-red-500/[0.03]" :
                          ev.severity === "warning" ? "border-l-2 border-amber-500/40" : ""
                        }`}
                      >
                        <EventIcon type={ev.type} />
                        <div className="flex-1 min-w-0">
                          <p className="text-xs text-white/80 truncate">{ev.summary}</p>
                          <p className="text-[10px] text-white/30 font-mono">
                            {ev.agent_id} · {new Date(ev.timestamp).toLocaleTimeString()}
                            {ev.signed && <span className="ml-1.5 text-emerald-400/70">✓ ML-DSA-65</span>}
                          </p>
                        </div>
                        <SeverityBadge severity={ev.severity} />
                      </div>
                    ))}
                  </div>
                )}
              </ScrollArea>
            </CardContent>
          </Card>

          {/* ── Incident Queue ── */}
          <Card className="bg-white/[0.02] border-white/5 shadow-none">
            <CardHeader className="pb-3 pt-4 px-4">
              <CardTitle className="text-xs font-mono text-white/60 uppercase tracking-wider flex items-center gap-2">
                <AlertTriangle className="h-3.5 w-3.5 text-red-400" />
                Incident Queue
                {pendingApprovals > 0 && (
                  <Badge className="ml-1 bg-red-500/20 text-red-300 border-red-500/30 text-[9px]">
                    {pendingApprovals} need approval
                  </Badge>
                )}
              </CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-4">
              {incidentData.length === 0 ? (
                <div className="flex items-center gap-2 text-white/20 text-xs py-4">
                  <CheckCircle className="h-4 w-4" />
                  No active incidents
                </div>
              ) : (
                <div className="space-y-2">
                  {incidentData.map((inc) => (
                    <div key={inc.id} className="flex items-center gap-3 p-3 bg-white/[0.03] rounded-lg border border-white/5">
                      <div className="flex-1 min-w-0">
                        <p className="text-xs text-white/80 truncate">{inc.summary}</p>
                        <p className="text-[10px] text-white/30 font-mono">
                          {inc.agent_id} · playbook: {inc.playbook}
                          {inc.dag_node_id && <span className="ml-1.5 text-cyan-400/50">DAG: {inc.dag_node_id.slice(0, 12)}…</span>}
                        </p>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <SeverityBadge severity={inc.severity} />
                        {inc.status === "pending" && (
                          <Button size="sm" className="h-6 text-[10px] bg-emerald-600 hover:bg-emerald-500 text-white px-2">
                            Approve →
                          </Button>
                        )}
                        {inc.status !== "pending" && (
                          <span className="text-[10px] font-mono text-white/30 uppercase">{inc.status}</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* ── Agent Fleet ── */}
        <div className="space-y-4">
          <Card className="bg-white/[0.02] border-white/5 shadow-none">
            <CardHeader className="pb-3 pt-4 px-4">
              <CardTitle className="text-xs font-mono text-white/60 uppercase tracking-wider flex items-center gap-2">
                <Users className="h-3.5 w-3.5" />
                Agent Fleet
                <span className="ml-auto text-white/30">{fleetData.length} agents</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-4">
              {fleetData.length === 0 ? (
                <div className="text-white/20 text-xs py-4 text-center">No agents observed yet</div>
              ) : (
                <div className="space-y-3">
                  {fleetData.map((agent) => (
                    <div key={agent.agent_id} className="space-y-1.5">
                      <div className="flex items-center gap-2">
                        <FleetStatusDot status={agent.status} />
                        <span className="text-xs font-mono text-white/70 flex-1 truncate">{agent.agent_id}</span>
                        <span className="text-[10px] text-white/30">{agent.tool_calls} calls</span>
                      </div>
                      <ThreatScoreMeter score={agent.anomaly_score} />
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* ── Evidence Package Builder ── */}
          <Card className="bg-white/[0.02] border-white/5 shadow-none">
            <CardHeader className="pb-3 pt-4 px-4">
              <CardTitle className="text-xs font-mono text-white/60 uppercase tracking-wider flex items-center gap-2">
                <FileCheck className="h-3.5 w-3.5 text-cyan-400" />
                Evidence Package
              </CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-4 space-y-3">
              <div className="space-y-2 text-xs">
                {[
                  { label: "Flight Frames", value: signedCount, icon: CheckCircle, ok: signedCount > 0 },
                  { label: "Incidents", value: incidentData.length, icon: AlertTriangle, ok: true },
                  { label: "ML-DSA-65 Signed", value: `${signedCount}/${events.length}`, icon: Lock, ok: signedCount > 0 },
                ].map(({ label, value, icon: Icon, ok }) => (
                  <div key={label} className="flex items-center justify-between py-1 border-b border-white/5">
                    <div className="flex items-center gap-2 text-white/50">
                      <Icon className={`h-3 w-3 ${ok ? "text-emerald-400" : "text-white/20"}`} />
                      {label}
                    </div>
                    <span className="font-mono text-white/70">{value}</span>
                  </div>
                ))}
              </div>
              <Button
                className="w-full h-8 text-xs bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white border-0"
                disabled={events.length === 0}
              >
                <Download className="h-3 w-3 mr-1.5" />
                Generate Signed PDF
              </Button>
              <p className="text-[9px] text-white/20 text-center font-mono">
                ML-DSA-65 signed · SOC 2 / EU AI Act / ISO 42001
              </p>
            </CardContent>
          </Card>

          {/* ── KASA Threat Score Timeline ── */}
          <Card className="bg-white/[0.02] border-white/5 shadow-none">
            <CardHeader className="pb-3 pt-4 px-4">
              <CardTitle className="text-xs font-mono text-white/60 uppercase tracking-wider flex items-center gap-2">
                <Zap className="h-3.5 w-3.5 text-amber-400" />
                KASA Threat Timeline
              </CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-4">
              <div className="flex items-end gap-0.5 h-16">
                {Array.from({ length: 20 }, (_, i) => {
                  const bucketEvents = events.slice(i * 5, i * 5 + 5);
                  const maxScore = bucketEvents.reduce((m, e) => {
                    return Math.max(m, (e.detail?.score as number) ?? (e.severity === "critical" ? 0.9 : e.severity === "warning" ? 0.5 : 0.1));
                  }, 0);
                  const h = Math.max(4, maxScore * 100);
                  const color = maxScore >= 0.8 ? "bg-red-500" : maxScore >= 0.5 ? "bg-amber-400" : "bg-emerald-500/50";
                  return (
                    <div key={i} className="flex-1 flex items-end">
                      <div className={`w-full rounded-sm ${color} transition-all`} style={{ height: `${h}%` }} />
                    </div>
                  );
                })}
              </div>
              <p className="text-[9px] text-white/20 font-mono mt-2 text-center">last 100 events · KASA behavioral score</p>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
