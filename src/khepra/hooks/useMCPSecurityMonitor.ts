/**
 * useMCPSecurityMonitor — P1 React Hook
 * ============================================================
 * Continuously monitors the MCP transport configuration for signs of
 * the Mitiga Labs Claude Code attack chain (localhost proxy injection,
 * unexpected sessionStart hooks, alreadyTrusted flags).
 *
 * In a browser context we cannot directly read ~/.claude.json from the
 * filesystem. This hook instead:
 *   1. Accepts a snapshot fetched by the parent (e.g., via a native
 *      bridge, Tauri, Electron IPC, or a local service sidecar).
 *   2. Runs MCPTransportGuard.inspect() on every snapshot update.
 *   3. Emits ASAF security events for any anomalies found.
 *   4. Exposes alert state to the UI for dashboard display.
 *
 * Usage:
 *   const { alerts, isSafe, lastChecked } = useMCPSecurityMonitor(snapshot);
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import {
  MCPTransportGuard,
  MCPThreatAlert,
  ClaudeJsonSnapshot,
} from '@/services/MCPTransportGuard';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface MCPSecurityMonitorState {
  /** All active threat alerts from the most recent inspection */
  alerts: MCPThreatAlert[];
  /** True when the last inspection found no issues */
  isSafe: boolean;
  /** Timestamp of the last completed inspection */
  lastChecked: Date | null;
  /** True while an inspection is in progress */
  isChecking: boolean;
  /** Total number of inspections run this session */
  totalChecks: number;
  /** Total lifetime alerts (accumulates across snapshots) */
  totalAlertsDetected: number;
  /** Manually trigger a re-inspection of the current snapshot */
  recheckNow: () => void;
  /** Clear all current alerts (does NOT fix the underlying issue) */
  dismissAlerts: () => void;
}

// ─── Hook ─────────────────────────────────────────────────────────────────────

/**
 * @param snapshot  Parsed contents of ~/.claude.json (null = not available)
 * @param pollMs    How often to re-inspect (default: 30s). Pass 0 to disable polling.
 */
export function useMCPSecurityMonitor(
  snapshot: ClaudeJsonSnapshot | null,
  pollMs = 30_000,
): MCPSecurityMonitorState {
  const [alerts, setAlerts]                   = useState<MCPThreatAlert[]>([]);
  const [lastChecked, setLastChecked]         = useState<Date | null>(null);
  const [isChecking, setIsChecking]           = useState(false);
  const [totalChecks, setTotalChecks]         = useState(0);
  const [totalAlerts, setTotalAlerts]         = useState(0);

  const snapshotRef = useRef<ClaudeJsonSnapshot | null>(null);
  snapshotRef.current = snapshot;

  const runInspection = useCallback(async () => {
    const current = snapshotRef.current;
    if (!current) return;

    setIsChecking(true);
    try {
      const found = await MCPTransportGuard.inspectAndEmit(current);
      setAlerts(found);
      setLastChecked(new Date());
      setTotalChecks(n => n + 1);
      if (found.length > 0) {
        setTotalAlerts(n => n + found.length);
        // Surface critical alerts to console so they are not missed
        const criticals = found.filter(a => a.severity === 'critical');
        if (criticals.length > 0) {
          console.error(
            '[KHEPRA MCP SECURITY ALERT]',
            criticals.length,
            'critical threat(s) detected in ~/.claude.json:',
            criticals,
          );
        }
      }
    } catch (err) {
      console.error('[useMCPSecurityMonitor] Inspection error:', err);
    } finally {
      setIsChecking(false);
    }
  }, []);

  // Run immediately when snapshot changes
  useEffect(() => {
    if (snapshot !== null) {
      runInspection();
    }
  }, [snapshot, runInspection]);

  // Polling
  useEffect(() => {
    if (pollMs <= 0 || snapshot === null) return;
    const id = setInterval(runInspection, pollMs);
    return () => clearInterval(id);
  }, [snapshot, pollMs, runInspection]);

  const dismissAlerts = useCallback(() => setAlerts([]), []);

  return {
    alerts,
    isSafe: alerts.length === 0,
    lastChecked,
    isChecking,
    totalChecks,
    totalAlertsDetected: totalAlerts,
    recheckNow: runInspection,
    dismissAlerts,
  };
}

// ─── UI helper ────────────────────────────────────────────────────────────────

/**
 * Severity → Tailwind color class mapping for dashboard badges.
 * Usage: <span className={severityColor(alert.severity)}>...</span>
 */
export function severityColor(severity: MCPThreatAlert['severity']): string {
  return {
    low:      'text-blue-400  bg-blue-900/30  border-blue-700',
    medium:   'text-yellow-400 bg-yellow-900/30 border-yellow-700',
    high:     'text-orange-400 bg-orange-900/30 border-orange-700',
    critical: 'text-red-400   bg-red-900/30   border-red-700',
  }[severity];
}

/**
 * Short human-readable label for each threat event type.
 */
export function eventLabel(event: MCPThreatAlert['event']): string {
  return {
    mcp_config_tamper:           'MCP Config Tampered',
    mcp_localhost_proxy:         'Localhost Proxy Detected',
    claude_json_trust_flag_set:  'Unexpected Trust Flag',
    postinstall_hook_detected:   'Postinstall Hook Found',
    oauth_refresh_unknown_origin:'OAuth Refresh — Unknown Origin',
  }[event] ?? event;
}
