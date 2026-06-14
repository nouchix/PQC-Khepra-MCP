/**
 * MCPTransportGuard — P1 Transport Integrity Service
 * ============================================================
 * Detects MCP endpoint rewrites (the core of the Mitiga Labs attack chain)
 * by comparing the active mcpServers configuration against canonical known-good
 * values and emitting ASAF security events on any deviation.
 *
 * This runs client-side in the KHEPRA dashboard. On a hardened server it would
 * run as a Go sidecar — this TypeScript version covers the SaaS/dashboard path.
 *
 * ASAF events emitted:
 *   mcp_config_tamper          — mcpServers URL changed from canonical value
 *   mcp_localhost_proxy         — mcpServers URL resolves to loopback
 *   claude_json_trust_flag_set  — alreadyTrusted flag found on a project path
 *   postinstall_hook_detected   — npm lifecycle hook found in active config
 */

import { supabase } from '@/integrations/supabase/client';

// ─── Types ────────────────────────────────────────────────────────────────────

export type MCPThreatEvent =
  | 'mcp_config_tamper'
  | 'mcp_localhost_proxy'
  | 'claude_json_trust_flag_set'
  | 'postinstall_hook_detected'
  | 'oauth_refresh_unknown_origin';

export type MCPThreatSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface MCPThreatAlert {
  event: MCPThreatEvent;
  severity: MCPThreatSeverity;
  serverName?: string;
  detectedValue?: string;
  canonicalValue?: string;
  timestamp: Date;
  recommendation: string;
}

export interface MCPServerEntry {
  command?: string;
  args?: string[];
  url?: string;
  env?: Record<string, string>;
}

export interface ClaudeJsonSnapshot {
  mcpServers?: Record<string, MCPServerEntry>;
  projects?: Record<string, { alreadyTrusted?: boolean }>;
  sessionStart?: unknown;
  hookStart?: unknown;
  hooks?: unknown;
  preToolUse?: unknown;
}

// ─── Canonical KHEPRA MCP configuration ─────────────────────────────────────

/**
 * Canonical commands for the KHEPRA MCP server.
 * Any MCP entry whose command is NOT one of these is flagged.
 */
const CANONICAL_MCP_COMMANDS: ReadonlySet<string> = new Set([
  'docker',  // container mode: docker run ... ghcr.io/nouchix/pqc-khepra-mcp
  'go',      // source mode:    go run ./cmd/khepra-mcp/main.go
]);

/**
 * Patterns indicating a localhost proxy has been injected.
 */
const LOCALHOST_PATTERNS = [
  /^localhost$/i,
  /^127\.\d+\.\d+\.\d+$/,
  /^::1$/,
  /^0\.0\.0\.0$/,
];

/**
 * Hook keys that should never appear in ~/.claude.json
 * unless explicitly added by the user.
 */
const SUSPICIOUS_HOOK_KEYS = [
  'sessionStart', 'hookStart', 'hooks', 'preToolUse', 'postToolUse',
] as const;

// ─── MCPTransportGuard ────────────────────────────────────────────────────────

export class MCPTransportGuard {
  private static readonly SOURCE = 'khepra_mcp_transport_guard';

  /**
   * Inspect a parsed ~/.claude.json snapshot and return any threat alerts.
   * This is the core detection function — call it whenever claude.json is read.
   */
  static inspect(snapshot: ClaudeJsonSnapshot): MCPThreatAlert[] {
    const alerts: MCPThreatAlert[] = [];

    // 1. Check each mcpServers entry
    if (snapshot.mcpServers) {
      for (const [name, entry] of Object.entries(snapshot.mcpServers)) {
        const cmdAlerts = this.inspectMCPEntry(name, entry);
        alerts.push(...cmdAlerts);
      }
    }

    // 2. Check for unexpected hook keys
    for (const hookKey of SUSPICIOUS_HOOK_KEYS) {
      if ((snapshot as Record<string, unknown>)[hookKey] !== undefined) {
        alerts.push({
          event: 'postinstall_hook_detected',
          severity: 'critical',
          detectedValue: hookKey,
          timestamp: new Date(),
          recommendation:
            `~/.claude.json contains an unexpected '${hookKey}' entry. ` +
            'Do NOT rotate tokens. Remove the hook, kill any proxy processes, ' +
            'then rotate. See docs/MCP_SECURITY_RUNBOOK.md.',
        });
      }
    }

    // 3. Check for alreadyTrusted flags
    if (snapshot.projects) {
      for (const [projPath, proj] of Object.entries(snapshot.projects)) {
        if (proj.alreadyTrusted === true) {
          alerts.push({
            event: 'claude_json_trust_flag_set',
            severity: 'medium',
            serverName: projPath,
            detectedValue: 'alreadyTrusted: true',
            timestamp: new Date(),
            recommendation:
              `Project '${projPath}' has alreadyTrusted=true. ` +
              'Verify you explicitly approved this path in Claude Code.',
          });
        }
      }
    }

    return alerts;
  }

  /**
   * Inspect a single mcpServers entry for anomalies.
   */
  private static inspectMCPEntry(name: string, entry: MCPServerEntry): MCPThreatAlert[] {
    const alerts: MCPThreatAlert[] = [];
    const cmd = entry.command ?? '';
    const argsStr = (entry.args ?? []).join(' ');
    const url = entry.url ?? '';

    // Check command is canonical
    if (cmd && !CANONICAL_MCP_COMMANDS.has(cmd.toLowerCase())) {
      alerts.push({
        event: 'mcp_config_tamper',
        severity: 'critical',
        serverName: name,
        detectedValue: cmd,
        canonicalValue: [...CANONICAL_MCP_COMMANDS].join(' | '),
        timestamp: new Date(),
        recommendation:
          `mcpServers.${name} uses unexpected command '${cmd}'. ` +
          'Do NOT rotate tokens. Remove the hook, then rotate credentials. ' +
          'See docs/MCP_SECURITY_RUNBOOK.md.',
      });
    }

    // Check for localhost in command, args, or url
    const fullText = `${cmd} ${argsStr} ${url}`;
    for (const pattern of LOCALHOST_PATTERNS) {
      if (pattern.test(cmd) || argsStr.split(/\s+/).some(t => pattern.test(t)) || pattern.test(url)) {
        alerts.push({
          event: 'mcp_localhost_proxy',
          severity: 'critical',
          serverName: name,
          detectedValue: fullText.trim().slice(0, 200),
          timestamp: new Date(),
          recommendation:
            `mcpServers.${name} routes to a local address — classic proxy injection. ` +
            'DO NOT rotate tokens yet. Follow IR sequence in docs/MCP_SECURITY_RUNBOOK.md.',
        });
        break;
      }
    }

    // Check for HTTP/HTTPS URL in command (should be a binary, not a URL)
    if (/^https?:\/\//i.test(cmd)) {
      alerts.push({
        event: 'mcp_config_tamper',
        severity: 'high',
        serverName: name,
        detectedValue: cmd,
        timestamp: new Date(),
        recommendation:
          `mcpServers.${name} command is a URL ('${cmd}'). ` +
          'MCP server command should be a local binary or docker, not a URL.',
      });
    }

    return alerts;
  }

  /**
   * Emit all alerts as ASAF security events to Supabase.
   * Non-blocking — failures are logged but do not throw.
   */
  static async emitAlerts(alerts: MCPThreatAlert[]): Promise<void> {
    if (alerts.length === 0) return;

    for (const alert of alerts) {
      try {
        await supabase.from('security_events').insert({
          event_type: alert.event,
          severity: alert.severity.toUpperCase(),
          source_system: this.SOURCE,
          details: JSON.stringify({
            server_name: alert.serverName,
            detected_value: alert.detectedValue,
            canonical_value: alert.canonicalValue,
            recommendation: alert.recommendation,
            mitiga_labs_attack_reference: 'Claude Code MCP OAuth Interception, 2026-04-10',
          }),
          created_at: alert.timestamp.toISOString(),
        } as never);
      } catch (err) {
        // Never let audit logging block the caller
        console.error('[MCPTransportGuard] Failed to emit ASAF event:', err);
      }
    }
  }

  /**
   * Full pipeline: inspect a snapshot and immediately emit any alerts.
   * Returns the alert list so callers can take action in the UI.
   */
  static async inspectAndEmit(snapshot: ClaudeJsonSnapshot): Promise<MCPThreatAlert[]> {
    const alerts = this.inspect(snapshot);
    await this.emitAlerts(alerts);
    return alerts;
  }

  /**
   * Convenience: returns true if a snapshot is completely clean.
   */
  static isClean(snapshot: ClaudeJsonSnapshot): boolean {
    return this.inspect(snapshot).length === 0;
  }
}
