/**
 * ConnectorDAG — Iron Bank dag.Node pattern ported to TypeScript
 *
 * Content-addressing: SHA-256(action + symbol + time + sorted PQC pairs)
 * matches the Go ComputeHash() canonical form in pkg/dag/dag.go exactly.
 * Signing uses HMAC-SHA256 (Web Crypto API) as the browser-side analog
 * to ML-DSA-65; the Go backend can co-sign via the mitochondrial-proxy
 * adding an ml_dsa_signature when available.
 *
 * Every ConnectorSDK action (add, test, delete, learn, fail) writes one
 * immutable DAG node to connector_dag_nodes. Duplicate writes (same
 * content hash) are silently dropped — idempotent.
 */

import { supabase } from '@/integrations/supabase/client';

// ─────────────────────────────────────────────────────────────────────
// Types (mirror Iron Bank dag.Node)
// ─────────────────────────────────────────────────────────────────────

export type ConnectorAction =
  | 'connector.add'
  | 'connector.test'
  | 'connector.test.pass'
  | 'connector.test.fail'
  | 'connector.learn'          // AI Learning Mode triggered
  | 'connector.pattern.evolve' // codex-orchestrator generated a pattern
  | 'connector.delete'
  | 'connector.license.issue'
  | 'connector.pqc.session';

export interface DAGNode {
  nodeHash: string;         // SHA-256 content address
  parentHashes: string[];   // links to parent nodes
  action: ConnectorAction;
  symbol: string;           // Adinkra symbol / source agent name
  actorId?: string;
  organizationId: string;
  connectorId?: string;
  pqcMetadata: PQCMetadata;
  hmacSignature?: string;   // HMAC-SHA256(nodeHash, sessionSecret)
  mlDsaSignature?: string;  // populated by mitochondrial-proxy Go backend
  createdAt: string;
}

export interface PQCMetadata {
  tier?: 'community' | 'professional' | 'enterprise' | 'partner';
  threatLevel?: 'green' | 'yellow' | 'orange' | 'red';
  certainty?: number;       // 0.0–1.0
  scopes?: string[];
  provider?: string;
  errorCode?: string;
  httpStatus?: number;
  [key: string]: unknown;
}

// ─────────────────────────────────────────────────────────────────────
// Content hashing — matches Go ComputeHash() canonical form
// ─────────────────────────────────────────────────────────────────────

async function sha256Hex(data: string): Promise<string> {
  const encoded = new TextEncoder().encode(data);
  const buf = await crypto.subtle.digest('SHA-256', encoded);
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Computes the canonical content hash for a DAG node.
 * Mirrors Iron Bank dag.ComputeHash() exactly:
 *   canonical = JSON({ action, symbol, time, parents: sorted[], pqc: sorted k=v[] })
 *   hash = SHA-256(canonical)
 */
async function computeHash(
  action: ConnectorAction,
  symbol: string,
  time: string,
  parents: string[],
  pqc: PQCMetadata
): Promise<string> {
  const sortedParents = [...parents].sort();
  const pqcPairs = Object.entries(pqc)
    .filter(([, v]) => v !== undefined && v !== null)
    .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(',') : String(v)}`)
    .sort();

  const canonical = JSON.stringify({
    action,
    symbol,
    time,
    parents: sortedParents,
    pqc: pqcPairs,
  });

  return sha256Hex(canonical);
}

// ─────────────────────────────────────────────────────────────────────
// HMAC-SHA256 signing (browser-side PQC analog)
// ─────────────────────────────────────────────────────────────────────

async function hmacSign(nodeHash: string, secret: string): Promise<string> {
  if (!secret) return '';
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', keyMaterial, new TextEncoder().encode(nodeHash));
  return Array.from(new Uint8Array(sig))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// ─────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────

export interface WriteNodeInput {
  action: ConnectorAction;
  symbol: string;           // e.g. 'connector-sdk', 'learning-mode', 'wedjat-stig'
  organizationId: string;
  connectorId?: string;
  parentHashes?: string[];
  pqcMetadata?: PQCMetadata;
  /** Session-derived secret for HMAC signing (from PQC-OAuth session) */
  sessionSecret?: string;
}

/**
 * Writes an immutable DAG node for a ConnectorSDK action.
 * Returns the node_hash (content address) for chaining subsequent nodes.
 * Duplicate hashes are silently dropped (ON CONFLICT DO NOTHING).
 * Never throws — DAG write failure must not block the originating action.
 */
export async function writeDAGNode(input: WriteNodeInput): Promise<string> {
  try {
    const { data: authData } = await supabase.auth.getUser();
    const actorId = authData?.user?.id;

    const time = new Date().toISOString();
    const parents = input.parentHashes ?? [];
    const pqc: PQCMetadata = {
      tier: 'community',
      threatLevel: 'green',
      certainty: 1.0,
      ...input.pqcMetadata,
    };

    const nodeHash = await computeHash(input.action, input.symbol, time, parents, pqc);
    const hmacSignature = input.sessionSecret
      ? await hmacSign(nodeHash, input.sessionSecret)
      : undefined;

    const row = {
      node_hash: nodeHash,
      parent_hashes: parents,
      action: input.action,
      symbol: input.symbol,
      actor_id: actorId ?? null,
      organization_id: input.organizationId,
      connector_id: input.connectorId ?? null,
      pqc_metadata: pqc,
      hmac_signature: hmacSignature ?? null,
      created_at: time,
    };

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { error } = await (supabase as any)
      .from('connector_dag_nodes')
      .insert(row)
      .select('node_hash')
      .single();

    if (error && error.code !== '23505') {
      // 23505 = unique_violation — duplicate hash is expected and fine
      console.error('[ConnectorDAG] write error:', error.message);
    }

    return nodeHash;
  } catch (err) {
    console.error('[ConnectorDAG] unexpected error:', err);
    return '';
  }
}

/**
 * Logs a connector failure for AI Learning Mode.
 * Associates the failure with its DAG node for full traceability.
 */
export async function logConnectorFailure(params: {
  organizationId: string;
  connectorId: string;
  provider: string;
  errorCode?: string;
  errorBody?: Record<string, unknown>;
  httpStatus?: number;
  dagNodeHash?: string;
}): Promise<void> {
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { error } = await (supabase as any).from('connector_failure_log').insert({
      organization_id: params.organizationId,
      connector_id: params.connectorId,
      provider: params.provider,
      error_code: params.errorCode ?? null,
      error_body: params.errorBody ?? {},
      http_status: params.httpStatus ?? null,
      dag_node_hash: params.dagNodeHash ?? null,
      pattern_generated: false,
    });
    if (error) console.error('[ConnectorDAG] failure log error:', error.message);
  } catch (err) {
    console.error('[ConnectorDAG] failure log unexpected error:', err);
  }
}

/**
 * Records a billable usage event linked to the DAG node.
 */
export async function recordUsageEvent(params: {
  organizationId: string;
  action: ConnectorAction;
  provider?: string;
  dagNodeHash?: string;
  billable?: boolean;
  costUnits?: number;
  licenseId?: string;
  sessionId?: string;
}): Promise<void> {
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { error } = await (supabase as any).from('connector_usage_events').insert({
      organization_id: params.organizationId,
      license_id: params.licenseId ?? null,
      session_id: params.sessionId ?? null,
      dag_node_hash: params.dagNodeHash ?? null,
      action: params.action,
      provider: params.provider ?? null,
      billable: params.billable ?? false,
      cost_units: params.costUnits ?? 0,
    });
    if (error) console.error('[ConnectorDAG] usage event error:', error.message);
  } catch (err) {
    console.error('[ConnectorDAG] usage event unexpected error:', err);
  }
}

/**
 * Fetches the DAG chain for a connector (most recent first).
 */
export async function getConnectorDAGChain(
  connectorId: string,
  limit = 50
): Promise<DAGNode[]> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { data, error } = await (supabase as any)
    .from('connector_dag_nodes')
    .select('*')
    .eq('connector_id', connectorId)
    .order('created_at', { ascending: false })
    .limit(limit);

  if (error) throw new Error(`DAG chain fetch failed: ${error.message}`);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return ((data as any[]) ?? []).map((row: any) => ({
    nodeHash: row.node_hash,
    parentHashes: row.parent_hashes ?? [],
    action: row.action as ConnectorAction,
    symbol: row.symbol,
    actorId: row.actor_id ?? undefined,
    organizationId: row.organization_id,
    connectorId: row.connector_id ?? undefined,
    pqcMetadata: (row.pqc_metadata as PQCMetadata) ?? {},
    hmacSignature: row.hmac_signature ?? undefined,
    mlDsaSignature: row.ml_dsa_signature ?? undefined,
    createdAt: row.created_at,
  }));
}
