/**
 * @souhimbou/dag-viewer — ASAF SSE Stream Client
 * SouHimBou AI ASAF Flight Recorder · NouchiX SecRed Knowledge Inc.
 *
 * Typed client for the ASAF binary REST + SSE API.
 * Works for both cloud (https://agent.souhimbou.ai) and
 * sovereign local (http://127.0.0.1:45444) profiles.
 */

import type { DAGNode, DAGEdge, SessionStats } from './DAGViewer'

// ── Config ───────────────────────────────────────────────────────────────────

export type ASAFMode = 'cloud' | 'sovereign'

export interface ASAFClientConfig {
  mode:          ASAFMode
  cloudUrl?:     string   // default: https://agent.souhimbou.ai
  sovereignUrl?: string   // default: http://127.0.0.1:45444
  authToken?:    string
}

const CLOUD_URL     = 'https://agent.souhimbou.ai'
const SOVEREIGN_URL = 'http://127.0.0.1:45444'

// ── Session types ─────────────────────────────────────────────────────────────

export interface ASAFSession {
  id:          string
  session_ref: string
  status:      'running' | 'complete' | 'failed'
  created_at:  string
  tool_calls:  number
  findings:    number
  attestations: number
  controls_mapped: number
}

export interface StreamHandlers {
  onNode?:  (node: DAGNode)       => void
  onEdge?:  (edge: DAGEdge)       => void
  onStats?: (stats: SessionStats) => void
  onError?: (err: Event)          => void
}

export interface DAGRecordPayload {
  type:       'dag_node' | 'dag_edge'
  session_id: string
  payload:    DAGNode | DAGEdge
}

// ── Client ───────────────────────────────────────────────────────────────────

export class ASAFClient {
  private readonly baseUrl:     string
  private readonly authToken?:  string

  constructor(config: ASAFClientConfig) {
    this.authToken = config.authToken
    this.baseUrl = config.mode === 'sovereign'
      ? (config.sovereignUrl ?? SOVEREIGN_URL)
      : (config.cloudUrl    ?? CLOUD_URL)
  }

  // ── REST ─────────────────────────────────────────────────────

  /** List all ASAF sessions for the authenticated tenant */
  async getSessions(): Promise<ASAFSession[]> {
    const res = await fetch(`${this.baseUrl}/api/v1/asaf/sessions`, {
      headers: this.authHeaders(),
    })
    if (!res.ok) throw new Error(`ASAF getSessions: ${res.status} ${res.statusText}`)
    return res.json() as Promise<ASAFSession[]>
  }

  /** Get a single session by ID */
  async getSession(sessionId: string): Promise<ASAFSession> {
    const res = await fetch(`${this.baseUrl}/api/v1/asaf/sessions/${sessionId}`, {
      headers: this.authHeaders(),
    })
    if (!res.ok) throw new Error(`ASAF getSession: ${res.status} ${res.statusText}`)
    return res.json() as Promise<ASAFSession>
  }

  /** Get the full DAG for a completed session */
  async getDag(sessionId: string): Promise<{ nodes: DAGNode[]; links: DAGEdge[] }> {
    const res = await fetch(`${this.baseUrl}/api/v1/asaf/sessions/${sessionId}/dag`, {
      headers: this.authHeaders(),
    })
    if (!res.ok) throw new Error(`ASAF getDag: ${res.status} ${res.statusText}`)
    return res.json() as Promise<{ nodes: DAGNode[]; links: DAGEdge[] }>
  }

  /** Write a DAG event (used by MCP interceptor or khepra-mcp Go server) */
  async record(payload: DAGRecordPayload): Promise<void> {
    const res = await fetch(`${this.baseUrl}/api/v1/asaf/record`, {
      method:  'POST',
      headers: { ...this.authHeaders(), 'Content-Type': 'application/json' },
      body:    JSON.stringify(payload),
    })
    if (!res.ok) throw new Error(`ASAF record: ${res.status} ${res.statusText}`)
  }

  // ── SSE Stream ──────────────────────────────────────────────

  /**
   * Subscribe to the live DAG event stream for a session.
   * Returns a cleanup function — call it to close the EventSource.
   *
   * @example
   * const stop = client.streamSession('sess-xxx', {
   *   onNode:  node  => addToGraph(node),
   *   onEdge:  edge  => addToGraph(edge),
   *   onStats: stats => updateHeader(stats),
   * })
   * // later: stop()
   */
  streamSession(sessionId: string, handlers: StreamHandlers): () => void {
    const url = this.streamUrl(sessionId)
    const es  = new EventSource(url)

    es.addEventListener('dag_node',      (e: MessageEvent) => handlers.onNode?.(JSON.parse(e.data)))
    es.addEventListener('dag_edge',      (e: MessageEvent) => handlers.onEdge?.(JSON.parse(e.data)))
    es.addEventListener('session_stats', (e: MessageEvent) => handlers.onStats?.(JSON.parse(e.data)))
    es.addEventListener('error',         (e: Event)        => handlers.onError?.(e))

    return () => es.close()
  }

  /**
   * Subscribe to ALL sessions (admin stream).
   * Useful for the dashboard overview page.
   */
  streamAll(handlers: StreamHandlers): () => void {
    const url = `${this.baseUrl}/api/v1/asaf/stream`
      + (this.authToken ? `?token=${encodeURIComponent(this.authToken)}` : '')
    const es = new EventSource(url)

    es.addEventListener('dag_node',      (e: MessageEvent) => handlers.onNode?.(JSON.parse(e.data)))
    es.addEventListener('dag_edge',      (e: MessageEvent) => handlers.onEdge?.(JSON.parse(e.data)))
    es.addEventListener('session_stats', (e: MessageEvent) => handlers.onStats?.(JSON.parse(e.data)))
    es.addEventListener('error',         (e: Event)        => handlers.onError?.(e))

    return () => es.close()
  }

  // ── Helpers ─────────────────────────────────────────────────

  get streamBaseUrl(): string { return this.baseUrl }

  streamUrl(sessionId: string): string {
    const base = `${this.baseUrl}/api/v1/asaf/stream?session=${encodeURIComponent(sessionId)}`
    return this.authToken ? `${base}&token=${encodeURIComponent(this.authToken)}` : base
  }

  private authHeaders(): Record<string, string> {
    return this.authToken ? { Authorization: `Bearer ${this.authToken}` } : {}
  }
}

// ── React Hook ───────────────────────────────────────────────────────────────

/**
 * useASAFStream — React hook that connects to the ASAF SSE stream
 * and accumulates DAG nodes/edges into state.
 *
 * @example
 * const { nodes, links, stats, connected } = useASAFStream({
 *   client,
 *   sessionId: 'sess-xxx',
 * })
 */
export interface UseASAFStreamOptions {
  client:     ASAFClient
  sessionId:  string
  enabled?:   boolean
}

export interface UseASAFStreamResult {
  nodes:     DAGNode[]
  links:     DAGEdge[]
  stats:     SessionStats | null
  connected: boolean
  error:     Event | null
}

// Hook (use in React components only)
export function useASAFStream({
  client,
  sessionId,
  enabled = true,
}: UseASAFStreamOptions): UseASAFStreamResult {
  // Lazy import React inside the hook so this file works in non-React contexts too
  const { useState, useEffect } = require('react') as typeof import('react')

  const [nodes, setNodes]         = useState<DAGNode[]>([])
  const [links, setLinks]         = useState<DAGEdge[]>([])
  const [stats, setStats]         = useState<SessionStats | null>(null)
  const [connected, setConnected] = useState(false)
  const [error, setError]         = useState<Event | null>(null)

  useEffect(() => {
    if (!enabled || !sessionId) return

    setConnected(true)
    const stop = client.streamSession(sessionId, {
      onNode:  node => setNodes(prev => [...prev.filter(n => n.id !== node.id), node]),
      onEdge:  edge => setLinks(prev => [...prev, edge]),
      onStats: s    => setStats(s),
      onError: e    => { setError(e); setConnected(false) },
    })

    return () => { stop(); setConnected(false) }
  }, [client, sessionId, enabled])

  return { nodes, links, stats, connected, error }
}
