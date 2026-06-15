'use client'
/**
 * @souhimbou/dag-viewer — DAGViewer React Component
 * SouHimBou AI ASAF Flight Recorder · NouchiX SecRed Knowledge Inc.
 *
 * Renders a 3D force-directed graph of KHEPRA MCP DAG audit events.
 * Supports both live SSE streaming and static session data.
 */

import { useEffect, useRef, useState, useCallback, CSSProperties } from 'react'
import ForceGraph3D from 'react-force-graph-3d'
import type { ForceGraphMethods, NodeObject, LinkObject } from 'react-force-graph-3d'

// ── Types ────────────────────────────────────────────────────────────────────

export type DAGNodeType = 'prompt' | 'tool' | 'finding' | 'control' | 'attest'
export type Severity    = 'CAT_I' | 'CAT_II' | 'CAT_III'

export interface DAGNode {
  id:          string
  label:       string
  type:        DAGNodeType
  severity?:   Severity
  desc?:       string
  impact?:     string
  remediation_cost?: string
  roi?:        string
  sig?:        string            // ML-DSA-65 signature hex
  framework?:  string
  tool_args?:  Record<string, unknown>
  ts?:         string
  val?:        number
  // Three.js coordinates (set by force graph)
  x?: number; y?: number; z?: number
}

export interface DAGEdge {
  source: string | DAGNode
  target: string | DAGNode
  w?:     number
}

export interface SessionStats {
  tool_calls:     number
  findings:       number
  attestations:   number
  controls_mapped: number
}

export interface DAGViewerProps {
  /** SSE URL: /api/v1/asaf/stream?session=<id>  */
  streamUrl?: string
  /** Static data (no streaming) */
  sessionData?: { nodes: DAGNode[]; links: DAGEdge[] }
  /** Bearer token for auth header */
  authToken?: string
  /** Display mode */
  mode?: 'dag' | 'compliance' | 'live'
  /** Container height (px). Defaults to fill parent */
  height?: number | string
  /** Called when user clicks a node */
  onNodeClick?: (node: DAGNode) => void
  /** Called when session stats update via SSE */
  onSessionStats?: (stats: SessionStats) => void
  showLegend?:    boolean
  showWatermark?: boolean
  className?: string
  style?: CSSProperties
}

// ── Color System ─────────────────────────────────────────────────────────────

const COLORS: Record<string, string> = {
  prompt:          '#818cf8',   // NouchiX indigo
  tool:            '#e5a54b',   // AdinKhepra gold
  finding_CAT_I:   '#cc2a36',   // critical red
  finding_CAT_II:  '#f97316',   // orange
  finding_CAT_III: '#22c55e',   // green
  control:         '#22c55e',   // SouHimBou green
  attest:          '#06b6d4',   // SouHimBou cyan
  default:         '#3d5a78',   // muted blue-grey
}

function nodeColor(n: DAGNode): string {
  if (n.type === 'finding') return COLORS[`finding_${n.severity}`] ?? '#cc2a36'
  return COLORS[n.type] ?? COLORS.default
}

function nodeVal(n: DAGNode): number {
  switch (n.type) {
    case 'prompt':  return 22
    case 'finding': return n.severity === 'CAT_I' ? 18 : n.severity === 'CAT_II' ? 13 : 9
    case 'tool':    return n.val ?? 12
    case 'control': return 7
    case 'attest':  return 5
    default:        return n.val ?? 6
  }
}

// ── Tooltip HTML ─────────────────────────────────────────────────────────────

function tooltipHtml(n: DAGNode): string {
  const col = nodeColor(n)
  const type = n.type === 'finding'
    ? `FINDING · ${n.severity}`
    : n.type.toUpperCase()
  const extra = n.impact
    ? `<br/><span style="color:#6b8aaa">impact </span><span style="color:#e5a54b">${n.impact}</span>
       <br/><span style="color:#6b8aaa">roi    </span><span style="color:#22c55e">${n.roi ?? '—'}</span>`
    : n.type === 'attest' && n.sig
    ? `<br/><span style="color:#6b8aaa">sig </span><span style="color:#06b6d4;font-size:9px">${n.sig.slice(0, 18)}…</span>`
    : n.framework
    ? `<br/><span style="color:#6b8aaa">${n.framework}</span>`
    : ''
  return `<div style="font-family:'JetBrains Mono',monospace;padding:8px 10px;border-left:2px solid ${col}">
    <div style="color:${col};font-weight:700;font-size:12px">${n.label}</div>
    <div style="color:#6b8aaa;font-size:8px;letter-spacing:1px;margin:2px 0">${type}</div>
    <div style="color:#e0eaf5;font-size:11px">${n.desc ?? ''}</div>
    ${extra}
  </div>`
}

// ── Legend ───────────────────────────────────────────────────────────────────

const LEGEND = [
  { color: '#818cf8', label: 'AI Prompt' },
  { color: '#e5a54b', label: 'Tool Execution' },
  { color: '#cc2a36', label: 'Finding · CAT I' },
  { color: '#f97316', label: 'Finding · CAT II' },
  { color: '#22c55e', label: 'Control Satisfied' },
  { color: '#06b6d4', label: 'ML-DSA-65 Attest' },
]

// ── Component ─────────────────────────────────────────────────────────────────

type GraphData = { nodes: DAGNode[]; links: DAGEdge[] }
const EMPTY: GraphData = { nodes: [], links: [] }

export function DAGViewer({
  streamUrl,
  sessionData,
  authToken,
  mode = 'dag',
  height = 600,
  onNodeClick,
  onSessionStats,
  showLegend   = true,
  showWatermark = true,
  className,
  style,
}: DAGViewerProps) {
  const [graphData, setGraphData] = useState<GraphData>(sessionData ?? EMPTY)
  const fgRef = useRef<ForceGraphMethods<NodeObject, LinkObject>>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const [dimensions, setDimensions] = useState({ w: 0, h: 0 })

  // Sync static data
  useEffect(() => {
    if (sessionData) setGraphData(sessionData)
  }, [sessionData])

  // SSE live stream
  useEffect(() => {
    if (!streamUrl) return
    const url = authToken ? `${streamUrl}&token=${encodeURIComponent(authToken)}` : streamUrl
    const es = new EventSource(url)

    const onNode = (e: MessageEvent) => {
      const node: DAGNode = JSON.parse(e.data)
      setGraphData(prev => ({
        ...prev,
        nodes: [...prev.nodes.filter(n => n.id !== node.id), node],
      }))
    }
    const onEdge = (e: MessageEvent) => {
      const edge: DAGEdge = JSON.parse(e.data)
      setGraphData(prev => ({ ...prev, links: [...prev.links, edge] }))
    }
    const onStats = (e: MessageEvent) => {
      onSessionStats?.(JSON.parse(e.data))
    }

    es.addEventListener('dag_node', onNode)
    es.addEventListener('dag_edge', onEdge)
    es.addEventListener('session_stats', onStats)

    return () => es.close()
  }, [streamUrl, authToken, onSessionStats])

  // Resize observer
  useEffect(() => {
    if (!containerRef.current) return
    const ro = new ResizeObserver(entries => {
      const e = entries[0]
      setDimensions({ w: e.contentRect.width, h: e.contentRect.height })
    })
    ro.observe(containerRef.current)
    return () => ro.disconnect()
  }, [])

  // Auto-fit after data loads
  useEffect(() => {
    const t = setTimeout(() => fgRef.current?.zoomToFit(400, 80), 1000)
    return () => clearTimeout(t)
  }, [graphData.nodes.length])

  // Node click with camera pan
  const handleClick = useCallback((node: NodeObject) => {
    const n = node as DAGNode
    onNodeClick?.(n)
    const dist = 120
    const dr = 1 + dist / Math.hypot(n.x ?? 1, n.y ?? 1, n.z ?? 1)
    fgRef.current?.cameraPosition(
      { x: (n.x ?? 0) * dr, y: (n.y ?? 0) * dr, z: (n.z ?? 0) * dr },
      { x: n.x ?? 0, y: n.y ?? 0, z: n.z ?? 0 },
      700
    )
  }, [onNodeClick])

  const containerStyle: CSSProperties = {
    position: 'relative',
    height,
    background: '#050c16',
    borderRadius: 8,
    overflow: 'hidden',
    ...style,
  }

  return (
    <div ref={containerRef} className={className} style={containerStyle}>
      <ForceGraph3D
        ref={fgRef}
        width={dimensions.w || undefined}
        height={typeof height === 'number' ? height : dimensions.h || undefined}
        graphData={graphData as { nodes: NodeObject[]; links: LinkObject[] }}
        backgroundColor="#050c16"
        nodeId="id"
        nodeLabel={(n: NodeObject) => tooltipHtml(n as DAGNode)}
        nodeColor={(n: NodeObject) => nodeColor(n as DAGNode)}
        nodeVal={(n: NodeObject) => nodeVal(n as DAGNode)}
        nodeOpacity={0.95}
        nodeResolution={18}
        linkColor={() => '#1a4f7a'}
        linkOpacity={0.45}
        linkWidth={(l: LinkObject) => 0.5 + (((l as DAGEdge).w) ?? 1) * 0.5}
        linkDirectionalParticles={(l: LinkObject) => (((l as DAGEdge).w) ?? 1) > 1 ? 3 : 1}
        linkDirectionalParticleColor={() => '#1a9fe8'}
        linkDirectionalParticleWidth={1.2}
        linkDirectionalParticleSpeed={0.005}
        onNodeClick={handleClick}
        onNodeHover={(n: NodeObject | null) => {
          if (containerRef.current) containerRef.current.style.cursor = n ? 'pointer' : 'default'
        }}
        d3AlphaDecay={0.02}
        d3VelocityDecay={0.3}
      />

      {showLegend && (
        <div style={{
          position: 'absolute', top: 14, left: 14,
          background: 'rgba(5,12,22,.9)', border: '1px solid rgba(26,159,232,.35)',
          borderRadius: 6, padding: '10px 12px', pointerEvents: 'none',
          backdropFilter: 'blur(8px)',
        }}>
          <div style={{ fontFamily: 'monospace', fontSize: 8, color: '#6b8aaa', letterSpacing: 2, textTransform: 'uppercase', marginBottom: 8 }}>
            Node Legend
          </div>
          {LEGEND.map(({ color, label }) => (
            <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 5, fontSize: 10, color: '#e0eaf5', fontFamily: 'monospace' }}>
              <div style={{ width: 8, height: 8, borderRadius: '50%', background: color, flexShrink: 0 }} />
              {label}
            </div>
          ))}
        </div>
      )}

      {showWatermark && (
        <div style={{ position: 'absolute', bottom: 14, right: 14, textAlign: 'right', opacity: 0.4, fontFamily: 'monospace', fontSize: 9, color: '#6b8aaa', lineHeight: 1.6, pointerEvents: 'none' }}>
          <span style={{ color: '#1a9fe8', display: 'block', fontWeight: 700 }}>NouchiX SecRed</span>
          SouHimBou ASAF · AdinKhepra
        </div>
      )}

      <div style={{ position: 'absolute', bottom: 14, left: '50%', transform: 'translateX(-50%)', fontFamily: 'monospace', fontSize: 9, color: '#3d5a78', pointerEvents: 'none', whiteSpace: 'nowrap' }}>
        drag · scroll · click a node to inspect
      </div>
    </div>
  )
}
