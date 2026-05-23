import { useMemo, useCallback } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  Node,
  Edge,
  Position,
  MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { useKhepraAPI, DAGNode } from '@/hooks/useKhepraAPI';
import { useKhepraDAGUpdates } from '@/hooks/useKhepraWebSocket';
import {
  Network,
  RefreshCw,
  Wifi,
  WifiOff,
  Shield,
  Bug,
  CheckCircle,
  FileText,
  Lock,
  Loader2,
} from 'lucide-react';

interface KhepraDAGVisualizationProps {
  deploymentUrl: string;
  apiKey: string;
  height?: number;
}

// Custom node component colors - Premium Palette
const nodeColors: Record<string, string> = {
  scan: '#3b82f6',         // blue
  finding: '#ef4444',      // red
  remediation: '#22c55e',  // green
  attestation: '#8b5cf6',  // purple
  ert: '#f59e0b',          // amber
  genesis: '#06b6d4',      // cyan
};

const nodeIcons: Record<string, React.ReactNode> = {
  scan: <Shield className="h-4 w-4" />,
  finding: <Bug className="h-4 w-4" />,
  remediation: <CheckCircle className="h-4 w-4" />,
  attestation: <FileText className="h-4 w-4" />,
  ert: <Lock className="h-4 w-4" />,
  genesis: <Network className="h-4 w-4" />,
};

function transformDAGToFlow(dagNodes: DAGNode[]): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const nodeMap = new Map<string, DAGNode>();

  // Build node map
  dagNodes.forEach((node) => {
    nodeMap.set(node.node_id, node);
  });

  // Calculate positions using a simple layout algorithm
  const levels = new Map<string, number>();

  function calculateLevel(nodeId: string): number {
    if (levels.has(nodeId)) return levels.get(nodeId)!;

    const node = nodeMap.get(nodeId);
    if (!node || node.parents.length === 0) {
      levels.set(nodeId, 0);
      return 0;
    }

    const parentLevels = node.parents
      .map((parentId) => calculateLevel(parentId))
      .filter((l) => l >= 0);

    const level = parentLevels.length > 0 ? Math.max(...parentLevels) + 1 : 0;
    levels.set(nodeId, level);
    return level;
  }

  // Calculate levels for all nodes
  dagNodes.forEach((node) => calculateLevel(node.node_id));

  // Group nodes by level
  const levelGroups = new Map<number, string[]>();
  levels.forEach((level, nodeId) => {
    if (!levelGroups.has(level)) {
      levelGroups.set(level, []);
    }
    levelGroups.get(level)!.push(nodeId);
  });

  // Create nodes with positions
  dagNodes.forEach((dagNode) => {
    const level = levels.get(dagNode.node_id) || 0;
    const levelNodes = levelGroups.get(level) || [];
    const indexInLevel = levelNodes.indexOf(dagNode.node_id);
    const totalInLevel = levelNodes.length;

    const x = 200 + level * 250;
    const y = 100 + indexInLevel * 100 - ((totalInLevel - 1) * 50);

    nodes.push({
      id: dagNode.node_id,
      type: 'default',
      position: { x, y },
      data: {
        label: (
          <div className="flex flex-col items-center gap-1 p-2">
            <div className="flex items-center gap-1">
              {nodeIcons[dagNode.type] || <Network className="h-4 w-4" />}
              <span className="text-[10px] font-black italic uppercase tracking-tighter capitalize">{dagNode.type}</span>
            </div>
            <div className="text-[8px] text-white/40 font-mono">
              {dagNode.node_id.slice(0, 12)}...
            </div>
            {dagNode.verified && (
              <Badge variant="outline" className="text-[8px] px-1 py-0 text-emerald-400 border-emerald-500/30 bg-emerald-500/10 uppercase font-black">
                PQC Secured
              </Badge>
            )}
          </div>
        ),
      },
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
      style: {
        background: 'rgba(0, 0, 0, 0.6)',
        color: 'white',
        borderRadius: '12px',
        padding: '2px',
        minWidth: '140px',
        border: `1px solid ${nodeColors[dagNode.type] || '#444'}`,
        boxShadow: `0 0 15px ${(nodeColors[dagNode.type] || '#444')}40`,
        backdropFilter: 'blur(10px)',
      },
    });

    // Create edges from parents
    dagNode.parents.forEach((parentId) => {
      if (nodeMap.has(parentId)) {
        edges.push({
          id: `${parentId}-${dagNode.node_id}`,
          source: parentId,
          target: dagNode.node_id,
          type: 'smoothstep',
          animated: true,
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: '#666',
          },
          style: {
            stroke: '#666',
            strokeWidth: 1.5,
            opacity: 0.4,
          },
        });
      }
    });
  });

  return { nodes, edges };
}

export function KhepraDAGVisualization({
  deploymentUrl,
  apiKey,
  height = 500,
}: KhepraDAGVisualizationProps) {
  const { dag } = useKhepraAPI(deploymentUrl, apiKey);
  const { isConnected, dagUpdates } = useKhepraDAGUpdates(deploymentUrl);

  const { initialNodes, initialEdges } = useMemo(() => {
    if (!dag.data?.nodes) {
      return { initialNodes: [], initialEdges: [] };
    }
    const { nodes, edges } = transformDAGToFlow(dag.data.nodes);
    return { initialNodes: nodes, initialEdges: edges };
  }, [dag.data?.nodes]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Update nodes when DAG data changes
  useMemo(() => {
    if (initialNodes.length > 0) {
      setNodes(initialNodes);
      setEdges(initialEdges);
    }
  }, [initialNodes, initialEdges, setNodes, setEdges]);

  const handleRefresh = useCallback(() => {
    dag.refetch();
  }, [dag]);

  return (
    <Card className="glass-card overflow-hidden border-white/5 shadow-2xl">
      <CardHeader className="border-b border-white/5 bg-white/2">
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2 text-xl font-black italic">
              <Network className="h-5 w-5 text-primary" />
              LIVING TRUST CONSTELLATION
            </CardTitle>
            <CardDescription className="text-muted-foreground uppercase text-[10px] tracking-widest font-bold">
              Immutable security event ledger • PQC Signed
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            {isConnected ? (
              <Badge variant="outline" className="text-primary border-primary/30 bg-primary/10 animate-pulse uppercase text-[9px]">
                <Wifi className="h-3 w-3 mr-1" />
                Linked
              </Badge>
            ) : (
              <Badge variant="outline" className="text-red-400 border-red-500/30 bg-red-500/10 uppercase text-[9px]">
                <WifiOff className="h-3 w-3 mr-1" />
                Detached
              </Badge>
            )}
            <Button variant="ghost" size="sm" onClick={handleRefresh} className="hover:bg-white/5">
              <RefreshCw className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-6">
        {/* Stats Bar */}
        {dag.data && (
          <div className="flex gap-4 mb-6 text-[10px] uppercase font-bold tracking-widest">
            <div className="bg-white/5 border border-white/5 rounded-full px-4 py-1.5 flex items-center gap-2">
              <span className="text-muted-foreground">Ledger Depth:</span>
              <span className="text-white italic">{dag.data.total_nodes}</span>
            </div>
            <div className="bg-white/5 border border-white/5 rounded-full px-4 py-1.5 flex items-center gap-2">
              <span className="text-muted-foreground">Genesis Nodes:</span>
              <span className="text-white italic">{dag.data.root_nodes.length}</span>
            </div>
            <div className="bg-primary/5 border border-primary/10 rounded-full px-4 py-1.5 flex items-center gap-2">
              <span className="text-primary/60">Real-time Stream:</span>
              <span className="text-primary italic">{dagUpdates.length} ev/s</span>
            </div>
          </div>
        )}

        {/* Legend */}
        <div className="flex flex-wrap gap-2 mb-6">
          {Object.entries(nodeColors).map(([type, color]) => (
            <div
              key={type}
              className="flex items-center gap-2 text-[9px] font-bold uppercase tracking-widest px-3 py-1.5 rounded-full border bg-white/2 transition-all hover:bg-white/5"
              style={{ borderColor: `${color}40`, color }}
            >
              {nodeIcons[type]}
              <span>{type}</span>
            </div>
          ))}
        </div>

        {/* Flow Diagram */}
        <div
          className="border border-white/10 rounded-xl overflow-hidden bg-black/40 backdrop-blur-3xl relative"
          style={{ height }}
        >
          {/* Cyber Overlay Grid */}
          <div className="absolute inset-0 bg-cyber-grid pointer-events-none opacity-20" />

          {dag.isLoading ? (
            <div className="flex items-center justify-center h-full">
              <Loader2 className="h-10 w-10 animate-spin text-primary/30" />
            </div>
          ) : nodes.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
              <Network className="h-12 w-12 mb-2 opacity-20" />
              <p className="font-black italic uppercase tracking-widest text-[10px]">Empty Constellation</p>
              <p className="text-[9px] uppercase tracking-tighter opacity-50">Node deployment pending</p>
            </div>
          ) : (
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              fitView
              attributionPosition="bottom-left"
              colorMode="dark"
            >
              <Background color="#111" gap={20} />
              <Controls className="bg-black/80 border-white/10 fill-white" />
              <MiniMap
                nodeColor={(node) => {
                  const type = nodes.find(n => n.id === node.id)?.id.includes('scan') ? 'scan' : 'default';
                  // Simple heuristic for minimap colors
                  return '#222';
                }}
                maskColor="rgba(0,0,0,0.8)"
                style={{ backgroundColor: '#000', border: '1px solid rgba(255,255,255,0.1)' }}
              />
            </ReactFlow>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
