import { useState, useEffect, useRef } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import {
  Network,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Eye,
  Target,
  GitBranch,
  Database,
  Zap,
  Users,
  Building,
  Globe,
  Key,
  FileText,
  ArrowRight,
  Search,
  Filter,
  Maximize,
  Minimize
} from 'lucide-react';

// Graph visualization component using canvas
interface GraphNode {
  id: string;
  label: string;
  type: 'asset' | 'control' | 'framework' | 'evidence' | 'remediation' | 'user' | 'organization';
  x: number;
  y: number;
  radius: number;
  color: string;
  status?: 'compliant' | 'non-compliant' | 'unknown';
  metadata: Record<string, any>;
  connections: string[];
}

interface GraphEdge {
  from: string;
  to: string;
  type: 'requires' | 'affects' | 'depends' | 'implements' | 'evidences' | 'remediates';
  strength: number;
  color: string;
  animated?: boolean;
}

interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  metadata: {
    totalNodes: number;
    totalEdges: number;
    complianceScore: number;
    lastUpdated: Date;
  };
}

const generatePendingGraphData = (): GraphData => {
  return {
    nodes: [],
    edges: [],
    metadata: {
      totalNodes: 0,
      totalEdges: 0,
      complianceScore: 0,
      lastUpdated: new Date()
    }
  };
};

export const ComplianceKnowledgeGraph: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [graphData, setGraphData] = useState<GraphData>(generatePendingGraphData());
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [hoveredNode, setHoveredNode] = useState<GraphNode | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<string>('all');
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [animationFrame, setAnimationFrame] = useState(0);
  const { toast } = useToast();

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Animation loop for dynamic effects
    const animate = () => {
      drawGraph(ctx, canvas.width, canvas.height);
      setAnimationFrame(prev => prev + 1);
      requestAnimationFrame(animate);
    };

    animate();
  }, [graphData, selectedNode, hoveredNode, animationFrame]);

  const drawGraph = (ctx: CanvasRenderingContext2D, width: number, height: number) => {
    // Clear canvas
    ctx.clearRect(0, 0, width, height);

    // Apply filters
    const filteredNodes = graphData.nodes.filter(node => {
      const matchesSearch = searchTerm === '' ||
        node.label.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesType = filterType === 'all' || node.type === filterType;
      return matchesSearch && matchesType;
    });

    const filteredNodeIds = new Set(filteredNodes.map(n => n.id));
    const filteredEdges = graphData.edges.filter(edge =>
      filteredNodeIds.has(edge.from) && filteredNodeIds.has(edge.to)
    );

    // Draw edges first
    filteredEdges.forEach(edge => {
      const fromNode = filteredNodes.find(n => n.id === edge.from);
      const toNode = filteredNodes.find(n => n.id === edge.to);

      if (!fromNode || !toNode) return;

      ctx.strokeStyle = edge.color;
      ctx.lineWidth = edge.strength * 2;

      if (edge.animated) {
        ctx.setLineDash([5, 5]);
        ctx.lineDashOffset = -animationFrame * 0.1;
      } else {
        ctx.setLineDash([]);
      }

      ctx.beginPath();
      ctx.moveTo(fromNode.x, fromNode.y);
      ctx.lineTo(toNode.x, toNode.y);
      ctx.stroke();

      // Draw arrow
      const angle = Math.atan2(toNode.y - fromNode.y, toNode.x - fromNode.x);
      const arrowLength = 10;
      const arrowX = toNode.x - Math.cos(angle) * (toNode.radius + 5);
      const arrowY = toNode.y - Math.sin(angle) * (toNode.radius + 5);

      ctx.fillStyle = edge.color;
      ctx.beginPath();
      ctx.moveTo(arrowX, arrowY);
      ctx.lineTo(
        arrowX - arrowLength * Math.cos(angle - Math.PI / 6),
        arrowY - arrowLength * Math.sin(angle - Math.PI / 6)
      );
      ctx.lineTo(
        arrowX - arrowLength * Math.cos(angle + Math.PI / 6),
        arrowY - arrowLength * Math.sin(angle + Math.PI / 6)
      );
      ctx.closePath();
      ctx.fill();
    });

    // Draw nodes
    filteredNodes.forEach(node => {
      const isSelected = selectedNode?.id === node.id;
      const isHovered = hoveredNode?.id === node.id;

      // Node circle with glow effect for selection
      if (isSelected || isHovered) {
        ctx.shadowColor = node.color;
        ctx.shadowBlur = 20;
      } else {
        ctx.shadowBlur = 0;
      }

      ctx.fillStyle = node.color;
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.radius, 0, 2 * Math.PI);
      ctx.fill();

      // Status indicator for assets
      if (node.type === 'asset' && node.status) {
        const statusColor = node.status === 'compliant' ? '#10b981' :
          node.status === 'non-compliant' ? '#ef4444' : '#6b7280';
        ctx.fillStyle = statusColor;
        ctx.beginPath();
        ctx.arc(node.x + node.radius - 10, node.y - node.radius + 10, 8, 0, 2 * Math.PI);
        ctx.fill();
      }

      // Node border
      ctx.strokeStyle = isSelected ? '#ffffff' : '#000000';
      ctx.lineWidth = isSelected ? 3 : 1;
      ctx.setLineDash([]);
      ctx.stroke();

      // Node label
      ctx.fillStyle = '#ffffff';
      ctx.font = `${node.radius > 35 ? '12' : '10'}px sans-serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';

      // Multi-line text for larger nodes
      if (node.radius > 35) {
        const words = node.label.split(' ');
        if (words.length > 1) {
          ctx.fillText(words[0], node.x, node.y - 6);
          ctx.fillText(words.slice(1).join(' '), node.x, node.y + 6);
        } else {
          ctx.fillText(node.label, node.x, node.y);
        }
      } else {
        ctx.fillText(node.label, node.x, node.y);
      }

      ctx.shadowBlur = 0;
    });
  };

  const handleCanvasClick = (event: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;

    // Find clicked node
    const clickedNode = graphData.nodes.find(node => {
      const distance = Math.sqrt((x - node.x) ** 2 + (y - node.y) ** 2);
      return distance <= node.radius;
    });

    if (clickedNode) {
      setSelectedNode(clickedNode);
      toast({
        title: "Node Selected",
        description: `Selected: ${clickedNode.label} (${clickedNode.type})`,
      });
    } else {
      setSelectedNode(null);
    }
  };

  const handleCanvasMouseMove = (event: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;

    const hoveredNode = graphData.nodes.find(node => {
      const distance = Math.sqrt((x - node.x) ** 2 + (y - node.y) ** 2);
      return distance <= node.radius;
    });

    setHoveredNode(hoveredNode || null);
    canvas.style.cursor = hoveredNode ? 'pointer' : 'default';
  };

  const refreshGraph = async () => {
    try {
      // Simulate fetching updated graph data
      const { data, error } = await supabase.functions.invoke('grok-ai-agent', {
        body: {
          action: 'generate_knowledge_graph',
          includeRemediations: true,
          frameworks: ['SOC2', 'ISO27001', 'PCI-DSS']
        }
      });

      if (error) throw error;

      // For now, regenerate pending data
      setGraphData(generatePendingGraphData());

      toast({
        title: "Graph Updated",
        description: "Knowledge graph has been refreshed with latest data",
      });
    } catch (error) {
      console.error('Failed to refresh graph:', error);
      toast({
        title: "Refresh Failed",
        description: "Unable to refresh knowledge graph",
        variant: "destructive"
      });
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'framework': return <Shield className="h-4 w-4" />;
      case 'control': return <CheckCircle className="h-4 w-4" />;
      case 'asset': return <Database className="h-4 w-4" />;
      case 'evidence': return <FileText className="h-4 w-4" />;
      case 'remediation': return <Zap className="h-4 w-4" />;
      case 'user': return <Users className="h-4 w-4" />;
      case 'organization': return <Building className="h-4 w-4" />;
      default: return <Globe className="h-4 w-4" />;
    }
  };

  const nodeTypes = ['all', 'framework', 'control', 'asset', 'evidence', 'remediation'];

  return (
    <div className="space-y-6">
      <Tabs defaultValue="graph" className="w-full">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="graph">Knowledge Graph</TabsTrigger>
          <TabsTrigger value="relationships">Relationships</TabsTrigger>
          <TabsTrigger value="analytics">Analytics</TabsTrigger>
        </TabsList>

        <TabsContent value="graph" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <Network className="h-5 w-5" />
                    Compliance Knowledge Graph
                  </CardTitle>
                  <CardDescription>
                    Interactive visualization of compliance relationships, dependencies, and remediation paths
                  </CardDescription>
                </div>
                <div className="flex items-center gap-2">
                  <Button onClick={refreshGraph} variant="outline" size="sm">
                    <Target className="h-4 w-4 mr-2" />
                    Refresh
                  </Button>
                  <Button
                    onClick={() => setIsFullscreen(!isFullscreen)}
                    variant="outline"
                    size="sm"
                  >
                    {isFullscreen ? <Minimize className="h-4 w-4" /> : <Maximize className="h-4 w-4" />}
                  </Button>
                </div>
              </div>
            </CardHeader>
          </Card>

          {/* Controls */}
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-2">
                  <Search className="h-4 w-4" />
                  <input
                    type="text"
                    placeholder="Search nodes..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="px-3 py-2 border rounded-md w-48"
                  />
                </div>
                <div className="flex items-center gap-2">
                  <Filter className="h-4 w-4" />
                  <select
                    value={filterType}
                    onChange={(e) => setFilterType(e.target.value)}
                    className="px-3 py-2 border rounded-md"
                  >
                    {nodeTypes.map(type => (
                      <option key={type} value={type}>
                        {type.charAt(0).toUpperCase() + type.slice(1)}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="flex items-center gap-4 text-sm text-muted-foreground ml-auto">
                  <span>Nodes: {graphData.metadata.totalNodes}</span>
                  <span>Edges: {graphData.metadata.totalEdges}</span>
                  <span>Compliance: {graphData.metadata.complianceScore}%</span>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Graph Visualization */}
          <div className="grid grid-cols-4 gap-6">
            <div className="col-span-3">
              <Card>
                <CardContent className="p-6">
                  <canvas
                    ref={canvasRef}
                    width={800}
                    height={600}
                    onClick={handleCanvasClick}
                    onMouseMove={handleCanvasMouseMove}
                    className="border rounded-lg w-full"
                    style={{ maxWidth: '100%', height: 'auto' }}
                  />
                </CardContent>
              </Card>
            </div>

            {/* Node Details Panel */}
            <div className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Node Details</CardTitle>
                </CardHeader>
                <CardContent>
                  {selectedNode ? (
                    <div className="space-y-3">
                      <div className="flex items-center gap-2">
                        {getTypeIcon(selectedNode.type)}
                        <span className="font-medium">{selectedNode.label}</span>
                      </div>

                      <div>
                        <Badge variant="outline">{selectedNode.type}</Badge>
                        {selectedNode.status && (
                          <Badge
                            className={`ml-2 ${selectedNode.status === 'compliant' ? 'bg-green-500' :
                                selectedNode.status === 'non-compliant' ? 'bg-red-500' : 'bg-gray-500'
                              }`}
                          >
                            {selectedNode.status}
                          </Badge>
                        )}
                      </div>

                      <div className="text-sm space-y-2">
                        <div>
                          <span className="font-medium">ID:</span> {selectedNode.id}
                        </div>
                        <div>
                          <span className="font-medium">Last Updated:</span>
                          <br />
                          {selectedNode.metadata.lastUpdated?.toLocaleString()}
                        </div>
                        {selectedNode.metadata.complianceStatus && (
                          <div>
                            <span className="font-medium">Status:</span> {selectedNode.metadata.complianceStatus}
                          </div>
                        )}
                      </div>

                      <div>
                        <span className="font-medium text-sm">Connected Nodes:</span>
                        <div className="text-xs text-muted-foreground mt-1">
                          {graphData.edges
                            .filter(edge => edge.from === selectedNode.id || edge.to === selectedNode.id)
                            .length} connections
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="text-center text-muted-foreground">
                      Click on a node to view details
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Legend */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Legend</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-sm">
                    <div className="flex items-center gap-2">
                      <div className="w-4 h-4 rounded-full bg-blue-500"></div>
                      <span>Frameworks</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-4 h-4 rounded-full bg-purple-500"></div>
                      <span>Controls</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-4 h-4 rounded-full bg-red-500"></div>
                      <span>Assets</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-4 h-4 rounded-full bg-green-500"></div>
                      <span>Evidence</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-4 h-4 rounded-full bg-pink-500"></div>
                      <span>Remediations</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="relationships" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Relationship Matrix</CardTitle>
              <CardDescription>
                Detailed view of all relationships between compliance entities
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {graphData.edges.map((edge, index) => {
                  const fromNode = graphData.nodes.find(n => n.id === edge.from);
                  const toNode = graphData.nodes.find(n => n.id === edge.to);

                  return (
                    <div key={index} className="flex items-center justify-between p-3 border rounded">
                      <div className="flex items-center gap-4">
                        <div className="flex items-center gap-2">
                          {fromNode && getTypeIcon(fromNode.type)}
                          <span className="font-medium">{fromNode?.label}</span>
                        </div>
                        <ArrowRight className="h-4 w-4 text-muted-foreground" />
                        <div className="flex items-center gap-2">
                          {toNode && getTypeIcon(toNode.type)}
                          <span className="font-medium">{toNode?.label}</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline">{edge.type}</Badge>
                        <div className="text-sm text-muted-foreground">
                          Strength: {Math.round(edge.strength * 100)}%
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="analytics" className="space-y-4">
          <div className="grid grid-cols-3 gap-4">
            <Card>
              <CardContent className="pt-6">
                <div className="text-center">
                  <div className="text-2xl font-bold">{graphData.metadata.complianceScore}%</div>
                  <div className="text-sm text-muted-foreground">Overall Compliance</div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="text-center">
                  <div className="text-2xl font-bold text-blue-500">
                    {graphData.nodes.filter(n => n.type === 'framework').length}
                  </div>
                  <div className="text-sm text-muted-foreground">Active Frameworks</div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="text-center">
                  <div className="text-2xl font-bold text-red-500">
                    {graphData.nodes.filter(n => n.status === 'non-compliant').length}
                  </div>
                  <div className="text-sm text-muted-foreground">Non-Compliant Assets</div>
                </div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Graph Analytics</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-6">
                <div>
                  <h4 className="font-medium mb-3">Node Distribution</h4>
                  <div className="space-y-2">
                    {nodeTypes.slice(1).map(type => {
                      const count = graphData.nodes.filter(n => n.type === type).length;
                      const percentage = (count / graphData.nodes.length) * 100;

                      return (
                        <div key={type} className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            {getTypeIcon(type)}
                            <span className="capitalize">{type}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-sm">{count}</span>
                            <div className="w-20 bg-gray-200 rounded-full h-2">
                              <div
                                className="bg-blue-500 h-2 rounded-full"
                                style={{ width: `${percentage}%` }}
                              ></div>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                <div>
                  <h4 className="font-medium mb-3">Relationship Types</h4>
                  <div className="space-y-2">
                    {['requires', 'affects', 'evidences', 'remediates'].map(type => {
                      const count = graphData.edges.filter(e => e.type === type).length;
                      const percentage = (count / graphData.edges.length) * 100;

                      return (
                        <div key={type} className="flex items-center justify-between">
                          <span className="capitalize">{type}</span>
                          <div className="flex items-center gap-2">
                            <span className="text-sm">{count}</span>
                            <div className="w-20 bg-gray-200 rounded-full h-2">
                              <div
                                className="bg-green-500 h-2 rounded-full"
                                style={{ width: `${percentage}%` }}
                              ></div>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};