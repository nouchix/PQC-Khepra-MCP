import { useEffect, useRef, useState, useCallback, ComponentType } from 'react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { 
  Monitor, 
  Router, 
  Database, 
  Globe, 
  Server, 
  Laptop,
  Smartphone,
  Printer,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Zap
} from 'lucide-react';
import type { SecurityAsset } from '@/services/ProductionSecurityService';
import { useKhepraProtection } from '@/hooks/useKhepraProtection';

interface AssetNode {
  id: string;
  x: number;
  y: number;
  asset: SecurityAsset;
  radius: number;
  color: string;
  icon: ComponentType<any>;
}

interface AssetConnection {
  from: string;
  to: string;
  color: string;
  strength: number;
}

interface AssetNetworkVisualizationProps {
  assets: SecurityAsset[];
  onAssetSelect?: (asset: SecurityAsset) => void;
  onAssetProtect?: (assetId: string) => void;
  selectedAssetId?: string;
}

export const AssetNetworkVisualization = ({
  assets,
  onAssetSelect,
  onAssetProtect,
  selectedAssetId
}: AssetNetworkVisualizationProps) => {
  const { protectionState, enableKhepraProtection } = useKhepraProtection();
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [nodes, setNodes] = useState<AssetNode[]>([]);
  const [connections, setConnections] = useState<AssetConnection[]>([]);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [canvasSize, setCanvasSize] = useState({ width: 800, height: 600 });

  const getAssetIcon = (type: string) => {
    switch (type) {
      case 'device': return Laptop;
      case 'network': return Router;
      case 'storage': return Database;
      case 'application': return Globe;
      case 'api': return Server;
      case 'mobile': return Smartphone;
      case 'printer': return Printer;
      default: return Monitor;
    }
  };

  const getAssetColor = (asset: SecurityAsset) => {
    if (asset.protectionLevel !== 'none') return '#10b981'; // emerald-500
    if (asset.vulnerabilities.length > 0) return '#ef4444'; // red-500
    return '#6b7280'; // gray-500
  };

  const generateNetworkLayout = useCallback(() => {
    if (assets.length === 0) return;

    const centerX = canvasSize.width / 2;
    const centerY = canvasSize.height / 2;
    const radius = Math.min(canvasSize.width, canvasSize.height) * 0.3;

    const newNodes: AssetNode[] = assets.map((asset, index) => {
      const angle = (index / assets.length) * 2 * Math.PI;
      const nodeRadius = asset.type === 'device' ? radius * 0.3 : radius;
      
      return {
        id: asset.id,
        x: centerX + Math.cos(angle) * nodeRadius,
        y: centerY + Math.sin(angle) * nodeRadius,
        asset,
        radius: 30,
        color: getAssetColor(asset),
        icon: getAssetIcon(asset.type)
      };
    });

    // Generate connections
    const newConnections: AssetConnection[] = [];
    const deviceAsset = assets.find(a => a.type === 'device');
    
    if (deviceAsset) {
      assets.forEach(asset => {
        if (asset.id !== deviceAsset.id) {
          newConnections.push({
            from: deviceAsset.id,
            to: asset.id,
            color: asset.protectionLevel !== 'none' ? '#10b981' : '#f59e0b',
            strength: asset.protectionLevel !== 'none' ? 3 : 1
          });
        }
      });
    }

    setNodes(newNodes);
    setConnections(newConnections);
  }, [assets, canvasSize]);

  const drawNetwork = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Clear canvas
    ctx.clearRect(0, 0, canvasSize.width, canvasSize.height);

    // Draw connections first
    connections.forEach(connection => {
      const fromNode = nodes.find(n => n.id === connection.from);
      const toNode = nodes.find(n => n.id === connection.to);
      
      if (fromNode && toNode) {
        ctx.beginPath();
        ctx.moveTo(fromNode.x, fromNode.y);
        ctx.lineTo(toNode.x, toNode.y);
        ctx.strokeStyle = connection.color + '80'; // Add transparency
        ctx.lineWidth = connection.strength;
        ctx.stroke();
      }
    });

    // Draw nodes
    nodes.forEach(node => {
      const isSelected = node.id === selectedAssetId;
      const isHovered = node.id === hoveredNode;
      
      // Draw node circle
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.radius, 0, 2 * Math.PI);
      ctx.fillStyle = node.color + (isSelected ? 'ff' : isHovered ? 'cc' : 'aa');
      ctx.fill();
      
      // Draw border
      ctx.strokeStyle = isSelected ? '#3b82f6' : '#e5e7eb';
      ctx.lineWidth = isSelected ? 3 : 1;
      ctx.stroke();

      // Draw status indicator
      const statusRadius = 8;
      const statusX = node.x + node.radius - statusRadius;
      const statusY = node.y - node.radius + statusRadius;
      
      ctx.beginPath();
      ctx.arc(statusX, statusY, statusRadius, 0, 2 * Math.PI);
      
      if (node.asset.protectionLevel !== 'none') {
        ctx.fillStyle = '#10b981';
      } else if (node.asset.vulnerabilities.length > 0) {
        ctx.fillStyle = '#ef4444';
      } else {
        ctx.fillStyle = '#6b7280';
      }
      ctx.fill();
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 2;
      ctx.stroke();

      // Draw text label
      ctx.fillStyle = '#1f2937';
      ctx.font = '12px Inter';
      ctx.textAlign = 'center';
      ctx.fillText(node.asset.name, node.x, node.y + node.radius + 20);
    });
  }, [nodes, connections, selectedAssetId, hoveredNode, canvasSize]);

  const handleCanvasClick = useCallback((event: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;

    // Find clicked node
    const clickedNode = nodes.find(node => {
      const distance = Math.sqrt((x - node.x) ** 2 + (y - node.y) ** 2);
      return distance <= node.radius;
    });

    if (clickedNode && onAssetSelect) {
      onAssetSelect(clickedNode.asset);
    }
  }, [nodes, onAssetSelect]);

  const handleCanvasMouseMove = useCallback((event: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;

    // Find hovered node
    const hoveredNode = nodes.find(node => {
      const distance = Math.sqrt((x - node.x) ** 2 + (y - node.y) ** 2);
      return distance <= node.radius;
    });

    setHoveredNode(hoveredNode?.id || null);
    canvas.style.cursor = hoveredNode ? 'pointer' : 'default';
  }, [nodes]);

  // Update canvas size based on container
  useEffect(() => {
    const updateCanvasSize = () => {
      if (containerRef.current) {
        const { width, height } = containerRef.current.getBoundingClientRect();
        setCanvasSize({ width: Math.max(width - 32, 400), height: Math.max(height - 32, 300) });
      }
    };

    updateCanvasSize();
    globalThis.addEventListener('resize', updateCanvasSize);
    return () => globalThis.removeEventListener('resize', updateCanvasSize);
  }, []);

  // Generate layout when assets change
  useEffect(() => {
    generateNetworkLayout();
  }, [generateNetworkLayout]);

  // Redraw when nodes/connections change
  useEffect(() => {
    drawNetwork();
  }, [drawNetwork]);

  const selectedAsset = nodes.find(n => n.id === selectedAssetId)?.asset;

  return (
    <div className="flex h-full">
      <div ref={containerRef} className="flex-1 relative bg-card rounded-lg border p-4">
        <canvas
          ref={canvasRef}
          width={canvasSize.width}
          height={canvasSize.height}
          onClick={handleCanvasClick}
          onMouseMove={handleCanvasMouseMove}
          className="w-full h-full"
        />
        
        {assets.length === 0 && (
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="text-center text-muted-foreground">
              <Monitor className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No assets discovered yet</p>
              <p className="text-sm">Scanning environment...</p>
            </div>
          </div>
        )}

        {hoveredNode && (
          <div className="absolute top-4 left-4 z-10">
            <Card className="w-64">
              <CardContent className="p-3">
                {(() => {
                  const node = nodes.find(n => n.id === hoveredNode);
                  if (!node) return null;
                  const IconComponent = node.icon;
                  return (
                    <div className="space-y-2">
                      <div className="flex items-center gap-2">
                        <IconComponent className="h-4 w-4" />
                        <span className="font-medium">{node.asset.name}</span>
                      </div>
                      <div className="text-xs space-y-1">
                        <div>Type: {node.asset.type}</div>
                        <div className="flex items-center gap-2">
                          Status: 
                          {node.asset.protectionLevel !== 'none' ? (
                            <Badge variant="default" className="text-xs bg-emerald-500">Protected</Badge>
                          ) : node.asset.vulnerabilities.length > 0 ? (
                            <Badge variant="destructive" className="text-xs">
                              {node.asset.vulnerabilities.length} vulnerabilities
                            </Badge>
                          ) : (
                            <Badge variant="secondary" className="text-xs">Unprotected</Badge>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })()}
              </CardContent>
            </Card>
          </div>
        )}
      </div>

      {selectedAsset && (
        <div className="w-80 border-l bg-muted/20 p-4">
          <Card>
            <CardContent className="p-4">
              <div className="space-y-4">
                <div className="flex items-center gap-3">
                  {(() => {
                    const IconComponent = getAssetIcon(selectedAsset.type);
                    return <IconComponent className="h-6 w-6" />;
                  })()}
                  <div>
                    <h3 className="font-medium">{selectedAsset.name}</h3>
                    <p className="text-sm text-muted-foreground">{selectedAsset.type}</p>
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Protection Status:</span>
                    {selectedAsset.protectionLevel !== 'none' ? (
                      <Badge variant="default" className="bg-emerald-500">
                        <Shield className="h-3 w-3 mr-1" />
                        Protected
                      </Badge>
                    ) : (
                      <Badge variant="outline">
                        <AlertTriangle className="h-3 w-3 mr-1" />
                        Unprotected
                      </Badge>
                    )}
                  </div>

                  {selectedAsset.vulnerabilities.length > 0 && (
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Vulnerabilities:</span>
                      <Badge variant="destructive">
                        {selectedAsset.vulnerabilities.length} found
                      </Badge>
                    </div>
                  )}

                  <div className="flex items-center justify-between">
                    <span className="text-sm">Last Scanned:</span>
                    <span className="text-xs text-muted-foreground">
                      {selectedAsset.lastScanned.toLocaleTimeString()}
                    </span>
                  </div>
                </div>

                {selectedAsset.protectionLevel === 'none' && (
                  <Button 
                    onClick={() => {
                      // Activate KHEPRA Protection for the environment
                      enableKhepraProtection();
                      // Also protect the specific asset
                      if (onAssetProtect) {
                        onAssetProtect(selectedAsset.id);
                      }
                    }}
                    className="w-full bg-gradient-to-r from-primary/80 to-purple-600/80 hover:from-primary hover:to-purple-600"
                    size="sm"
                    disabled={protectionState.isLoading}
                  >
                    <Shield className="h-4 w-4 mr-2" />
                    {protectionState.isLoading ? 'Activating...' : 'Enable KHEPRA Protection'}
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
};