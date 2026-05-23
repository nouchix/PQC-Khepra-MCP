import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { 
  Building2, 
  Users, 
  Server, 
  Activity, 
  AlertTriangle, 
  CheckCircle,
  TrendingUp,
  Database,
  Zap
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface OrganizationMetrics {
  id: string;
  name: string;
  userCount: number;
  assetCount: number;
  complianceScore: number;
  lastActivity: string;
  status: 'healthy' | 'warning' | 'critical';
  tier: 'trial' | 'standard' | 'enterprise';
  resourceUsage: {
    cpu: number;
    memory: number;
    storage: number;
    bandwidth: number;
  };
}

interface SystemPerformance {
  totalOrganizations: number;
  totalUsers: number;
  totalAssets: number;
  averageResponseTime: number;
  systemLoad: number;
  dbConnections: number;
  cacheHitRate: number;
}

export const OrganizationScaleManager = () => {
  const { toast } = useToast();
  const [organizations, setOrganizations] = useState<OrganizationMetrics[]>([]);
  const [systemPerf, setSystemPerf] = useState<SystemPerformance>({
    totalOrganizations: 0,
    totalUsers: 0,
    totalAssets: 0,
    averageResponseTime: 0,
    systemLoad: 0,
    dbConnections: 0,
    cacheHitRate: 0
  });

  // Initialize with placeholder data showing platform capabilities
  useEffect(() => {
    // Show current organization as the only one
    const currentOrg: OrganizationMetrics = {
      id: 'current-org',
      name: 'Your Organization',
      userCount: 1, // Current user
      assetCount: 0, // Will grow as they add assets
      complianceScore: 0, // Will improve as they configure compliance
      lastActivity: new Date().toISOString(),
      status: 'healthy',
      tier: 'trial',
      resourceUsage: {
        cpu: 5,
        memory: 10,
        storage: 5,
        bandwidth: 2
      }
    };

    setOrganizations([currentOrg]);
    
    setSystemPerf({
      totalOrganizations: 1,
      totalUsers: 1,
      totalAssets: 0,
      averageResponseTime: 45,
      systemLoad: 15,
      dbConnections: 25,
      cacheHitRate: 98
    });
  }, []);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return 'default';
      case 'warning': return 'secondary';
      case 'critical': return 'destructive';
      default: return 'outline';
    }
  };

  const getTierColor = (tier: string) => {
    switch (tier) {
      case 'enterprise': return 'default';
      case 'standard': return 'secondary';
      case 'trial': return 'outline';
      default: return 'outline';
    }
  };

  const optimizeResources = () => {
    toast({
      title: "Resource Optimization Started",
      description: "Analyzing resource usage and implementing optimizations...",
    });

    // Simulate optimization
    setTimeout(() => {
      setSystemPerf(prev => ({
        ...prev,
        systemLoad: Math.max(prev.systemLoad - 10, 20),
        averageResponseTime: Math.max(prev.averageResponseTime - 20, 30),
        cacheHitRate: Math.min(prev.cacheHitRate + 5, 99)
      }));

      toast({
        title: "Optimization Complete",
        description: "System performance improved successfully.",
      });
    }, 2000);
  };

  const scaleInfrastructure = () => {
    toast({
      title: "Scaling Infrastructure",
      description: "Adding additional capacity to handle increased load...",
    });

    setTimeout(() => {
      toast({
        title: "Infrastructure Scaled",
        description: "Additional capacity has been provisioned.",
      });
    }, 3000);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold">Organization Scale Manager</h2>
        <div className="flex gap-2">
          <Button onClick={optimizeResources} variant="outline">
            <Zap className="h-4 w-4 mr-2" />
            Optimize Resources
          </Button>
          <Button onClick={scaleInfrastructure}>
            <TrendingUp className="h-4 w-4 mr-2" />
            Scale Infrastructure
          </Button>
        </div>
      </div>

      {/* System Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <Building2 className="h-8 w-8 text-primary" />
              <div>
                <p className="text-sm text-muted-foreground">Organizations</p>
                <p className="text-2xl font-bold">{systemPerf.totalOrganizations}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <Users className="h-8 w-8 text-blue-500" />
              <div>
                <p className="text-sm text-muted-foreground">Total Users</p>
                <p className="text-2xl font-bold">{systemPerf.totalUsers.toLocaleString()}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <Server className="h-8 w-8 text-green-500" />
              <div>
                <p className="text-sm text-muted-foreground">Total Assets</p>
                <p className="text-2xl font-bold">{systemPerf.totalAssets.toLocaleString()}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <Activity className="h-8 w-8 text-yellow-500" />
              <div>
                <p className="text-sm text-muted-foreground">Avg Response</p>
                <p className="text-2xl font-bold">{systemPerf.averageResponseTime}ms</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Performance Metrics */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Database className="h-5 w-5" />
              System Load
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span>CPU Usage</span>
                  <span>{systemPerf.systemLoad}%</span>
                </div>
                <Progress value={systemPerf.systemLoad} className="h-2" />
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span>DB Connections</span>
                  <span>{systemPerf.dbConnections}</span>
                </div>
                <Progress value={(systemPerf.dbConnections / 200) * 100} className="h-2" />
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span>Cache Hit Rate</span>
                  <span>{systemPerf.cacheHitRate}%</span>
                </div>
                <Progress value={systemPerf.cacheHitRate} className="h-2" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Organization Status</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {['healthy', 'warning', 'critical'].map((status) => {
                const count = organizations.filter(org => org.status === status).length;
                const percentage = (count / organizations.length) * 100;
                return (
                  <div key={status} className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {status === 'healthy' && <CheckCircle className="h-4 w-4 text-green-500" />}
                      {status === 'warning' && <AlertTriangle className="h-4 w-4 text-yellow-500" />}
                      {status === 'critical' && <AlertTriangle className="h-4 w-4 text-red-500" />}
                      <span className="capitalize">{status}</span>
                    </div>
                    <div className="text-right">
                      <span className="font-medium">{count}</span>
                      <span className="text-sm text-muted-foreground ml-1">({percentage.toFixed(1)}%)</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Tier Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {['enterprise', 'standard', 'trial'].map((tier) => {
                const count = organizations.filter(org => org.tier === tier).length;
                const percentage = (count / organizations.length) * 100;
                return (
                  <div key={tier} className="flex items-center justify-between">
                    <Badge variant={getTierColor(tier)} className="capitalize">
                      {tier}
                    </Badge>
                    <div className="text-right">
                      <span className="font-medium">{count}</span>
                      <span className="text-sm text-muted-foreground ml-1">({percentage.toFixed(1)}%)</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Organizations List */}
      <Card>
        <CardHeader>
          <CardTitle>Organization Overview</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {organizations.slice(0, 20).map((org) => (
              <div 
                key={org.id} 
                className="flex items-center justify-between p-3 border rounded-lg hover:bg-muted/50 transition-colors"
              >
                <div className="flex items-center gap-3">
                  <Building2 className="h-4 w-4 text-muted-foreground" />
                  <div>
                    <p className="font-medium">{org.name}</p>
                    <p className="text-sm text-muted-foreground">
                      {org.userCount} users • {org.assetCount} assets
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <Badge variant={getTierColor(org.tier)} className="capitalize">
                    {org.tier}
                  </Badge>
                  <Badge variant={getStatusColor(org.status)} className="capitalize">
                    {org.status}
                  </Badge>
                  <div className="text-right">
                    <p className="text-sm font-medium">{org.complianceScore}%</p>
                    <p className="text-xs text-muted-foreground">Compliance</p>
                  </div>
                </div>
              </div>
            ))}
            {organizations.length > 20 && (
              <div className="text-center py-2 text-sm text-muted-foreground">
                And {organizations.length - 20} more organizations...
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};