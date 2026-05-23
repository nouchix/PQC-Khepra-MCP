import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/components/ui/use-toast';
import { 
  Search, 
  Plus, 
  Play, 
  Square, 
  RefreshCw, 
  Server, 
  Shield, 
  Network, 
  Cloud, 
  Activity,
  AlertTriangle,
  CheckCircle,
  Clock,
  Settings
} from 'lucide-react';
import { STIGConnectorService, DiscoveredAsset, DiscoveryJob } from '@/services/STIGConnectorService';
import { useOrganizationContext } from '@/components/OrganizationProvider';

interface STIGConnectorDashboardProps {
  organizationId: string;
}

export const STIGConnectorDashboard: React.FC<STIGConnectorDashboardProps> = ({ organizationId }) => {
  const { toast } = useToast();
  const [discoveredAssets, setDiscoveredAssets] = useState<DiscoveredAsset[]>([]);
  const [discoveryJobs, setDiscoveryJobs] = useState<DiscoveryJob[]>([]);
  const [statistics, setStatistics] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedAssetType, setSelectedAssetType] = useState<string>('all');
  const [showNewJobDialog, setShowNewJobDialog] = useState(false);
  const [newJobData, setNewJobData] = useState({
    job_name: '',
    discovery_type: 'network_scan' as const,
    targets: '',
    scan_options: {}
  });

  useEffect(() => {
    if (organizationId) {
      loadData();
    }
  }, [organizationId]);

  const loadData = async () => {
    try {
      setIsLoading(true);
      
      const [assets, jobs, stats] = await Promise.all([
        STIGConnectorService.getDiscoveredAssets(organizationId),
        STIGConnectorService.getDiscoveryJobs(organizationId),
        STIGConnectorService.getAssetStatistics(organizationId)
      ]);

      setDiscoveredAssets(assets.assets);
      setDiscoveryJobs(jobs);
      setStatistics(stats);
    } catch (error) {
      console.error('Failed to load discovery data:', error);
      toast({
        title: "Error loading data",
        description: "Failed to load discovery information",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleStartDiscovery = async () => {
    try {
      const targets = newJobData.targets.split('\n').filter(t => t.trim());
      
      const result = await STIGConnectorService.startDiscovery(organizationId, {
        type: newJobData.discovery_type as "nmap_scan" | "comprehensive_scan" | "stealth_scan" | "vulnerability_scan",
        targets,
        scan_options: newJobData.scan_options
      });

      toast({
        title: "Discovery Started",
        description: `Started ${newJobData.discovery_type} discovery with ${targets.length} targets`,
      });

      setShowNewJobDialog(false);
      setNewJobData({
        job_name: '',
        discovery_type: 'network_scan',
        targets: '',
        scan_options: {}
      });

      // Reload data to show the new job
      await loadData();
    } catch (error) {
      console.error('Failed to start discovery:', error);
      toast({
        title: "Discovery Failed",
        description: "Failed to start asset discovery",
        variant: "destructive",
      });
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'bg-blue-500';
      case 'completed': return 'bg-green-500';
      case 'failed': case 'error': return 'bg-red-500';
      case 'cancelled': return 'bg-gray-500';
      default: return 'bg-yellow-500';
    }
  };

  const getRiskColor = (riskScore: number) => {
    if (riskScore >= 80) return 'bg-red-500';
    if (riskScore >= 60) return 'bg-orange-500';
    if (riskScore >= 40) return 'bg-yellow-500';
    return 'bg-green-500';
  };

  const filteredAssets = discoveredAssets.filter(asset => {
    const matchesSearch = asset.hostname?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         asset.asset_identifier.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         asset.platform?.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesType = selectedAssetType === 'all' || asset.asset_type === selectedAssetType;
    
    return matchesSearch && matchesType;
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="h-8 w-8 animate-spin" />
        <span className="ml-2">Loading discovery data...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header with Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Assets</CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{statistics?.total_assets || 0}</div>
            <p className="text-xs text-muted-foreground">Discovered assets</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">STIG Coverage</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{statistics?.compliance_overview.total_stigs || 0}</div>
            <p className="text-xs text-muted-foreground">Applicable STIGs</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Compliance Rate</CardTitle>
            <CheckCircle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{statistics?.compliance_overview.compliance_percentage || 0}%</div>
            <p className="text-xs text-muted-foreground">STIG compliance</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">High Risk Assets</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {(statistics?.risk_distribution.high || 0) + (statistics?.risk_distribution.critical || 0)}
            </div>
            <p className="text-xs text-muted-foreground">Require attention</p>
          </CardContent>
        </Card>
      </div>

      {/* Main Dashboard */}
      <Tabs defaultValue="assets" className="space-y-4">
        <div className="flex items-center justify-between">
          <TabsList>
            <TabsTrigger value="assets">Discovered Assets</TabsTrigger>
            <TabsTrigger value="jobs">Discovery Jobs</TabsTrigger>
            <TabsTrigger value="credentials">Credentials</TabsTrigger>
          </TabsList>

          <Dialog open={showNewJobDialog} onOpenChange={setShowNewJobDialog}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="h-4 w-4 mr-2" />
                Start Discovery
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-2xl">
              <DialogHeader>
                <DialogTitle>Start Asset Discovery</DialogTitle>
                <DialogDescription>
                  Configure and start a new asset discovery process
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div>
                  <Label htmlFor="job_name">Job Name</Label>
                  <Input
                    id="job_name"
                    placeholder="Network scan - Production environment"
                    value={newJobData.job_name}
                    onChange={(e) => setNewJobData(prev => ({ ...prev, job_name: e.target.value }))}
                  />
                </div>

                <div>
                  <Label htmlFor="discovery_type">Discovery Type</Label>
                  <Select 
                    value={newJobData.discovery_type} 
                    onValueChange={(value: any) => setNewJobData(prev => ({ ...prev, discovery_type: value }))}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="network_scan">Network Scan</SelectItem>
                      <SelectItem value="cloud_discovery">Cloud Discovery</SelectItem>
                      <SelectItem value="snmp_discovery">SNMP Discovery</SelectItem>
                      <SelectItem value="agent_based">Agent-Based</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div>
                  <Label htmlFor="targets">Targets</Label>
                  <Textarea
                    id="targets"
                    placeholder="Enter IP addresses, ranges, or hostnames (one per line)&#10;192.168.1.1&#10;192.168.1.0/24&#10;server.example.com"
                    value={newJobData.targets}
                    onChange={(e) => setNewJobData(prev => ({ ...prev, targets: e.target.value }))}
                    rows={5}
                  />
                </div>

                <div className="flex justify-end space-x-2">
                  <Button 
                    variant="outline" 
                    onClick={() => setShowNewJobDialog(false)}
                  >
                    Cancel
                  </Button>
                  <Button onClick={handleStartDiscovery}>
                    Start Discovery
                  </Button>
                </div>
              </div>
            </DialogContent>
          </Dialog>
        </div>

        <TabsContent value="assets" className="space-y-4">
          {/* Filters */}
          <div className="flex flex-col sm:flex-row gap-4">
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search assets..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-8"
                />
              </div>
            </div>
            <Select value={selectedAssetType} onValueChange={setSelectedAssetType}>
              <SelectTrigger className="w-[200px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Asset Types</SelectItem>
                <SelectItem value="server">Servers</SelectItem>
                <SelectItem value="network_device">Network Devices</SelectItem>
                <SelectItem value="database">Databases</SelectItem>
                <SelectItem value="application">Applications</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Assets Grid */}
          {filteredAssets.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredAssets.map((asset) => (
                <Card key={asset.id} className="hover:shadow-md transition-shadow">
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-base">
                        {asset.hostname || asset.asset_identifier}
                      </CardTitle>
                      <Badge variant="outline" className="capitalize">
                        {asset.asset_type.replaceAll('_', ' ')}
                      </Badge>
                    </div>
                    <CardDescription className="text-sm">
                      {asset.platform} • {asset.operating_system}
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="flex items-center justify-between text-sm">
                      <span>Risk Score:</span>
                      <div className="flex items-center space-x-2">
                        <div className={`w-2 h-2 rounded-full ${getRiskColor(asset.risk_score)}`} />
                        <span className="font-medium">{asset.risk_score}/100</span>
                      </div>
                    </div>

                    <div className="flex items-center justify-between text-sm">
                      <span>Applicable STIGs:</span>
                      <Badge variant="secondary">
                        {asset.applicable_stigs?.length || 0}
                      </Badge>
                    </div>

                    <div className="flex items-center justify-between text-sm">
                      <span>Services:</span>
                      <span className="text-muted-foreground">
                        {asset.discovered_services?.length || 0} detected
                      </span>
                    </div>

                    <div className="text-xs text-muted-foreground">
                      Last discovered: {new Date(asset.last_discovered).toLocaleDateString()}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-12">
                <Server className="h-12 w-12 text-muted-foreground mb-4" />
                <h3 className="text-lg font-medium mb-2">No Assets Discovered</h3>
                <p className="text-muted-foreground text-center mb-4">
                  Start your first discovery to find assets in your environment
                </p>
                <Button onClick={() => setShowNewJobDialog(true)}>
                  <Plus className="h-4 w-4 mr-2" />
                  Start Discovery
                </Button>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="jobs" className="space-y-4">
          {discoveryJobs.length > 0 ? (
            <div className="space-y-4">
              {discoveryJobs.map((job) => (
                <Card key={job.id}>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <div>
                        <CardTitle className="text-base">{job.job_name}</CardTitle>
                        <CardDescription>
                          {job.discovery_type.replaceAll('_', ' ')} • 
                          Created {new Date(job.created_at).toLocaleDateString()}
                        </CardDescription>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Badge className={getStatusColor(job.status)}>
                          {job.status}
                        </Badge>
                        {job.status === 'running' && (
                          <Button variant="outline" size="sm">
                            <Square className="h-4 w-4" />
                          </Button>
                        )}
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                      <div>
                        <span className="text-muted-foreground">Targets:</span>
                        <div className="font-medium">
                          {job.target_specification?.targets?.length || 0}
                        </div>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Last Run:</span>
                        <div className="font-medium">
                          {job.last_run_at ? new Date(job.last_run_at).toLocaleDateString() : 'Never'}
                        </div>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Type:</span>
                        <div className="font-medium capitalize">
                          {job.discovery_type.replaceAll('_', ' ')}
                        </div>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Status:</span>
                        <div className="font-medium capitalize">
                          {job.status}
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-12">
                <Activity className="h-12 w-12 text-muted-foreground mb-4" />
                <h3 className="text-lg font-medium mb-2">No Discovery Jobs</h3>
                <p className="text-muted-foreground text-center mb-4">
                  Create your first discovery job to start finding assets
                </p>
                <Button onClick={() => setShowNewJobDialog(true)}>
                  <Plus className="h-4 w-4 mr-2" />
                  Create Job
                </Button>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="credentials">
          <Card>
            <CardContent className="flex flex-col items-center justify-center py-12">
              <Settings className="h-12 w-12 text-muted-foreground mb-4" />
              <h3 className="text-lg font-medium mb-2">Credential Management</h3>
              <p className="text-muted-foreground text-center mb-4">
                Manage discovery credentials for secure asset scanning
              </p>
              <Button disabled>
                <Plus className="h-4 w-4 mr-2" />
                Add Credential (Coming Soon)
              </Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};