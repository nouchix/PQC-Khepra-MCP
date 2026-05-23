import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Search, Server, Monitor, Shield, Wifi, Database,
  Cloud, AlertTriangle, CheckCircle, RefreshCw, Settings
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { useOrganization } from '@/hooks/useOrganization';

interface Asset {
  id: string;
  name: string;
  type: 'server' | 'workstation' | 'network_device' | 'database' | 'cloud_service';
  ip_address: string;
  os: string;
  version: string;
  status: 'online' | 'offline' | 'maintenance';
  compliance_score: number;
  vulnerabilities: number;
  last_scan: string;
  criticality: 'low' | 'medium' | 'high' | 'critical';
}

interface NetworkSegment {
  id: string;
  name: string;
  cidr: string;
  assets_count: number;
  compliance_level: number;
  security_zone: 'dmz' | 'internal' | 'secure' | 'external';
}

export const InfrastructureDiscovery = () => {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [networks, setNetworks] = useState<NetworkSegment[]>([]);
  const [scanning, setScanning] = useState(false);
  const [discoveryProgress, setDiscoveryProgress] = useState(0);
  const [, setDiscoveryResults] = useState<any[]>([]);
  const { toast } = useToast();
  const { currentOrganization } = useOrganization();

  // Fetch assets from database
  const fetchAssets = async () => {
    if (!currentOrganization?.id) return;

    console.log('Fetching discovered assets for organization:', currentOrganization.id);
    const { data, error } = await supabase
      .from('discovered_assets')
      .select('*')
      .eq('organization_id', currentOrganization.id)
      .order('last_discovered', { ascending: false });

    if (error) {
      console.error('Error fetching assets:', error);
      return;
    }

    if (data && data.length > 0) {
      const mappedAssets: Asset[] = data.map(item => {
        const meta = item.metadata as Record<string, any> | null;
        const ipAddresses = item.ip_addresses as string[] | null;
        return {
          id: item.asset_identifier,
          name: item.hostname || item.asset_identifier,
          type: (item.asset_type as Asset['type']) || 'server',
          ip_address: ipAddresses?.[0] ?? 'Unknown',
          os: item.operating_system || 'Unknown',
          version: item.version || '',
          status: (meta?.status as Asset['status']) || 'online',
          compliance_score: meta?.compliance_score ?? 0,
          vulnerabilities: meta?.vulnerabilities ?? 0,
          last_scan: item.last_discovered,
          criticality: (meta?.criticality as Asset['criticality']) || 'medium'
        };
      });
      setAssets(mappedAssets);
    }
  };

  // Fetch network segments from Supabase
  const fetchNetworks = async () => {
    if (!currentOrganization?.id) return;
    const { data, error } = await supabase
      .from('zero_trust_network_segments')
      .select('*')
      .eq('organization_id', currentOrganization.id);

    if (!error && data && data.length > 0) {
      const mappedNetworks: NetworkSegment[] = data.map((seg: any) => ({
        id: seg.id,
        name: seg.name,
        cidr: seg.cidr,
        assets_count: seg.assets_count ?? 0,
        compliance_level: seg.compliance_level ?? 0,
        security_zone: seg.security_zone || 'internal',
      }));
      setNetworks(mappedNetworks);
    }
  };

  useEffect(() => {
    fetchAssets();
    fetchNetworks();
  }, [currentOrganization?.id]);

  const getAssetIcon = (type: string) => {
    switch (type) {
      case 'server': return <Server className="h-5 w-5" />;
      case 'workstation': return <Monitor className="h-5 w-5" />;
      case 'network_device': return <Wifi className="h-5 w-5" />;
      case 'database': return <Database className="h-5 w-5" />;
      case 'cloud_service': return <Cloud className="h-5 w-5" />;
      default: return <Monitor className="h-5 w-5" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online': return 'bg-success text-success-foreground';
      case 'offline': return 'bg-destructive text-destructive-foreground';
      case 'maintenance': return 'bg-warning text-warning-foreground';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const getCriticalityColor = (criticality: string) => {
    switch (criticality) {
      case 'critical': return 'text-destructive';
      case 'high': return 'text-warning';
      case 'medium': return 'text-primary';
      case 'low': return 'text-success';
      default: return 'text-muted-foreground';
    }
  };

  const performSTIGFingerprinting = async (type: string) => {
    setScanning(true);
    setDiscoveryProgress(0);
    console.log(`Starting STIG ${type} fingerprinting...`);

    try {
      const { data, error } = await supabase.functions.invoke('infrastructure-discovery', {
        body: {
          action: 'stig_fingerprinting',
          target_os: type,
          stig_profiles: ['Windows Server 2019', 'Ubuntu 22.04', 'IIS 10.0', 'Apache 2.4'],
          organizationId: currentOrganization?.id,
          stig_viewer_lookup: true
        }
      });

      if (error) throw error;

      setDiscoveryResults(data.results || []);
      await fetchAssets();

      toast({
        title: "Discovery Complete",
        description: `Found ${data.discovered_count || 0} assets`,
      });
    } catch (error: any) {
      console.error('Discovery error:', error);
      toast({
        title: "Discovery Failed",
        description: error.message || "Failed to perform infrastructure discovery.",
        variant: "destructive",
      });
    } finally {
      setScanning(false);
      setDiscoveryProgress(100);
    }
  };

  const startSTIGDiscovery = async () => {
    setScanning(true);
    setDiscoveryProgress(0);

    // Run STIG-targeted fingerprinting for supported systems
    const stigTypes = ['windows_server_2019', 'ubuntu_22_04', 'iis_10', 'apache_2_4'];
    let completed = 0;

    for (const type of stigTypes) {
      performSTIGFingerprinting(type).finally(() => {
        completed++;
        setDiscoveryProgress((completed / stigTypes.length) * 100);

        if (completed === stigTypes.length) {
          setScanning(false);
          toast({
            title: "STIG Discovery Complete",
            description: `STIG fingerprinting completed for ${stigTypes.length} supported platforms`,
            variant: "default"
          });
        }
      });
    }
  };

  const totalAssets = assets.length;
  const onlineAssets = assets.filter(a => a.status === 'online').length;
  const criticalAssets = assets.filter(a => a.criticality === 'critical').length;
  const averageCompliance = Math.round(assets.reduce((sum, a) => sum + a.compliance_score, 0) / assets.length);

  return (
    <div className="space-y-6">
      {/* Discovery Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Total Assets</p>
                <p className="text-2xl font-bold text-primary">{totalAssets}</p>
              </div>
              <Monitor className="h-8 w-8 text-primary" />
            </div>
          </CardContent>
        </Card>

        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Online Assets</p>
                <p className="text-2xl font-bold text-success">{onlineAssets}</p>
              </div>
              <CheckCircle className="h-8 w-8 text-success" />
            </div>
          </CardContent>
        </Card>

        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Critical Assets</p>
                <p className="text-2xl font-bold text-destructive">{criticalAssets}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-destructive" />
            </div>
          </CardContent>
        </Card>

        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Avg Compliance</p>
                <p className="text-2xl font-bold text-accent">{averageCompliance}%</p>
              </div>
              <Shield className="h-8 w-8 text-accent" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Discovery Controls */}
      <Card className="card-cyber">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center space-x-2">
                <Search className="h-5 w-5 text-primary" />
                <span>Infrastructure Discovery</span>
              </CardTitle>
              <CardDescription>
                STIG-targeted fingerprinting and compliance assessment for critical systems
              </CardDescription>
            </div>
            <Button
              variant="cyber"
              onClick={startSTIGDiscovery}
              disabled={scanning}
            >
              {scanning ? (
                <>
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                  STIG Scanning...
                </>
              ) : (
                <>
                  <Shield className="h-4 w-4 mr-2" />
                  STIG Discovery
                </>
              )}
            </Button>
          </div>
        </CardHeader>

        {scanning && (
          <CardContent>
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span>Discovery Progress</span>
                <span>{discoveryProgress}%</span>
              </div>
              <Progress value={discoveryProgress} className="w-full" />
            </div>
          </CardContent>
        )}
      </Card>

      {/* Asset Management Tabs */}
      <Tabs defaultValue="assets" className="space-y-4">
        <TabsList className="bg-card border border-border">
          <TabsTrigger value="assets">Assets</TabsTrigger>
          <TabsTrigger value="networks">Network Segments</TabsTrigger>
        </TabsList>

        <TabsContent value="assets" className="space-y-4">
          <Card className="card-cyber">
            <CardHeader>
              <CardTitle>Discovered Assets</CardTitle>
              <CardDescription>
                Complete inventory of your IT infrastructure
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {assets.map((asset) => (
                  <div
                    key={asset.id}
                    className="p-4 border border-border rounded-lg bg-card hover:bg-accent/30 transition-colors"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-4">
                        {getAssetIcon(asset.type)}
                        <div className="flex-1">
                          <div className="flex items-center space-x-2 mb-1">
                            <h4 className="font-medium text-foreground">{asset.name}</h4>
                            <Badge className={getStatusColor(asset.status)}>
                              {asset.status.toUpperCase()}
                            </Badge>
                            <Badge variant="outline" className={getCriticalityColor(asset.criticality)}>
                              {asset.criticality.toUpperCase()}
                            </Badge>
                          </div>
                          <div className="grid grid-cols-2 gap-4 text-sm text-muted-foreground">
                            <span>IP: {asset.ip_address}</span>
                            <span>OS: {asset.os} {asset.version}</span>
                            <span>Compliance: {asset.compliance_score}%</span>
                            <span>Vulnerabilities: {asset.vulnerabilities}</span>
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center space-x-2">
                        <Button variant="outline" size="sm">
                          <Settings className="h-3 w-3 mr-1" />
                          Configure
                        </Button>
                        <Button variant="outline" size="sm">
                          <Search className="h-3 w-3 mr-1" />
                          Scan
                        </Button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="networks" className="space-y-4">
          <Card className="card-cyber">
            <CardHeader>
              <CardTitle>Network Segments</CardTitle>
              <CardDescription>
                Network topology and security zone analysis
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {networks.map((network) => (
                  <div
                    key={network.id}
                    className="p-4 border border-border rounded-lg bg-card hover:bg-accent/30 transition-colors"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-4">
                        <Wifi className="h-6 w-6 text-primary" />
                        <div>
                          <h4 className="font-medium text-foreground">{network.name}</h4>
                          <div className="flex items-center space-x-4 text-sm text-muted-foreground">
                            <span>CIDR: {network.cidr}</span>
                            <span>Assets: {network.assets_count}</span>
                            <span>Compliance: {network.compliance_level}%</span>
                            <Badge variant="outline">{network.security_zone.toUpperCase()}</Badge>
                          </div>
                        </div>
                      </div>

                      <Button variant="outline" size="sm">
                        <Search className="h-3 w-3 mr-1" />
                        Analyze
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};