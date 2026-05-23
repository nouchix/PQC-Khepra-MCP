import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Shield, Network, Search, AlertTriangle, Eye, Globe, Mail, Cloud } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';
import { useToast } from '@/hooks/use-toast';
import { useOrganizationContext } from '@/components/OrganizationProvider';

interface ThreatDetection {
  id: string;
  detection_type: string;
  threat_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  indicator: string;
  source: string;
  details: any;
  detected_at: string;
  status: 'ACTIVE' | 'INVESTIGATING' | 'RESOLVED';
}

interface NetworkAsset {
  id: string;
  ip_address: string;
  hostname?: string;
  ports: number[];
  services: string[];
  os_fingerprint?: string;
  risk_score: number;
  last_scanned: string;
}

export const EnterpriseSecurityDashboard = () => {
  const [threatDetections, setThreatDetections] = useState<ThreatDetection[]>([]);
  const [networkAssets, setNetworkAssets] = useState<NetworkAsset[]>([]);
  const [scanTarget, setScanTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [activeScans, setActiveScans] = useState(0);

  const { toast } = useToast();
  const { currentOrganization } = useOrganizationContext();
  const organizationId = currentOrganization?.organization_id;

  // Fetch real threat detections
  const fetchThreatDetections = async () => {
    try {
      if (!organizationId) return;

      const { data, error } = await supabase
        .from('threat_investigations')
        .select('*')
        .eq('organization_id', organizationId)
        .order('created_at', { ascending: false })
        .limit(50);

      if (error) throw error;

      const formattedDetections: ThreatDetection[] = (data || []).map(item => ({
        id: item.id,
        detection_type: item.indicator_type.toUpperCase(),
        threat_level: item.threat_level?.toUpperCase() as any || 'UNKNOWN',
        indicator: item.threat_indicator,
        source: 'THREAT_INTELLIGENCE',
        details: item.external_references || {},
        detected_at: item.created_at,
        status: item.investigation_status?.toUpperCase() as any || 'ACTIVE'
      }));

      setThreatDetections(formattedDetections);
    } catch (error) {
      console.error('Error fetching threat detections:', error);
    }
  };

  // Fetch network assets
  const fetchNetworkAssets = async () => {
    try {
      if (!organizationId) return;

      const { data, error } = await supabase
        .from('infrastructure_assets')
        .select('*')
        .eq('organization_id', organizationId)
        .eq('asset_type', 'network')
        .order('last_updated', { ascending: false });

      if (error) throw error;

      const formattedAssets: NetworkAsset[] = (data || []).map(asset => {
        const results = asset.discovery_results as any || {};
        return {
          id: asset.id,
          ip_address: asset.target,
          hostname: results.hostname,
          ports: results.open_ports || [],
          services: results.services || [],
          os_fingerprint: results.os_fingerprint,
          risk_score: results.risk_score || 0,
          last_scanned: asset.last_updated
        };
      });

      setNetworkAssets(formattedAssets);
    } catch (error) {
      console.error('Error fetching network assets:', error);
    }
  };

  // Initiate network discovery scan
  const initiateNetworkScan = async () => {
    if (!scanTarget.trim()) {
      toast({
        title: "Error",
        description: "Please enter a target IP range or hostname",
        variant: "destructive"
      });
      return;
    }

    setLoading(true);
    setActiveScans(prev => prev + 1);

    try {
      const { data, error } = await supabase.functions.invoke('infrastructure-discovery', {
        body: {
          action: 'network_scan',
          target: scanTarget.trim(),
          organizationId: organizationId
        }
      });

      if (error) throw error;

      toast({
        title: "Network Scan Initiated",
        description: `Discovered ${data.count} assets. Threat analysis in progress.`
      });

      // Refresh data
      await Promise.all([fetchNetworkAssets(), fetchThreatDetections()]);
      setScanTarget('');
    } catch (error) {
      console.error('Network scan error:', error);
      toast({
        title: "Scan Failed",
        description: "Failed to initiate network scan",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
      setActiveScans(prev => prev - 1);
    }
  };

  // Investigate specific threat
  const investigateThreat = async (indicator: string, type: string) => {
    setLoading(true);
    try {
      const { error } = await supabase.functions.invoke('threat-intelligence-lookup', {
        body: { indicator, type }
      });

      if (error) throw error;

      toast({
        title: "Threat Investigation Complete",
        description: `Analysis complete for ${indicator}`
      });

      await fetchThreatDetections();
    } catch (error) {
      console.error('Threat investigation error:', error);
      toast({
        title: "Investigation Failed",
        description: "Failed to complete threat investigation",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (organizationId) {
      fetchThreatDetections();
      fetchNetworkAssets();
    }
  }, [organizationId]);

  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case 'CRITICAL': return 'destructive';
      case 'HIGH': return 'destructive';
      case 'MEDIUM': return 'secondary';
      case 'LOW': return 'outline';
      default: return 'outline';
    }
  };

  const threatStats = {
    total: threatDetections.length,
    critical: threatDetections.filter(t => t.threat_level === 'CRITICAL').length,
    high: threatDetections.filter(t => t.threat_level === 'HIGH').length,
    active: threatDetections.filter(t => t.status === 'ACTIVE').length
  };

  return (
    <div className="space-y-6">
      {/* Header Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Threats</CardTitle>
            <AlertTriangle className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{threatStats.active}</div>
            <p className="text-xs text-muted-foreground">Requiring investigation</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Critical Threats</CardTitle>
            <Shield className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{threatStats.critical}</div>
            <p className="text-xs text-muted-foreground">Immediate action required</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Network Assets</CardTitle>
            <Network className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{networkAssets.length}</div>
            <p className="text-xs text-muted-foreground">Discovered endpoints</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Scans</CardTitle>
            <Search className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{activeScans}</div>
            <p className="text-xs text-muted-foreground">Running discoveries</p>
          </CardContent>
        </Card>
      </div>

      {/* Main Content Tabs */}
      <Tabs defaultValue="threats" className="space-y-4">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="threats">Threat Detection</TabsTrigger>
          <TabsTrigger value="network">Network Discovery</TabsTrigger>
          <TabsTrigger value="intelligence">Threat Intelligence</TabsTrigger>
          <TabsTrigger value="monitoring">Continuous Monitoring</TabsTrigger>
        </TabsList>

        <TabsContent value="threats" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                Real-Time Threat Detections
                <Badge variant="outline" className="ml-2 text-xs bg-yellow-500/10 text-yellow-400 border-yellow-500/30">
                  BETA
                </Badge>
              </CardTitle>
              <CardDescription>
                Active threats detected across your infrastructure
              </CardDescription>
            </CardHeader>
            <CardContent>
              {threatDetections.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No active threats detected</p>
                  <p className="text-sm">Your infrastructure appears secure</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {threatDetections.map((threat) => (
                    <div key={threat.id} className="flex items-center justify-between p-4 border rounded-lg">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2">
                          <Badge variant={getThreatLevelColor(threat.threat_level)}>
                            {threat.threat_level}
                          </Badge>
                          <Badge variant="outline">{threat.detection_type}</Badge>
                          <Badge variant={threat.status === 'ACTIVE' ? 'destructive' : 'secondary'}>
                            {threat.status}
                          </Badge>
                        </div>
                        <p className="font-medium">{threat.indicator}</p>
                        <p className="text-sm text-muted-foreground">
                          Source: {threat.source} • {new Date(threat.detected_at).toLocaleString()}
                        </p>
                      </div>
                      <Button
                        size="sm"
                        onClick={() => investigateThreat(threat.indicator, threat.detection_type.toLowerCase())}
                        disabled={loading}
                      >
                        <Eye className="h-4 w-4 mr-1" />
                        Investigate
                      </Button>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="network" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                Network Discovery & Asset Management
                <Badge variant="outline" className="ml-2 text-xs bg-yellow-500/10 text-yellow-400 border-yellow-500/30">
                  BETA
                </Badge>
              </CardTitle>
              <CardDescription>
                Discover and monitor network assets for security threats
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex gap-2">
                <Input
                  placeholder="Enter IP range (e.g., 192.168.1.0/24) or hostname"
                  value={scanTarget}
                  onChange={(e) => setScanTarget(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && initiateNetworkScan()}
                />
                <Button onClick={initiateNetworkScan} disabled={loading}>
                  <Search className="h-4 w-4 mr-1" />
                  Scan
                </Button>
              </div>

              {networkAssets.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Network className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No network assets discovered</p>
                  <p className="text-sm">Start a network scan to discover assets</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {networkAssets.map((asset) => (
                    <div key={asset.id} className="p-4 border rounded-lg">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <h3 className="font-medium">{asset.ip_address}</h3>
                          {asset.hostname && (
                            <span className="text-sm text-muted-foreground">({asset.hostname})</span>
                          )}
                        </div>
                        <Badge variant={asset.risk_score > 40 ? 'destructive' : 'secondary'}>
                          Risk: {asset.risk_score}
                        </Badge>
                      </div>

                      <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
                        <div>
                          <p className="text-muted-foreground">Open Ports</p>
                          <p>{asset.ports.slice(0, 5).join(', ')}{asset.ports.length > 5 ? '...' : ''}</p>
                        </div>
                        <div>
                          <p className="text-muted-foreground">Services</p>
                          <p>{asset.services.slice(0, 3).join(', ')}{asset.services.length > 3 ? '...' : ''}</p>
                        </div>
                        <div>
                          <p className="text-muted-foreground">OS</p>
                          <p>{asset.os_fingerprint || 'Unknown'}</p>
                        </div>
                      </div>

                      <p className="text-xs text-muted-foreground mt-2">
                        Last scanned: {new Date(asset.last_scanned).toLocaleString()}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="intelligence" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Globe className="h-5 w-5" />
                  Threat Intelligence Feeds
                  <Badge variant="outline" className="ml-2 text-xs bg-yellow-500/10 text-yellow-400 border-yellow-500/30">
                    BETA
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between items-center">
                    <span>AbuseIPDB</span>
                    <Badge variant="secondary">Active</Badge>
                  </div>
                  <div className="flex justify-between items-center">
                    <span>VirusTotal</span>
                    <Badge variant="secondary">Active</Badge>
                  </div>
                  <div className="flex justify-between items-center">
                    <span>AlienVault OTX</span>
                    <Badge variant="secondary">Active</Badge>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="cursor-pointer hover:bg-card/80 transition-colors" onClick={() => alert('Dark Web Monitoring - Feature coming soon!')}>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Eye className="h-5 w-5" />
                  Dark Web Monitoring
                  <Badge variant="outline" className="ml-2 text-xs bg-yellow-500/10 text-yellow-400 border-yellow-500/20">
                    IN DEVELOPMENT
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-4">
                  Monitor for leaked credentials and threat actor discussions
                </p>
                <Button variant="outline" size="sm">
                  Configure Monitoring
                </Button>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="monitoring" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card className="cursor-pointer hover:bg-card/80 transition-colors" onClick={() => alert('Cloud Security Integration - Feature coming soon!')}>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Cloud className="h-5 w-5" />
                  Cloud Security
                  <Badge variant="outline" className="ml-2 text-xs bg-yellow-500/10 text-yellow-400 border-yellow-500/20">
                    IN DEVELOPMENT
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-4">
                  Monitor AWS, Azure, GCP for misconfigurations
                </p>
                <Button variant="outline" size="sm">
                  Setup Integration
                </Button>
              </CardContent>
            </Card>

            <Card className="cursor-pointer hover:bg-card/80 transition-colors" onClick={() => alert('Email Security Analysis - Feature coming soon!')}>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Mail className="h-5 w-5" />
                  Email Security
                  <Badge variant="outline" className="ml-2 text-xs bg-yellow-500/10 text-yellow-400 border-yellow-500/20">
                    IN DEVELOPMENT
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-4">
                  Analyze email headers and attachments for threats
                </p>
                <Button variant="outline" size="sm">
                  Configure Analysis
                </Button>
              </CardContent>
            </Card>

            <Card className="cursor-pointer hover:bg-card/80 transition-colors" onClick={() => alert('DNS Monitoring - Feature coming soon!')}>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Network className="h-5 w-5" />
                  DNS Monitoring
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-4">
                  Passive DNS analysis for domain intelligence
                </p>
                <Button variant="outline" size="sm">
                  Enable Monitoring
                </Button>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};