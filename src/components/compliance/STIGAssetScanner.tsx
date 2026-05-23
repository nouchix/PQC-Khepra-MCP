import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Checkbox } from '@/components/ui/checkbox';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { 
  Play, 
  Search, 
  Shield, 
  Server, 
  Monitor, 
  AlertTriangle,
  CheckCircle,
  Clock,
  Pause,
  RotateCcw
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';

interface Asset {
  id: string;
  asset_name: string;
  asset_type: string;
  platform: string;
  operating_system?: string | null;
  ip_address?: string | null;
  hostname?: string | null;
  compliance_status: any;
  last_scanned: string;
  stig_applicability?: any;
  discovery_method?: string | null;
  created_at: string;
  updated_at: string;
  metadata?: any;
  risk_score?: number;
  version?: string | null;
  organization_id: string;
}

interface ScanJob {
  id: string;
  asset_id: string;
  scan_type: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  progress: number;
  started_at: string;
  completed_at?: string;
  error_message?: string;
}

interface STIGAssetScannerProps {
  organizationId: string;
  onScanComplete?: (results: any) => void;
}

export const STIGAssetScanner: React.FC<STIGAssetScannerProps> = ({
  organizationId,
  onScanComplete
}) => {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [selectedAssets, setSelectedAssets] = useState<string[]>([]);
  const [scanJobs, setScanJobs] = useState<ScanJob[]>([]);
  const [loading, setLoading] = useState(false);
  const [scanType, setScanType] = useState('automated');
  const [filterPlatform, setFilterPlatform] = useState('all');
  const [filterCompliance, setFilterCompliance] = useState('all');
  const { toast } = useToast();

  useEffect(() => {
    fetchAssets();
    const interval = setInterval(fetchScanJobs, 5000); // Poll every 5 seconds
    return () => clearInterval(interval);
  }, [organizationId]);

  const fetchAssets = async () => {
    try {
      setLoading(true);
      const { data, error } = await supabase
        .from('environment_assets')
        .select('*')
        .eq('organization_id', organizationId);

      if (error) throw error;
      setAssets((data || []).map(asset => ({
        ...asset,
        ip_address: asset.ip_address?.toString() || null,
        hostname: asset.hostname || null,
        operating_system: asset.operating_system || null,
        discovery_method: asset.discovery_method || null,
        version: asset.version || null
      })));
    } catch (err) {
      console.error('Error fetching assets:', err);
      toast({
        title: "Error",
        description: "Failed to fetch environment assets",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const fetchScanJobs = async () => {
    try {
      // Use edge function to get scan jobs
      const { data, error } = await supabase.functions.invoke('stig-compliance-orchestrator', {
        body: {
          action: 'get_scan_jobs',
          organization_id: organizationId
        }
      });

      if (error) throw error;
      setScanJobs(data?.jobs || []);
    } catch (err) {
      console.error('Error fetching scan jobs:', err);
    }
  };

  const initiateScan = async (assetIds: string[], type: string = 'automated') => {
    try {
      setLoading(true);
      
      for (const assetId of assetIds) {
        const { data, error } = await supabase.functions.invoke('stig-compliance-orchestrator', {
          body: {
            action: 'scan',
            asset_id: assetId,
            organization_id: organizationId,
            scan_type: type
          }
        });

        if (error) throw error;
      }

      toast({
        title: "Scans Initiated",
        description: `STIG compliance scans started for ${assetIds.length} asset(s)`,
      });

      setSelectedAssets([]);
      await fetchScanJobs();
      
    } catch (err) {
      console.error('Error initiating scans:', err);
      toast({
        title: "Scan Failed",
        description: "Failed to initiate STIG compliance scans",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const cancelScan = async (jobId: string) => {
    try {
      const { data, error } = await supabase.functions.invoke('stig-compliance-orchestrator', {
        body: {
          action: 'cancel_scan',
          job_id: jobId,
          organization_id: organizationId
        }
      });

      if (error) throw error;

      toast({
        title: "Scan Cancelled",
        description: "STIG compliance scan has been cancelled",
      });

      await fetchScanJobs();
    } catch (err) {
      console.error('Error cancelling scan:', err);
      toast({
        title: "Cancellation Failed",
        description: "Failed to cancel scan",
        variant: "destructive"
      });
    }
  };

  const filteredAssets = assets.filter(asset => {
    if (filterPlatform !== 'all' && asset.platform !== filterPlatform) return false;
    if (filterCompliance !== 'all') {
      const status = asset.compliance_status?.status || 'unknown';
      if (filterCompliance !== status) return false;
    }
    return true;
  });

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'compliant': return 'hsl(var(--success))';
      case 'non_compliant': return 'hsl(var(--destructive))';
      case 'partial': return 'hsl(var(--warning))';
      default: return 'hsl(var(--muted))';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'failed': return <AlertTriangle className="h-4 w-4 text-red-500" />;
      case 'running': return <Clock className="h-4 w-4 text-blue-500" />;
      case 'pending': return <Clock className="h-4 w-4 text-yellow-500" />;
      case 'cancelled': return <Pause className="h-4 w-4 text-gray-500" />;
      default: return <Shield className="h-4 w-4 text-gray-500" />;
    }
  };

  const platforms = [...new Set(assets.map(a => a.platform))];
  const activeScanJobs = scanJobs.filter(job => ['pending', 'running'].includes(job.status));

  return (
    <div className="space-y-6">
      {/* Control Panel */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Search className="h-5 w-5" />
            STIG Asset Scanner
          </CardTitle>
          <CardDescription>
            Discover and scan assets for STIG compliance violations
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div>
              <label className="text-sm font-medium mb-2 block">Scan Type</label>
              <Select value={scanType} onValueChange={setScanType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="automated">Automated</SelectItem>
                  <SelectItem value="comprehensive">Comprehensive</SelectItem>
                  <SelectItem value="targeted">Targeted</SelectItem>
                  <SelectItem value="baseline">Baseline</SelectItem>
                </SelectContent>
              </Select>
            </div>
            
            <div>
              <label className="text-sm font-medium mb-2 block">Platform Filter</label>
              <Select value={filterPlatform} onValueChange={setFilterPlatform}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Platforms</SelectItem>
                  {platforms.map(platform => (
                    <SelectItem key={platform} value={platform}>{platform}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            
            <div>
              <label className="text-sm font-medium mb-2 block">Compliance Status</label>
              <Select value={filterCompliance} onValueChange={setFilterCompliance}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Status</SelectItem>
                  <SelectItem value="compliant">Compliant</SelectItem>
                  <SelectItem value="non_compliant">Non-Compliant</SelectItem>
                  <SelectItem value="partial">Partial</SelectItem>
                  <SelectItem value="unknown">Unknown</SelectItem>
                </SelectContent>
              </Select>
            </div>
            
            <div className="flex flex-col justify-end">
              <Button 
                onClick={() => initiateScan(selectedAssets, scanType)}
                disabled={selectedAssets.length === 0 || loading}
                className="bg-hsl(var(--primary)) hover:bg-hsl(var(--primary))/90"
              >
                <Play className="h-4 w-4 mr-2" />
                Scan Selected ({selectedAssets.length})
              </Button>
            </div>
          </div>

          {activeScanJobs.length > 0 && (
            <Alert className="mb-4">
              <Monitor className="h-4 w-4" />
              <AlertDescription>
                {activeScanJobs.length} scan(s) currently running. Progress will update automatically.
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* Asset List */}
      <Card>
        <CardHeader>
          <CardTitle>Environment Assets</CardTitle>
          <CardDescription>
            Select assets to scan for STIG compliance violations ({filteredAssets.length} assets)
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {filteredAssets.map((asset) => {
              const scanJob = scanJobs.find(job => job.asset_id === asset.id && ['pending', 'running'].includes(job.status));
              const lastScan = scanJobs.find(job => job.asset_id === asset.id && job.status === 'completed');
              
              return (
                <div key={asset.id} className="flex items-center space-x-4 p-4 border rounded-lg">
                  <Checkbox
                    checked={selectedAssets.includes(asset.id)}
                    onCheckedChange={(checked) => {
                      if (checked) {
                        setSelectedAssets([...selectedAssets, asset.id]);
                      } else {
                        setSelectedAssets(selectedAssets.filter(id => id !== asset.id));
                      }
                    }}
                  />
                  
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <Server className="h-4 w-4 text-gray-500" />
                      <span className="font-medium">{asset.asset_name}</span>
                      <Badge variant="outline">{asset.platform}</Badge>
                      {asset.operating_system && (
                        <Badge variant="secondary">{asset.operating_system}</Badge>
                      )}
                    </div>
                    
                    <div className="text-sm text-gray-600 grid grid-cols-2 gap-4">
                      <div>
                        <p>Type: {asset.asset_type}</p>
                        {asset.ip_address && <p>IP: {asset.ip_address}</p>}
                        {asset.hostname && <p>Hostname: {asset.hostname}</p>}
                      </div>
                      <div>
                        <p>Last Scanned: {new Date(asset.last_scanned).toLocaleDateString()}</p>
                        {lastScan && (
                          <p>Last STIG Scan: {new Date(lastScan.completed_at!).toLocaleDateString()}</p>
                        )}
                      </div>
                    </div>
                    
                    {scanJob && (
                      <div className="mt-3">
                        <div className="flex items-center justify-between text-sm mb-1">
                          <span className="flex items-center gap-1">
                            {getStatusIcon(scanJob.status)}
                            Scanning ({scanJob.scan_type})
                          </span>
                          <span>{scanJob.progress}%</span>
                        </div>
                        <Progress value={scanJob.progress} className="h-2" />
                      </div>
                    )}
                  </div>
                  
                  <div className="flex flex-col items-end gap-2">
                    <Badge 
                      style={{ backgroundColor: getStatusColor(asset.compliance_status?.status || 'unknown') }}
                      className="text-white"
                    >
                      {asset.compliance_status?.status || 'Unknown'}
                    </Badge>
                    
                    {scanJob ? (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => cancelScan(scanJob.id)}
                        className="text-red-600 hover:text-red-700"
                      >
                        <Pause className="h-4 w-4 mr-1" />
                        Cancel
                      </Button>
                    ) : (
                      <Button
                        size="sm"
                        onClick={() => initiateScan([asset.id], scanType)}
                        disabled={loading}
                        className="bg-hsl(var(--primary)) hover:bg-hsl(var(--primary))/90"
                      >
                        <Play className="h-4 w-4 mr-1" />
                        Scan Now
                      </Button>
                    )}
                  </div>
                </div>
              );
            })}
            
            {filteredAssets.length === 0 && (
              <Alert>
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  No assets found matching the current filters. Try adjusting your filter criteria or add new assets to your environment.
                </AlertDescription>
              </Alert>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Scan History */}
      {scanJobs.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Recent Scan Activity</CardTitle>
            <CardDescription>
              Latest STIG compliance scan results and status
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {scanJobs.slice(0, 10).map((job) => {
                const asset = assets.find(a => a.id === job.asset_id);
                return (
                  <div key={job.id} className="flex items-center justify-between p-3 border rounded">
                    <div className="flex items-center gap-3">
                      {getStatusIcon(job.status)}
                      <div>
                        <p className="font-medium">{asset?.asset_name || 'Unknown Asset'}</p>
                        <p className="text-sm text-gray-600">
                          {job.scan_type} scan • Started {new Date(job.started_at).toLocaleString()}
                        </p>
                      </div>
                    </div>
                    <div className="text-right">
                      <Badge 
                        variant={job.status === 'completed' ? "default" : 
                                job.status === 'failed' ? "destructive" : "secondary"}
                      >
                        {job.status}
                      </Badge>
                      {job.error_message && (
                        <p className="text-xs text-red-600 mt-1">{job.error_message}</p>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};