import { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Search, Shield, AlertTriangle, CheckCircle, Database, ExternalLink } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';
import { useOrganization } from '@/hooks/useOrganization';
import { toast } from '@/hooks/use-toast';

interface ThreatInvestigation {
  id: string;
  threat_indicator: string;
  indicator_type: string;
  investigation_status: string;
  threat_level: string;
  real_or_simulated: string;
  investigation_notes?: string;
  external_references: any;
  created_at: string;
}

interface InfrastructureAsset {
  id: string;
  asset_type: string;
  asset_identifier: string;
  location: string;
  security_status: string;
  metadata: any;
  last_verified: string;
}

export const ThreatInvestigation = () => {
  const [investigations, setInvestigations] = useState<ThreatInvestigation[]>([]);
  const [assets, setAssets] = useState<InfrastructureAsset[]>([]);
  const [newIndicator, setNewIndicator] = useState('');
  const [indicatorType, setIndicatorType] = useState('ip');
  const [loading, setLoading] = useState(false);
  const [investigationResults, setInvestigationResults] = useState<any>(null);
  
  const { user } = useAuth();
  const { currentOrganization } = useOrganization();

  useEffect(() => {
    fetchInvestigations();
    fetchAssets();
  }, [currentOrganization]);

  const fetchInvestigations = async () => {
    if (!currentOrganization) return;
    
    const { data, error } = await supabase
      .from('threat_investigations')
      .select('*')
      .eq('organization_id', currentOrganization.id)
      .order('created_at', { ascending: false });

    if (error) {
      toast({
        title: "Error",
        description: "Failed to fetch threat investigations",
        variant: "destructive",
      });
    } else {
      setInvestigations(data || []);
    }
  };

  const fetchAssets = async () => {
    if (!currentOrganization) return;
    
    const { data, error } = await supabase
      .from('infrastructure_audit')
      .select('*')
      .eq('organization_id', currentOrganization.id)
      .order('created_at', { ascending: false });

    if (error) {
      toast({
        title: "Error",
        description: "Failed to fetch infrastructure assets",
        variant: "destructive",
      });
    } else {
      setAssets(data || []);
    }
  };

  const investigateIndicator = async (indicator: string, type: string) => {
    setLoading(true);
    try {
      // Call threat intelligence function to get real data
      const { data, error } = await supabase.functions.invoke('threat-intelligence-lookup', {
        body: { indicator, type }
      });

      if (error) throw error;
      
      setInvestigationResults(data);
      
      // Update investigation in database
      await supabase
        .from('threat_investigations')
        .update({
          investigation_status: 'resolved',
          real_or_simulated: data.is_real ? 'real' : 'simulated',
          investigation_notes: JSON.stringify(data),
          external_references: data.references || []
        })
        .eq('threat_indicator', indicator);

      fetchInvestigations();
      
      toast({
        title: "Investigation Complete",
        description: `Analysis completed for ${indicator}`,
      });
    } catch (error) {
      toast({
        title: "Investigation Failed",
        description: "Failed to investigate threat indicator",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const addNewInvestigation = async () => {
    if (!newIndicator || !currentOrganization || !user) return;

    const { error } = await supabase
      .from('threat_investigations')
      .insert([{
        organization_id: currentOrganization.id,
        threat_indicator: newIndicator,
        indicator_type: indicatorType,
        investigation_status: 'pending',
        created_by: user.id
      }]);

    if (error) {
      toast({
        title: "Error",
        description: "Failed to create investigation",
        variant: "destructive",
      });
    } else {
      setNewIndicator('');
      fetchInvestigations();
      toast({
        title: "Investigation Created",
        description: "New threat investigation started",
      });
    }
  };

  const getStatusBadge = (status: string) => {
    const variants: Record<string, any> = {
      pending: { variant: "secondary", icon: AlertTriangle },
      investigating: { variant: "default", icon: Search },
      resolved: { variant: "default", icon: CheckCircle },
      false_positive: { variant: "secondary", icon: CheckCircle }
    };
    
    const config = variants[status] || variants.pending;
    const Icon = config.icon;
    
    return (
      <Badge variant={config.variant} className="flex items-center gap-1">
        <Icon className="h-3 w-3" />
        {status.replaceAll('_', ' ').toUpperCase()}
      </Badge>
    );
  };

  const getThreatLevelBadge = (level: string) => {
    const colors: Record<string, string> = {
      low: "bg-green-500/20 text-green-400 border-green-500/30",
      medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
      high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
      critical: "bg-red-500/20 text-red-400 border-red-500/30",
      unknown: "bg-gray-500/20 text-gray-400 border-gray-500/30"
    };
    
    return (
      <Badge className={colors[level] || colors.unknown}>
        {level.toUpperCase()}
      </Badge>
    );
  };

  const getRealityBadge = (reality: string) => {
    const colors: Record<string, string> = {
      real: "bg-red-500/20 text-red-400 border-red-500/30",
      simulated: "bg-blue-500/20 text-blue-400 border-blue-500/30",
      unknown: "bg-gray-500/20 text-gray-400 border-gray-500/30"
    };
    
    return (
      <Badge className={colors[reality] || colors.unknown}>
        {reality.toUpperCase()}
      </Badge>
    );
  };

  return (
    <div className="space-y-6">
      <Alert className="border-amber-500/50 bg-amber-500/10">
        <AlertTriangle className="h-4 w-4" />
        <AlertDescription>
          <strong>SECURITY ALERT INVESTIGATION</strong><br />
          Use this tool to verify if threats are real or simulated. For the IP 185.220.101.42 mentioned by ARGUS, 
          we need to determine if this is actual threat activity or demo data.
        </AlertDescription>
      </Alert>

      <Tabs defaultValue="investigations" className="w-full">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="investigations">Active Investigations</TabsTrigger>
          <TabsTrigger value="infrastructure">Infrastructure Audit</TabsTrigger>
          <TabsTrigger value="new">New Investigation</TabsTrigger>
        </TabsList>

        <TabsContent value="investigations" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Search className="h-5 w-5" />
                Threat Investigations
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {investigations.map((investigation) => (
                  <div key={investigation.id} className="p-4 border rounded-lg space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <code className="font-mono text-sm bg-slate-100 dark:bg-slate-800 px-2 py-1 rounded">
                          {investigation.threat_indicator}
                        </code>
                        <Badge variant="outline">{investigation.indicator_type.toUpperCase()}</Badge>
                      </div>
                      <div className="flex items-center gap-2">
                        {getStatusBadge(investigation.investigation_status)}
                        {getThreatLevelBadge(investigation.threat_level)}
                        {getRealityBadge(investigation.real_or_simulated)}
                      </div>
                    </div>
                    
                    {investigation.investigation_notes && (
                      <div className="text-sm text-muted-foreground bg-slate-50 dark:bg-slate-900 p-3 rounded">
                        {investigation.investigation_notes}
                      </div>
                    )}
                    
                    <div className="flex items-center gap-2">
                      <Button 
                        size="sm" 
                        onClick={() => investigateIndicator(investigation.threat_indicator, investigation.indicator_type)}
                        disabled={loading}
                      >
                        {loading ? 'Investigating...' : 'Investigate'}
                      </Button>
                      {investigation.real_or_simulated === 'real' && (
                        <Badge variant="destructive">REAL THREAT CONFIRMED</Badge>
                      )}
                      {investigation.real_or_simulated === 'simulated' && (
                        <Badge variant="secondary">SIMULATED DATA</Badge>
                      )}
                    </div>
                  </div>
                ))}
                
                {investigations.length === 0 && (
                  <div className="text-center py-8 text-muted-foreground">
                    No threat investigations found
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="infrastructure" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Database className="h-5 w-5" />
                Your Actual Infrastructure
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {assets.map((asset) => (
                  <div key={asset.id} className="p-4 border rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-3">
                        <Badge variant="outline">{asset.asset_type.toUpperCase()}</Badge>
                        <code className="font-mono text-sm">{asset.asset_identifier}</code>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge className={
                          asset.location === 'supabase' ? 'bg-green-500/20 text-green-400' :
                          asset.location === 'internal' ? 'bg-red-500/20 text-red-400' :
                          'bg-blue-500/20 text-blue-400'
                        }>
                          {asset.location.toUpperCase()}
                        </Badge>
                        <Badge className={
                          asset.security_status === 'secure' ? 'bg-green-500/20 text-green-400' :
                          asset.security_status === 'vulnerable' ? 'bg-orange-500/20 text-orange-400' :
                          asset.security_status === 'compromised' ? 'bg-red-500/20 text-red-400' :
                          'bg-gray-500/20 text-gray-400'
                        }>
                          {asset.security_status.toUpperCase()}
                        </Badge>
                      </div>
                    </div>
                    
                    {asset.metadata && Object.keys(asset.metadata).length > 0 && (
                      <div className="text-sm text-muted-foreground">
                        <pre className="text-xs">{JSON.stringify(asset.metadata, null, 2)}</pre>
                      </div>
                    )}
                    
                    <div className="text-xs text-muted-foreground mt-2">
                      Last verified: {new Date(asset.last_verified).toLocaleString()}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="new" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Start New Investigation</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4">
                <div>
                  <label className="text-sm font-medium">Threat Indicator</label>
                  <Input
                    placeholder="Enter IP, domain, hash, etc."
                    value={newIndicator}
                    onChange={(e) => setNewIndicator(e.target.value)}
                  />
                </div>
                
                <div>
                  <label className="text-sm font-medium">Indicator Type</label>
                  <Select value={indicatorType} onValueChange={setIndicatorType}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ip">IP Address</SelectItem>
                      <SelectItem value="domain">Domain</SelectItem>
                      <SelectItem value="hash">File Hash</SelectItem>
                      <SelectItem value="url">URL</SelectItem>
                      <SelectItem value="email">Email</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                
                <Button onClick={addNewInvestigation} disabled={!newIndicator}>
                  Start Investigation
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {investigationResults && (
        <Card className="border-amber-500/50">
          <CardHeader>
            <CardTitle className="text-amber-400">Investigation Results</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="text-sm bg-slate-900 p-4 rounded overflow-auto">
              {JSON.stringify(investigationResults, null, 2)}
            </pre>
          </CardContent>
        </Card>
      )}
    </div>
  );
};