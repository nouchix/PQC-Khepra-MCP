import { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Shield, Link, Server, CheckCircle, AlertTriangle, Clock, Zap, Eye, Download, Upload } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";

interface STIGRule {
  id: string;
  stig_id: string;
  title: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  platform: string;
  check_content: string;
  fix_text: string;
  nist_control_mappings: string[];
  implementation_status: string;
  automation_script?: string;
  validation_query?: string;
}

interface EnvironmentAsset {
  id: string;
  asset_name: string;
  asset_type: string;
  platform: string;
  ip_address: string;
  hostname: string;
  operating_system: string;
  compliance_status: any;
  stig_applicability: string[];
  risk_score: number;
}

interface ConnectorMetrics {
  totalAssets: number;
  compliantAssets: number;
  totalSTIGs: number;
  implementedSTIGs: number;
  automatedChecks: number;
  securityScore: number;
}

export const STIGsConnector: React.FC = () => {
  const [stigRules, setSTIGRules] = useState<STIGRule[]>([]);
  const [assets, setAssets] = useState<EnvironmentAsset[]>([]);
  const [filteredSTIGs, setFilteredSTIGs] = useState<STIGRule[]>([]);
  const [selectedPlatform, setSelectedPlatform] = useState('all');
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [metrics, setMetrics] = useState<ConnectorMetrics>({
    totalAssets: 0,
    compliantAssets: 0,
    totalSTIGs: 0,
    implementedSTIGs: 0,
    automatedChecks: 0,
    securityScore: 0
  });
  const [loading, setLoading] = useState(true);
  const [scanInProgress, setScanInProgress] = useState(false);
  const { toast } = useToast();

  const platforms = [
    'Windows Server 2019',
    'Windows Server 2022',
    'Windows 10',
    'Windows 11',
    'Red Hat Enterprise Linux 8',
    'Red Hat Enterprise Linux 9',
    'Ubuntu 20.04',
    'Ubuntu 22.04',
    'VMware vSphere',
    'Microsoft SQL Server',
    'Oracle Database',
    'Active Directory'
  ];

  const severityColors = {
    CRITICAL: 'bg-red-500/10 text-red-400 border-red-500/30',
    HIGH: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
    MEDIUM: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
    LOW: 'bg-green-500/10 text-green-400 border-green-500/30'
  };

  useEffect(() => {
    fetchConnectorData();
  }, []);

  useEffect(() => {
    filterSTIGs();
  }, [stigRules, searchTerm, selectedPlatform, selectedSeverity]);

  const fetchConnectorData = async () => {
    try {
      // Fetch STIG rules
      const { data: stigsData, error: stigsError } = await supabase
        .from('stig_rules')
        .select('*')
        .order('stig_id');

      if (stigsError) throw stigsError;

      // Fetch environment assets
      const { data: assetsData, error: assetsError } = await supabase
        .from('environment_assets')
        .select('*')
        .order('asset_name');

      if (assetsError) throw assetsError;

      const transformedSTIGs = (stigsData || []).map(s => ({
        ...s,
        severity: (s.severity as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL') || 'MEDIUM',
        nist_control_mappings: Array.isArray(s.nist_control_mappings) ? s.nist_control_mappings : []
      }));
      
      const transformedAssets = (assetsData || []).map(a => ({
        ...a,
        ip_address: (a.ip_address as string) || '',
        compliance_status: a.compliance_status || {},
        stig_applicability: Array.isArray(a.stig_applicability) 
          ? a.stig_applicability.map(item => String(item)) 
          : []
      }));
      
      setSTIGRules(transformedSTIGs);
      setAssets(transformedAssets);
      calculateMetrics(transformedSTIGs, transformedAssets);
      
    } catch (error) {
      console.error('Error fetching connector data:', error);
      toast({
        title: "Error",
        description: "Failed to load STIGs connector data",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const calculateMetrics = (stigsData: STIGRule[], assetsData: EnvironmentAsset[]) => {
    const totalAssets = assetsData.length;
    const compliantAssets = assetsData.filter(a => a.risk_score < 30).length;
    const totalSTIGs = stigsData.length;
    const implementedSTIGs = stigsData.filter(s => s.implementation_status === 'implemented').length;
    const automatedChecks = stigsData.filter(s => s.automation_script).length;
    const securityScore = totalAssets > 0 ? Math.round((compliantAssets / totalAssets) * 100) : 0;

    setMetrics({
      totalAssets,
      compliantAssets,
      totalSTIGs,
      implementedSTIGs,
      automatedChecks,
      securityScore
    });
  };

  const filterSTIGs = () => {
    let filtered = stigRules;

    if (searchTerm) {
      filtered = filtered.filter(stig =>
        stig.stig_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        stig.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
        stig.description.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    if (selectedPlatform !== 'all') {
      filtered = filtered.filter(stig => stig.platform === selectedPlatform);
    }

    if (selectedSeverity !== 'all') {
      filtered = filtered.filter(stig => stig.severity === selectedSeverity);
    }

    setFilteredSTIGs(filtered);
  };

  const startEnvironmentScan = async () => {
    setScanInProgress(true);
    
    try {
      const { data, error } = await supabase.functions.invoke('environment-discovery-scanner', {
        body: {
          scan_type: 'comprehensive',
          include_stig_mapping: true
        }
      });

      if (error) throw error;

      toast({
        title: "Environment Scan Started",
        description: "Discovering assets and mapping STIG applicability",
      });

      // Refresh data after scan
      setTimeout(() => {
        fetchConnectorData();
        setScanInProgress(false);
      }, 5000);
      
    } catch (error) {
      setScanInProgress(false);
      toast({
        title: "Scan Failed",
        description: "Could not complete environment scan",
        variant: "destructive"
      });
    }
  };

  const implementSTIGRule = async (stigId: string) => {
    try {
      const { data, error } = await supabase.functions.invoke('stig-implementation-engine', {
        body: {
          stig_id: stigId,
          action: 'implement',
          validate_after: true
        }
      });

      if (error) throw error;

      toast({
        title: "Implementation Started",
        description: `STIG ${stigId} implementation initiated`,
      });
      
      fetchConnectorData();
    } catch (error) {
      toast({
        title: "Implementation Failed",
        description: "Could not implement STIG rule",
        variant: "destructive"
      });
    }
  };

  const getImplementationIcon = (status: string) => {
    switch (status) {
      case 'implemented': return <CheckCircle className="h-4 w-4 text-green-400" />;
      case 'in_progress': return <Clock className="h-4 w-4 text-yellow-400" />;
      case 'failed': return <AlertTriangle className="h-4 w-4 text-red-400" />;
      default: return <AlertTriangle className="h-4 w-4 text-gray-400" />;
    }
  };

  if (loading) {
    return (
      <Card className="bg-black/40 border-primary/30">
        <CardContent className="p-8">
          <div className="flex items-center justify-center">
            <div className="animate-spin h-8 w-8 border-2 border-primary border-t-transparent rounded-full"></div>
            <span className="ml-3 text-primary">Loading STIGs connector...</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Security Dashboard */}
      <div className="grid grid-cols-1 md:grid-cols-6 gap-4">
        <Card className="bg-gradient-to-r from-blue-500/10 to-blue-600/10 border-blue-500/30">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-blue-300 text-sm">Total Assets</p>
                <p className="text-2xl font-bold text-blue-400">{metrics.totalAssets}</p>
              </div>
              <Server className="h-6 w-6 text-blue-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-r from-green-500/10 to-green-600/10 border-green-500/30">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-green-300 text-sm">Compliant</p>
                <p className="text-2xl font-bold text-green-400">{metrics.compliantAssets}</p>
              </div>
              <CheckCircle className="h-6 w-6 text-green-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-r from-purple-500/10 to-purple-600/10 border-purple-500/30">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-purple-300 text-sm">STIG Rules</p>
                <p className="text-2xl font-bold text-purple-400">{metrics.totalSTIGs}</p>
              </div>
              <Shield className="h-6 w-6 text-purple-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-r from-orange-500/10 to-orange-600/10 border-orange-500/30">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-orange-300 text-sm">Implemented</p>
                <p className="text-2xl font-bold text-orange-400">{metrics.implementedSTIGs}</p>
              </div>
              <CheckCircle className="h-6 w-6 text-orange-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-r from-cyan-500/10 to-cyan-600/10 border-cyan-500/30">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-cyan-300 text-sm">Automated</p>
                <p className="text-2xl font-bold text-cyan-400">{metrics.automatedChecks}</p>
              </div>
              <Zap className="h-6 w-6 text-cyan-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-r from-primary/10 to-primary/5 border-primary/30">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-primary text-sm">Security Score</p>
                <p className="text-2xl font-bold text-primary">{metrics.securityScore}%</p>
              </div>
              <Shield className="h-6 w-6 text-primary" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main STIGs Connector Interface */}
      <Card className="bg-black/40 border-primary/30">
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Link className="h-6 w-6 text-primary" />
              <span className="text-primary">STIGs Connector</span>
              <Badge variant="outline" className="ml-2 text-xs bg-primary/10 text-primary border-primary/30">
                OWASP Secure
              </Badge>
            </div>
            
            <Button 
              onClick={startEnvironmentScan} 
              disabled={scanInProgress}
              className="bg-primary hover:bg-primary/90"
            >
              {scanInProgress ? (
                <Clock className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Eye className="h-4 w-4 mr-2" />
              )}
              {scanInProgress ? 'Scanning...' : 'Scan Environment'}
            </Button>
          </CardTitle>
          
          {/* Filters */}
          <div className="flex flex-wrap gap-4 mt-4">
            <div className="flex-1 min-w-64">
              <Input
                placeholder="Search STIG rules..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="bg-black/40 border-primary/30"
              />
            </div>
            
            <Select value={selectedPlatform} onValueChange={setSelectedPlatform}>
              <SelectTrigger className="w-64 bg-black/40 border-primary/30">
                <SelectValue placeholder="Select Platform" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Platforms</SelectItem>
                {platforms.map(platform => (
                  <SelectItem key={platform} value={platform}>
                    {platform}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select value={selectedSeverity} onValueChange={setSelectedSeverity}>
              <SelectTrigger className="w-48 bg-black/40 border-primary/30">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severities</SelectItem>
                <SelectItem value="CRITICAL">Critical</SelectItem>
                <SelectItem value="HIGH">High</SelectItem>
                <SelectItem value="MEDIUM">Medium</SelectItem>
                <SelectItem value="LOW">Low</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>

        <CardContent>
          <Tabs defaultValue="rules">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="rules">STIG Rules</TabsTrigger>
              <TabsTrigger value="assets">Environment Assets</TabsTrigger>
              <TabsTrigger value="mapping">Control Mapping</TabsTrigger>
            </TabsList>

            <TabsContent value="rules" className="mt-6 space-y-4">
              <div className="space-y-3">
                {filteredSTIGs.slice(0, 20).map((stig) => (
                  <div key={stig.id} className="p-4 bg-slate-800/40 rounded-lg border border-slate-600/30 hover:border-primary/30 transition-colors">
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-center space-x-3">
                        {getImplementationIcon(stig.implementation_status)}
                        <div>
                          <h4 className="font-semibold text-white">{stig.stig_id}</h4>
                          <p className="text-sm text-slate-300">{stig.title}</p>
                          <p className="text-xs text-slate-400 mt-1">{stig.platform}</p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Badge className={severityColors[stig.severity]}>
                          {stig.severity}
                        </Badge>
                        {stig.automation_script && (
                          <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/30">
                            <Zap className="h-3 w-3 mr-1" />
                            Auto
                          </Badge>
                        )}
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-3">
                      <div>
                        <p className="text-xs text-slate-400 mb-1">Check Content:</p>
                        <p className="text-xs text-slate-300 bg-black/20 p-2 rounded border">
                          {stig.check_content ? stig.check_content.substring(0, 100) + '...' : 'No check content available'}
                        </p>
                      </div>
                      <div>
                        <p className="text-xs text-slate-400 mb-1">Fix Text:</p>
                        <p className="text-xs text-slate-300 bg-black/20 p-2 rounded border">
                          {stig.fix_text ? stig.fix_text.substring(0, 100) + '...' : 'No fix text available'}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-4 text-xs text-slate-400">
                        <span>NIST Controls: {stig.nist_control_mappings?.length || 0}</span>
                        {stig.validation_query && <span>Validation: Available</span>}
                      </div>
                      
                      {stig.implementation_status !== 'implemented' && (
                        <Button 
                          onClick={() => implementSTIGRule(stig.stig_id)}
                          size="sm" 
                          variant="outline"
                          className="border-primary/30"
                        >
                          <Upload className="h-3 w-3 mr-1" />
                          Implement
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
                
                {filteredSTIGs.length > 20 && (
                  <div className="text-center py-4">
                    <p className="text-slate-400">Showing first 20 of {filteredSTIGs.length} STIG rules</p>
                  </div>
                )}
              </div>
            </TabsContent>

            <TabsContent value="assets" className="mt-6">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {assets.map((asset) => (
                  <Card key={asset.id} className="bg-slate-800/40 border-slate-600/30">
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between mb-3">
                        <div>
                          <h4 className="font-semibold text-white">{asset.asset_name}</h4>
                          <p className="text-xs text-slate-300">{asset.asset_type}</p>
                        </div>
                        <div className={`w-3 h-3 rounded-full ${asset.risk_score < 30 ? 'bg-green-500' : asset.risk_score < 70 ? 'bg-yellow-500' : 'bg-red-500'}`}></div>
                      </div>
                      
                      <div className="space-y-2 text-xs">
                        <div className="flex justify-between">
                          <span className="text-slate-400">Platform:</span>
                          <span className="text-white">{asset.platform}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-400">OS:</span>
                          <span className="text-white">{asset.operating_system}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-400">Risk Score:</span>
                          <span className={`font-semibold ${asset.risk_score < 30 ? 'text-green-400' : asset.risk_score < 70 ? 'text-yellow-400' : 'text-red-400'}`}>
                            {asset.risk_score}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-400">Applicable STIGs:</span>
                          <span className="text-white">{asset.stig_applicability?.length || 0}</span>
                        </div>
                      </div>
                      
                      <Progress 
                        value={100 - asset.risk_score} 
                        className="h-2 mt-3"
                      />
                    </CardContent>
                  </Card>
                ))}
              </div>
            </TabsContent>

            <TabsContent value="mapping" className="mt-6">
              <div className="text-center py-12">
                <Shield className="h-16 w-16 text-primary mx-auto mb-4" />
                <h3 className="text-xl font-semibold text-white mb-2">Control Mapping Engine</h3>
                <p className="text-slate-400 mb-4">
                  Intelligent mapping between NIST 800-53 controls, CMMC requirements, and STIG implementations
                </p>
                <Button className="bg-primary hover:bg-primary/90">
                  <Download className="h-4 w-4 mr-2" />
                  Generate Mapping Report
                </Button>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};