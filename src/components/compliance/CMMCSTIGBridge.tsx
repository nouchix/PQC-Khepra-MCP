import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { CheckCircle, AlertTriangle, FileText, Target, Zap, Clock, Shield } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';

interface CMMCSTIGBridgeProps {
  organizationId: string;
}

interface ComplianceStatus {
  cmmc_level: number;
  total_assets: number;
  compliant_assets: number;
  compliance_percentage: number;
  overall_status: string;
  next_assessment_due: string;
  recommendations: string[];
}

interface ImplementationPlan {
  phases: Array<{
    phase: number;
    name: string;
    duration_weeks: number;
    tasks: string[];
  }>;
  estimated_completion: string;
  priority_controls: string[];
}

export const CMMCSTIGBridge: React.FC<CMMCSTIGBridgeProps> = ({ organizationId }) => {
  const [loading, setLoading] = useState(false);
  const [complianceStatus, setComplianceStatus] = useState<ComplianceStatus | null>(null);
  const [implementationPlan, setImplementationPlan] = useState<ImplementationPlan | null>(null);
  const [selectedLevel, setSelectedLevel] = useState<number>(3);
  const [selectedFamilies, setSelectedFamilies] = useState<string[]>([]);
  const [evidenceCount, setEvidenceCount] = useState(0);
  const [poamCount, setPOAMCount] = useState(0);

  const controlFamilies = [
    'Access Control',
    'Audit and Accountability',
    'Configuration Management',
    'Identification and Authentication',
    'Incident Response',
    'System and Communications Protection'
  ];

  useEffect(() => {
    loadComplianceStatus();
  }, [organizationId]);

  const loadComplianceStatus = async () => {
    try {
      const { data, error } = await supabase.functions.invoke('cmmc-stig-bridge', {
        body: {
          action: 'validate_compliance',
          organization_id: organizationId,
          cmmc_level: selectedLevel
        }
      });

      if (error) throw error;
      setComplianceStatus(data.compliance_status);
    } catch (error) {
      console.error('Error loading compliance status:', error);
      toast.error('Failed to load compliance status');
    }
  };

  const generateMapping = async () => {
    setLoading(true);
    try {
      const { data, error } = await supabase.functions.invoke('cmmc-stig-bridge', {
        body: {
          action: 'generate_mapping',
          organization_id: organizationId,
          cmmc_level: selectedLevel,
          control_families: selectedFamilies
        }
      });

      if (error) throw error;

      setImplementationPlan(data.implementation_plan);
      toast.success(`Generated mapping for ${data.mapped_controls} controls`);
    } catch (error) {
      console.error('Error generating mapping:', error);
      toast.error('Failed to generate CMMC-STIG mapping');
    } finally {
      setLoading(false);
    }
  };

  const collectEvidence = async () => {
    setLoading(true);
    try {
      const { data, error } = await supabase.functions.invoke('cmmc-stig-bridge', {
        body: {
          action: 'collect_evidence',
          organization_id: organizationId
        }
      });

      if (error) throw error;

      setEvidenceCount(data.evidence_collected);
      toast.success(`Collected ${data.evidence_collected} evidence items`);
    } catch (error) {
      console.error('Error collecting evidence:', error);
      toast.error('Failed to collect automated evidence');
    } finally {
      setLoading(false);
    }
  };

  const generatePOAM = async () => {
    setLoading(true);
    try {
      const { data, error } = await supabase.functions.invoke('cmmc-stig-bridge', {
        body: {
          action: 'create_poam',
          organization_id: organizationId
        }
      });

      if (error) throw error;

      setPOAMCount(data.poam_entries);
      toast.success(`Generated ${data.poam_entries} POAM entries`);
    } catch (error) {
      console.error('Error generating POAM:', error);
      toast.error('Failed to generate POAM');
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'COMPLIANT': return 'bg-green-500';
      case 'NON_COMPLIANT': return 'bg-red-500';
      default: return 'bg-yellow-500';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="p-2 bg-indigo-500/10 rounded-lg border border-indigo-500/20">
            <Zap className="h-8 w-8 text-indigo-500" />
          </div>
          <div>
            <h2 className="text-2xl font-black text-white tracking-tight">Sentinel Compliance Autopilot</h2>
            <p className="text-slate-400 text-sm">
              AI-Driven CMMC-to-STIG Evidence Correlation & Lifecycle Management
            </p>
          </div>
        </div>
        <Badge variant="secondary" className="bg-indigo-600/20 text-indigo-400 border-indigo-600/30 px-4 py-2 animate-pulse">
          <Shield className="w-4 h-4 mr-2" />
          Live Autopilot Engine
        </Badge>
      </div>

      {/* Compliance Status Overview */}
      {complianceStatus && (
        <Card className="bg-slate-900/40 border-slate-800 backdrop-blur-md">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-indigo-400">
              <Target className="w-5 h-5 text-indigo-500" />
              CMMC Level {complianceStatus.cmmc_level} Enterprise Coverage
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
              <div className="space-y-1">
                <div className="text-3xl font-black text-white">{complianceStatus.total_assets}</div>
                <div className="text-[10px] text-slate-500 uppercase font-black tracking-widest">Monitored Assets</div>
              </div>
              <div className="space-y-1">
                <div className="text-3xl font-black text-emerald-500">{complianceStatus.compliant_assets}</div>
                <div className="text-[10px] text-slate-500 uppercase font-black tracking-widest">Validated Compliance</div>
              </div>
              <div className="space-y-1">
                <div className="flex items-end justify-between mb-1">
                  <div className="text-3xl font-black text-white">{complianceStatus.compliance_percentage}%</div>
                  <div className="text-[10px] text-slate-500 uppercase font-black tracking-widest">Health</div>
                </div>
                <Progress value={complianceStatus.compliance_percentage} className="h-1.5 bg-slate-800" />
              </div>
              <div className="flex flex-col items-center justify-center p-3 rounded-lg bg-slate-800/50">
                <Badge className={`${getStatusColor(complianceStatus.overall_status)} text-white font-black`}>
                  {complianceStatus.overall_status}
                </Badge>
                <div className="text-[9px] text-slate-500 mt-2 uppercase font-bold">Current Posture</div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      <Tabs defaultValue="mapping" className="space-y-4">
        <TabsList className="grid w-full grid-cols-4 bg-slate-950 border-slate-800">
          <TabsTrigger value="mapping" className="data-[state=active]:bg-indigo-600">STIG Mapping</TabsTrigger>
          <TabsTrigger value="evidence" className="data-[state=active]:bg-indigo-600">Evidence Collection</TabsTrigger>
          <TabsTrigger value="poam" className="data-[state=active]:bg-indigo-600">POAM Generation</TabsTrigger>
          <TabsTrigger value="implementation" className="data-[state=active]:bg-indigo-600">Implementation</TabsTrigger>
        </TabsList>

        {/* STIG Mapping Tab */}
        <TabsContent value="mapping">
          <Card className="bg-black/20 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">CMMC-to-STIG Intelligence Mapping</CardTitle>
              <CardDescription className="text-slate-400">
                AI-driven correlation between CMMC level requirements and technical STIG controls
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-2">
                  <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Target CMMC Level</label>
                  <Select value={selectedLevel.toString()} onValueChange={(value) => setSelectedLevel(Number.parseInt(value))}>
                    <SelectTrigger className="bg-slate-900 border-slate-800 text-white">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-slate-900 border-slate-800">
                      <SelectItem value="1">Level 1 - Basic Cyber Hygiene</SelectItem>
                      <SelectItem value="2">Level 2 - Intermediate Cyber Hygiene</SelectItem>
                      <SelectItem value="3">Level 3 - Good Cyber Hygiene</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Focus Control Families</label>
                  <Select onValueChange={(value) => {
                    if (!selectedFamilies.includes(value)) {
                      setSelectedFamilies([...selectedFamilies, value]);
                    }
                  }}>
                    <SelectTrigger className="bg-slate-900 border-slate-800 text-white">
                      <SelectValue placeholder="Select families..." />
                    </SelectTrigger>
                    <SelectContent className="bg-slate-900 border-slate-800">
                      {controlFamilies.map((family) => (
                        <SelectItem key={family} value={family}>{family}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              {selectedFamilies.length > 0 && (
                <div className="flex flex-wrap gap-2 pt-2">
                  {selectedFamilies.map((family) => (
                    <Badge key={family} variant="secondary" className="bg-indigo-500/10 text-indigo-400 border-indigo-500/20 cursor-pointer hover:bg-red-500/20"
                      onClick={() => setSelectedFamilies(selectedFamilies.filter(f => f !== family))}>
                      {family} ×
                    </Badge>
                  ))}
                </div>
              )}

              <Button onClick={generateMapping} disabled={loading} className="w-full bg-indigo-600 hover:bg-indigo-700 font-bold py-6">
                {loading ? (
                  <div className="flex items-center gap-2">
                    <Clock className="w-4 h-4 animate-spin" />
                    Correlating Controls...
                  </div>
                ) : 'Execute CMMC-to-STIG Bridge Mapping'}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Evidence Collection Tab */}
        <TabsContent value="evidence">
          <Card className="bg-black/20 border-slate-800">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-white">
                <FileText className="w-5 h-5 text-indigo-400" />
                Automated Evidence Vault
              </CardTitle>
              <CardDescription className="text-slate-400">
                Continuous collection of technical evidence from Sentinel forensic traces and system scans
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="text-center p-6 border border-slate-800 bg-slate-900/50 rounded-xl relative overflow-hidden group">
                  <div className="absolute top-0 left-0 w-full h-1 bg-blue-500" />
                  <div className="text-3xl font-black text-blue-400 mb-1">{evidenceCount}</div>
                  <div className="text-[10px] text-slate-500 uppercase font-black tracking-widest">Verified Artifacts</div>
                </div>
                <div className="text-center p-6 border border-slate-800 bg-slate-900/50 rounded-xl relative overflow-hidden">
                  <div className="absolute top-0 left-0 w-full h-1 bg-emerald-500" />
                  <div className="text-3xl font-black text-emerald-400">
                    {complianceStatus?.total_assets || 0}
                  </div>
                  <div className="text-[10px] text-slate-500 uppercase font-black tracking-widest">Discovery Coverage</div>
                </div>
                <div className="text-center p-6 border border-slate-800 bg-indigo-950/20 rounded-xl relative overflow-hidden ring-1 ring-indigo-500/30">
                  <div className="absolute top-0 left-0 w-full h-1 bg-indigo-500" />
                  <div className="text-3xl font-black text-indigo-400 italic">AGENTIC</div>
                  <div className="text-[10px] text-indigo-300 uppercase font-black tracking-widest mt-1">Sentinel Engine</div>
                </div>
              </div>

              <div className="space-y-4">
                <h4 className="text-[11px] font-black text-slate-400 uppercase tracking-widest flex items-center">
                  <Shield className="h-3 w-3 mr-2 text-indigo-500" />
                  Live Artifact Streams:
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="flex items-center gap-3 p-3 rounded-lg border border-slate-800 bg-slate-900/30">
                    <CheckCircle className="w-5 h-5 text-emerald-500" />
                    <div>
                      <div className="text-xs font-bold text-white">Sentinel Behavioral Traces</div>
                      <div className="text-[10px] text-slate-500 leading-tight">Mapped to IR.L2-3.6.1 and SI.L2-3.14.6</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 p-3 rounded-lg border border-slate-800 bg-slate-900/30 opacity-70">
                    <CheckCircle className="w-5 h-5 text-indigo-500" />
                    <div>
                      <div className="text-xs font-bold text-white">System Config Exports</div>
                      <div className="text-[10px] text-slate-500 leading-tight">Technical documentation of STIG implementation</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 p-3 rounded-lg border border-slate-800 bg-slate-900/30">
                    <CheckCircle className="w-5 h-5 text-emerald-500" />
                    <div>
                      <div className="text-xs font-bold text-white">Access Control Matrix</div>
                      <div className="text-[10px] text-slate-500 leading-tight">Live verification of AC.L2-3.1.1 information flows</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 p-3 rounded-lg border border-slate-800 bg-slate-900/30 opacity-70">
                    <CheckCircle className="w-5 h-5 text-indigo-500" />
                    <div>
                      <div className="text-xs font-bold text-white">Vulnerability Attestations</div>
                      <div className="text-[10px] text-slate-500 leading-tight">Point-in-time evidence of CA.L2-3.12.1 scans</div>
                    </div>
                  </div>
                </div>
              </div>

              <Button onClick={collectEvidence} disabled={loading} className="w-full bg-indigo-600 hover:bg-indigo-700 font-bold py-6 group">
                <Zap className="w-4 h-4 mr-2 group-hover:animate-bounce" />
                {loading ? 'Executing Real-Time Collection...' : 'Initiate Automated Evidence Harvest'}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* POAM Generation Tab */}
        <TabsContent value="poam">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5" />
                Plan of Action & Milestones (POAM)
              </CardTitle>
              <CardDescription>
                Automatically generate POAM entries for identified findings
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="text-center p-4 border rounded-lg">
                  <div className="text-2xl font-bold text-red-600">{poamCount}</div>
                  <div className="text-sm text-muted-foreground">POAM Entries</div>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <div className="text-2xl font-bold text-orange-600">
                    {complianceStatus ? complianceStatus.total_assets - complianceStatus.compliant_assets : 0}
                  </div>
                  <div className="text-sm text-muted-foreground">Non-Compliant Assets</div>
                </div>
              </div>

              <div className="space-y-2">
                <h4 className="font-medium">POAM includes:</h4>
                <ul className="text-sm space-y-1 text-muted-foreground">
                  <li>• Weakness descriptions and severity levels</li>
                  <li>• Affected CMMC controls mapping</li>
                  <li>• Detailed remediation plans</li>
                  <li>• Estimated completion timelines</li>
                  <li>• Responsible party assignments</li>
                </ul>
              </div>

              <Button onClick={generatePOAM} disabled={loading} className="w-full">
                {loading ? 'Generating...' : 'Generate POAM'}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Implementation Plan Tab */}
        <TabsContent value="implementation">
          {implementationPlan ? (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Clock className="w-5 h-5" />
                  Implementation Roadmap
                </CardTitle>
                <CardDescription>
                  Estimated completion: {implementationPlan.estimated_completion}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  {implementationPlan.phases.map((phase) => (
                    <div key={phase.phase} className="border-l-4 border-blue-500 pl-4">
                      <div className="flex items-center justify-between mb-2">
                        <h4 className="font-medium">
                          Phase {phase.phase}: {phase.name}
                        </h4>
                        <Badge variant="outline">
                          {phase.duration_weeks} weeks
                        </Badge>
                      </div>
                      <ul className="text-sm space-y-1 text-muted-foreground">
                        {phase.tasks.map((task, index) => (
                          <li key={index}>• {task}</li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="text-center py-8">
                <p className="text-muted-foreground">
                  Generate CMMC-STIG mapping first to see implementation plan
                </p>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>

      {/* Recommendations */}
      {complianceStatus?.recommendations && (
        <Card>
          <CardHeader>
            <CardTitle>Recommendations</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2">
              {complianceStatus.recommendations.map((rec, index) => (
                <li key={index} className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-blue-500 mt-0.5 flex-shrink-0" />
                  <span className="text-sm">{rec}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  );
};