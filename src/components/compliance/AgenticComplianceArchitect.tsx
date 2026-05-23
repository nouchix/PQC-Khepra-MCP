import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import {
  Brain,
  Shield,
  CheckCircle,
  AlertTriangle,
  Clock,
  GitBranch,
  Eye,
  Play,
  Pause,
  Settings,
  FileCheck,
  Network
} from 'lucide-react';
import { ControlTestEngine } from './ControlTestEngine';
import { RemediationOrchestrator } from './RemediationOrchestrator';
import { ConnectorSDK } from './ConnectorSDK';
import { ComplianceKnowledgeGraph } from './ComplianceKnowledgeGraph';
import { AttestationEngine } from './AttestationEngine';
import { EvidenceCollectionEngine } from './EvidenceCollectionEngine';
import { ComplianceControlMapper } from './ComplianceControlMapper';
import { POAMGenerator } from '../automation/POAMGenerator';
import { EnhancedPOAMTracker } from '../automation/EnhancedPOAMTracker';
import { ComplianceDemoScenarios } from '../demo/ComplianceDemoScenarios';

interface AgentMode {
  id: string;
  name: string;
  description: string;
  riskLevel: 'low' | 'medium' | 'high';
  enabled: boolean;
}

interface ControlGap {
  id: string;
  controlId: string;
  framework: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'detected' | 'analyzing' | 'remediation-planned' | 'pending-approval' | 'remediating' | 'verified' | 'attested';
  description: string;
  affectedAssets: number;
  estimatedTime: string;
  blastRadius: number;
  remediationPlan?: {
    tool: string;
    steps: string[];
    approvalRequired: boolean;
    rollbackPlan: string[];
  };
}

interface AgentCapability {
  name: string;
  status: 'active' | 'inactive' | 'error';
  lastRun: Date;
  successRate: number;
  description: string;
}

const agentModes: AgentMode[] = [
  {
    id: 'observe',
    name: 'Observe Only',
    description: 'Monitor and report compliance gaps without taking action',
    riskLevel: 'low',
    enabled: true
  },
  {
    id: 'recommend',
    name: 'Recommend',
    description: 'Generate remediation plans and recommendations',
    riskLevel: 'low',
    enabled: true
  },
  {
    id: 'remediate-approval',
    name: 'Remediate with Approval',
    description: 'Execute remediations after human approval',
    riskLevel: 'medium',
    enabled: false
  },
  {
    id: 'autopilot',
    name: 'Autopilot',
    description: 'Fully autonomous remediation for low-risk controls',
    riskLevel: 'high',
    enabled: false
  }
];

export const AgenticComplianceArchitect: React.FC = () => {
  const [agentStatus, setAgentStatus] = useState<'running' | 'paused' | 'configuring'>('paused');
  const [activeMode, setActiveMode] = useState<string>('observe');
  const [controlGaps, setControlGaps] = useState<ControlGap[]>([]);
  const [capabilities, setCapabilities] = useState<AgentCapability[]>([]);
  const [overallCompliance, setOverallCompliance] = useState(78);
  const [isLoading, setIsLoading] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    initializeAgent();
    fetchControlGaps();
    fetchCapabilities();
  }, []);

  const initializeAgent = async () => {
    try {
      // Initialize agent with existing KHEPRA components
      const { data: frameworks } = await (supabase
        .from('compliance_frameworks') as any)
        .select('*')
        .eq('enabled', true);

      const { data: controls } = await supabase
        .from('compliance_controls')
        .select('*');

      console.log('Agent initialized with', frameworks?.length, 'frameworks and', controls?.length, 'controls');
    } catch (error) {
      console.error('Failed to initialize agent:', error);
    }
  };

  const updateGapStatus = (gapId: string, status: ControlGap['status']) => {
    setControlGaps(prev => prev.map(g => g.id === gapId ? { ...g, status } : g));
  };

  const mapToControlGap = (d: any): ControlGap => ({
    id: d.id,
    controlId: d.control_id,
    framework: 'SOC2 / TBD',
    severity: d.severity as any || 'medium',
    status: d.status as any || 'detected',
    description: d.description || '',
    affectedAssets: 0,
    estimatedTime: '4h',
    blastRadius: 5,
    remediationPlan: d.remediation_plan ? (typeof d.remediation_plan === 'string' ? JSON.parse(d.remediation_plan) : d.remediation_plan) : undefined
  });

  const fetchControlGaps = async () => {
    setIsLoading(true);
    try {
      const { data, error } = await supabase.from('compliance_control_gaps').select('*');
      if (error) throw error;

      if (data && data.length > 0) {
        setControlGaps(data.map(mapToControlGap));
      } else {
        setControlGaps([]);
      }
    } catch (error) {
      console.error('Failed to fetch control gaps:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const fetchCapabilities = async () => {
    const pendingCapabilities: AgentCapability[] = [];

    setCapabilities(pendingCapabilities);
  };

  const handleAgentToggle = async () => {
    if (agentStatus === 'running') {
      setAgentStatus('paused');
      toast({
        title: "Agent Paused",
        description: "SouHimBou AI agent has been paused",
      });
    } else {
      setAgentStatus('running');
      toast({
        title: "Agent Started",
        description: `SouHimBou AI agent is now running in ${activeMode} mode`,
      });

      // Trigger initial scan
      await triggerComplianceScan();
    }
  };

  const triggerComplianceScan = async () => {
    try {
      const { data, error } = await supabase.functions.invoke('grok-ai-agent', {
        body: {
          action: 'compliance_scan',
          mode: activeMode,
          frameworks: ['SOC2', 'ISO27001', 'PCI-DSS']
        }
      });

      if (error) throw error;

      toast({
        title: "Compliance Scan Initiated",
        description: "Agent is analyzing your infrastructure for compliance gaps",
      });
    } catch (error) {
      console.error('Failed to trigger compliance scan:', error);
      toast({
        title: "Scan Failed",
        description: "Failed to initiate compliance scan",
        variant: "destructive"
      });
    }
  };

  const handleModeChange = (mode: string) => {
    setActiveMode(mode);
    toast({
      title: "Mode Changed",
      description: `Agent mode changed to ${mode}`,
    });
  };

  const executeRemediation = async (gap: ControlGap) => {
    if (!gap.remediationPlan) return;

    try {
      await supabase.from('compliance_control_gaps').update({ status: 'remediating' }).eq('id', gap.id);

      updateGapStatus(gap.id, 'remediating');

      const { data, error } = await supabase.functions.invoke('grok-ai-agent', {
        body: {
          action: 'execute_remediation',
          controlId: gap.controlId,
          plan: gap.remediationPlan,
          requiresApproval: gap.remediationPlan.approvalRequired
        }
      });

      if (error) throw error;

      toast({
        title: "Remediation Executed",
        description: `Successfully executed remediation for ${gap.controlId}`,
      });

      await supabase.from('compliance_control_gaps').update({ status: 'verified' }).eq('id', gap.id);

      updateGapStatus(gap.id, 'verified');
    } catch (error) {
      console.error('Failed to execute remediation:', error);
      toast({
        title: "Remediation Failed",
        description: "Failed to execute remediation plan",
        variant: "destructive"
      });
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-blue-500';
      default: return 'bg-gray-500';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'verified': return 'text-green-600';
      case 'attested': return 'text-emerald-600';
      case 'remediating': return 'text-blue-600';
      case 'pending-approval': return 'text-orange-600';
      case 'detected': return 'text-red-600';
      default: return 'text-gray-600';
    }
  };

  return (
    <div className="space-y-6">
      {/* Agent Status Header */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Brain className="h-8 w-8 text-primary" />
              <div>
                <CardTitle>SouHimBou AI - Automated Compliance Engine</CardTitle>
                <CardDescription>
                  AI-powered infrastructure discovery, vulnerability scanning, and automated remediation to achieve CMMC certification in 90 days
                </CardDescription>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Badge variant={agentStatus === 'running' ? 'default' : 'secondary'}>
                {agentStatus === 'running' ? 'ACTIVE' : 'PAUSED'}
              </Badge>
              <Button
                onClick={handleAgentToggle}
                variant={agentStatus === 'running' ? 'outline' : 'default'}
                className="flex items-center gap-2"
              >
                {agentStatus === 'running' ? (
                  <>
                    <Pause className="h-4 w-4" />
                    Pause Agent
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4" />
                    Start Agent
                  </>
                )}
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-5 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">{overallCompliance}%</div>
              <div className="text-sm text-muted-foreground">CMMC Progress</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-orange-500">{controlGaps.length}</div>
              <div className="text-sm text-muted-foreground">Critical Gaps</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-500">1,247</div>
              <div className="text-sm text-muted-foreground">Assets Discovered</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-red-500">89</div>
              <div className="text-sm text-muted-foreground">Vulnerabilities</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-green-500">34</div>
              <div className="text-sm text-muted-foreground">Auto-Remediated</div>
            </div>
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="overview" className="w-full">
        <TabsList className="grid w-full grid-cols-8">
          <TabsTrigger value="overview">CMMC Dashboard</TabsTrigger>
          <TabsTrigger value="discovery">Asset Discovery</TabsTrigger>
          <TabsTrigger value="scanning">Vuln Scanning</TabsTrigger>
          <TabsTrigger value="remediation">Auto-Remediation</TabsTrigger>
          <TabsTrigger value="testing">Control Testing</TabsTrigger>
          <TabsTrigger value="connectors">Integrations</TabsTrigger>
          <TabsTrigger value="attestation">CMMC Attestation</TabsTrigger>
          <TabsTrigger value="modes">AI Modes</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <Alert className="border-blue-200 bg-blue-50">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>
              <strong>CMMC Certification Goal:</strong> 78% complete - On track to achieve Level 2 certification within 90 days.
              AI engine has automated 89% of remediation tasks, reducing manual effort by 340 hours.
            </AlertDescription>
          </Alert>

          <div className="grid grid-cols-2 gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  CMMC Level 2 Progress
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div>
                    <div className="flex justify-between text-sm mb-1">
                      <span>Access Control (AC)</span>
                      <span>92%</span>
                    </div>
                    <Progress value={92} className="h-2" />
                  </div>
                  <div>
                    <div className="flex justify-between text-sm mb-1">
                      <span>Identification & Authentication (IA)</span>
                      <span>78%</span>
                    </div>
                    <Progress value={78} className="h-2" />
                  </div>
                  <div>
                    <div className="flex justify-between text-sm mb-1">
                      <span>System & Communications Protection (SC)</span>
                      <span>65%</span>
                    </div>
                    <Progress value={65} className="h-2" />
                  </div>
                  <div>
                    <div className="flex justify-between text-sm mb-1">
                      <span>Configuration Management (CM)</span>
                      <span>88%</span>
                    </div>
                    <Progress value={88} className="h-2" />
                  </div>
                  <div>
                    <div className="flex justify-between text-sm mb-1">
                      <span>Incident Response (IR)</span>
                      <span>71%</span>
                    </div>
                    <Progress value={71} className="h-2" />
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Network className="h-5 w-5" />
                  Recent Activity
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3 text-sm">
                  <div className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500" />
                    <span>MFA enforcement completed for Okta</span>
                    <span className="text-muted-foreground ml-auto">2m ago</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <GitBranch className="h-4 w-4 text-blue-500" />
                    <span>PR created for S3 encryption compliance</span>
                    <span className="text-muted-foreground ml-auto">15m ago</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Eye className="h-4 w-4 text-yellow-500" />
                    <span>Asset discovery scan completed</span>
                    <span className="text-muted-foreground ml-auto">1h ago</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <FileCheck className="h-4 w-4 text-green-500" />
                    <span>Evidence collected for 15 controls</span>
                    <span className="text-muted-foreground ml-auto">2h ago</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="discovery" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Network className="h-5 w-5" />
                AI-Powered Infrastructure Discovery
              </CardTitle>
              <CardDescription>
                Automated discovery and cataloging of assets across cloud, on-premises, and OT environments
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-3 gap-4 mb-6">
                <div className="text-center p-4 border rounded-lg">
                  <div className="text-2xl font-bold text-blue-500">1,247</div>
                  <div className="text-sm text-muted-foreground">Total Assets</div>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <div className="text-2xl font-bold text-green-500">98.7%</div>
                  <div className="text-sm text-muted-foreground">Discovery Rate</div>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <div className="text-2xl font-bold text-orange-500">45</div>
                  <div className="text-sm text-muted-foreground">New This Week</div>
                </div>
              </div>

              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="p-4 border rounded-lg">
                    <h4 className="font-medium mb-2">Cloud Assets</h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span>AWS EC2 Instances</span>
                        <span className="font-medium">342</span>
                      </div>
                      <div className="flex justify-between">
                        <span>S3 Buckets</span>
                        <span className="font-medium">89</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Azure VMs</span>
                        <span className="font-medium">156</span>
                      </div>
                      <div className="flex justify-between">
                        <span>GCP Compute</span>
                        <span className="font-medium">78</span>
                      </div>
                    </div>
                  </div>

                  <div className="p-4 border rounded-lg">
                    <h4 className="font-medium mb-2">Identity Systems</h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span>Active Directory Users</span>
                        <span className="font-medium">2,134</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Okta Identities</span>
                        <span className="font-medium">1,892</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Service Accounts</span>
                        <span className="font-medium">267</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Privileged Accounts</span>
                        <span className="font-medium">45</span>
                      </div>
                    </div>
                  </div>
                </div>

                <Button className="w-full">
                  <Play className="h-4 w-4 mr-2" />
                  Run Full Infrastructure Discovery
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="scanning" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5" />
                Continuous Vulnerability Scanning
              </CardTitle>
              <CardDescription>
                AI-driven vulnerability assessment and risk prioritization for CMMC compliance
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-4 gap-4 mb-6">
                <div className="text-center p-4 border rounded-lg">
                  <div className="text-2xl font-bold text-red-500">89</div>
                  <div className="text-sm text-muted-foreground">Critical Vulns</div>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <div className="text-2xl font-bold text-orange-500">234</div>
                  <div className="text-sm text-muted-foreground">High Risk</div>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <div className="text-2xl font-bold text-yellow-500">456</div>
                  <div className="text-sm text-muted-foreground">Medium Risk</div>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <div className="text-2xl font-bold text-green-500">34</div>
                  <div className="text-sm text-muted-foreground">Auto-Fixed</div>
                </div>
              </div>

              <div className="space-y-4">
                <div className="p-4 border rounded-lg border-red-200 bg-red-50">
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="font-medium text-red-800">Critical: Unencrypted Data at Rest</h4>
                    <Badge variant="destructive">CMMC Blocker</Badge>
                  </div>
                  <p className="text-sm text-red-700 mb-3">
                    12 S3 buckets and 3 databases lack encryption, violating CMMC SC.13.175
                  </p>
                  <div className="flex gap-2">
                    <Button size="sm" variant="destructive">
                      Auto-Remediate Now
                    </Button>
                    <Button size="sm" variant="outline">
                      View Details
                    </Button>
                  </div>
                </div>

                <div className="p-4 border rounded-lg border-orange-200 bg-orange-50">
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="font-medium text-orange-800">High: Missing MFA Enforcement</h4>
                    <Badge variant="secondary">AC.7.020</Badge>
                  </div>
                  <p className="text-sm text-orange-700 mb-3">
                    45 user accounts without enforced multi-factor authentication
                  </p>
                  <div className="flex gap-2">
                    <Button size="sm" className="bg-orange-600 hover:bg-orange-700">
                      Schedule Remediation
                    </Button>
                    <Button size="sm" variant="outline">
                      Risk Assessment
                    </Button>
                  </div>
                </div>

                <Button className="w-full">
                  <Play className="h-4 w-4 mr-2" />
                  Start Comprehensive Security Scan
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="testing" className="space-y-4">
          <ControlTestEngine />
        </TabsContent>

        <TabsContent value="remediation" className="space-y-4">
          <RemediationOrchestrator />
        </TabsContent>

        <TabsContent value="connectors" className="space-y-4">
          <ConnectorSDK />
        </TabsContent>

        <TabsContent value="knowledge" className="space-y-4">
          <ComplianceKnowledgeGraph />
        </TabsContent>

        <TabsContent value="attestation" className="space-y-4">
          <AttestationEngine />
        </TabsContent>

        <TabsContent value="evidence" className="space-y-4">
          <EvidenceCollectionEngine />
        </TabsContent>

        <TabsContent value="poam" className="space-y-4">
          <POAMGenerator />
        </TabsContent>

        <TabsContent value="mapping" className="space-y-4">
          <ComplianceControlMapper />
        </TabsContent>

        <TabsContent value="demo" className="space-y-4">
          <ComplianceDemoScenarios />
        </TabsContent>

        <TabsContent value="gaps" className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">Active Control Gaps</h3>
            <Button onClick={fetchControlGaps} disabled={isLoading}>
              {isLoading ? 'Scanning...' : 'Refresh'}
            </Button>
          </div>

          <div className="space-y-4">
            {controlGaps.map((gap) => (
              <Card key={gap.id}>
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div>
                      <CardTitle className="flex items-center gap-2">
                        <Badge className={getSeverityColor(gap.severity)}>
                          {gap.severity.toUpperCase()}
                        </Badge>
                        {gap.controlId} - {gap.framework}
                      </CardTitle>
                      <CardDescription>{gap.description}</CardDescription>
                    </div>
                    <Badge variant="outline" className={getStatusColor(gap.status)}>
                      {gap.status.replaceAll('-', ' ').toUpperCase()}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-3 gap-4 mb-4">
                    <div className="text-center">
                      <div className="text-lg font-semibold">{gap.affectedAssets}</div>
                      <div className="text-sm text-muted-foreground">Affected Assets</div>
                    </div>
                    <div className="text-center">
                      <div className="text-lg font-semibold">{gap.estimatedTime}</div>
                      <div className="text-sm text-muted-foreground">Est. Time</div>
                    </div>
                    <div className="text-center">
                      <div className="text-lg font-semibold">{gap.blastRadius}/10</div>
                      <div className="text-sm text-muted-foreground">Blast Radius</div>
                    </div>
                  </div>

                  {gap.remediationPlan && (
                    <div className="space-y-3">
                      <h5 className="font-medium">Remediation Plan ({gap.remediationPlan.tool})</h5>
                      <div className="bg-muted p-3 rounded space-y-1">
                        {gap.remediationPlan.steps.map((step, index) => (
                          <div key={index} className="text-sm">
                            {index + 1}. {step}
                          </div>
                        ))}
                      </div>

                      {gap.remediationPlan.approvalRequired && gap.status === 'remediation-planned' && (
                        <Alert>
                          <AlertTriangle className="h-4 w-4" />
                          <AlertDescription>
                            This remediation requires approval before execution.
                          </AlertDescription>
                        </Alert>
                      )}

                      <div className="flex gap-2">
                        {gap.status === 'pending-approval' && (
                          <Button
                            onClick={() => executeRemediation(gap)}
                            size="sm"
                          >
                            Execute Remediation
                          </Button>
                        )}
                        {gap.status === 'remediation-planned' && (
                          <Button
                            onClick={() => executeRemediation(gap)}
                            size="sm"
                            variant="outline"
                          >
                            Request Approval
                          </Button>
                        )}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="capabilities" className="space-y-4">
          <div className="grid gap-4">
            {capabilities.map((capability, index) => (
              <Card key={index}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="flex items-center gap-2">
                        <Badge variant={capability.status === 'active' ? 'default' : 'secondary'}>
                          {capability.status}
                        </Badge>
                        {capability.name}
                      </CardTitle>
                      <CardDescription>{capability.description}</CardDescription>
                    </div>
                    <div className="text-right">
                      <div className="text-lg font-semibold">{capability.successRate}%</div>
                      <div className="text-sm text-muted-foreground">Success Rate</div>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center justify-between text-sm">
                    <span>Last Run: {capability.lastRun.toLocaleString()}</span>
                    <Progress value={capability.successRate} className="w-32 h-2" />
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="modes" className="space-y-4">
          <div className="grid gap-4">
            {agentModes.map((mode) => (
              <Card key={mode.id} className={activeMode === mode.id ? 'ring-2 ring-primary' : ''}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="flex items-center gap-2">
                        {mode.name}
                        <Badge variant={mode.riskLevel === 'high' ? 'destructive' : mode.riskLevel === 'medium' ? 'default' : 'secondary'}>
                          {mode.riskLevel} risk
                        </Badge>
                      </CardTitle>
                      <CardDescription>{mode.description}</CardDescription>
                    </div>
                    <div className="flex items-center gap-2">
                      {activeMode === mode.id && (
                        <Badge variant="outline">Active</Badge>
                      )}
                      <Button
                        onClick={() => handleModeChange(mode.id)}
                        variant={activeMode === mode.id ? 'default' : 'outline'}
                        size="sm"
                      >
                        {activeMode === mode.id ? 'Active' : 'Select'}
                      </Button>
                    </div>
                  </div>
                </CardHeader>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="attestations" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileCheck className="h-5 w-5" />
                KHEPRA Compliance Attestations
              </CardTitle>
              <CardDescription>
                Cryptographically signed compliance attestations with immutable evidence chains
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="grid grid-cols-3 gap-4">
                  <Card>
                    <CardContent className="pt-6">
                      <div className="text-center">
                        <div className="text-2xl font-bold text-green-500">24</div>
                        <div className="text-sm text-muted-foreground">Signed Attestations</div>
                      </div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent className="pt-6">
                      <div className="text-center">
                        <div className="text-2xl font-bold text-blue-500">156</div>
                        <div className="text-sm text-muted-foreground">Evidence Artifacts</div>
                      </div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent className="pt-6">
                      <div className="text-center">
                        <div className="text-2xl font-bold text-purple-500">98.7%</div>
                        <div className="text-sm text-muted-foreground">Chain Integrity</div>
                      </div>
                    </CardContent>
                  </Card>
                </div>

                <Alert>
                  <Shield className="h-4 w-4" />
                  <AlertDescription>
                    All attestations are cryptographically signed using KHEPRA protocol for maximum auditability and trust.
                  </AlertDescription>
                </Alert>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};