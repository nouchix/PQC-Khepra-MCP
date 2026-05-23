import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Switch } from '@/components/ui/switch';
import { Progress } from '@/components/ui/progress';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { 
  Shield, 
  Lock, 
  FileCheck, 
  AlertTriangle, 
  CheckCircle, 
  Zap,
  Eye,
  UserCheck,
  Settings,
  TrendingUp
} from 'lucide-react';

interface ComplianceFramework {
  id: string;
  name: string;
  type: 'soc2' | 'fedramp' | 'iso27001' | 'hipaa' | 'cmmc';
  status: 'compliant' | 'in-progress' | 'non-compliant';
  coverage: number;
  controls: number;
  validatedControls: number;
  lastAssessment: string;
  nextAssessment: string;
}

interface SecurityControl {
  id: string;
  name: string;
  category: string;
  status: 'implemented' | 'partial' | 'not-implemented';
  automation: boolean;
  lastValidated: string;
  evidence: string[];
}

export const ComplianceSecurityEnhancement = () => {
  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([
    {
      id: 'soc2-type2',
      name: 'SOC 2 Type II',
      type: 'soc2',
      status: 'compliant',
      coverage: 98,
      controls: 125,
      validatedControls: 123,
      lastAssessment: '2024-01-15',
      nextAssessment: '2024-07-15'
    },
    {
      id: 'fedramp-moderate',
      name: 'FedRAMP Moderate',
      type: 'fedramp',
      status: 'in-progress',
      coverage: 85,
      controls: 325,
      validatedControls: 276,
      lastAssessment: '2023-12-01',
      nextAssessment: '2024-03-01'
    },
    {
      id: 'iso27001',
      name: 'ISO 27001:2022',
      type: 'iso27001',
      status: 'compliant',
      coverage: 95,
      controls: 93,
      validatedControls: 88,
      lastAssessment: '2024-01-10',
      nextAssessment: '2025-01-10'
    },
    {
      id: 'cmmc-level3',
      name: 'CMMC Level 3',
      type: 'cmmc',
      status: 'in-progress',
      coverage: 75,
      controls: 130,
      validatedControls: 98,
      lastAssessment: '2023-11-15',
      nextAssessment: '2024-02-15'
    }
  ]);

  const [securityControls] = useState<SecurityControl[]>([
    {
      id: 'ac-01',
      name: 'Access Control Policy',
      category: 'Access Control',
      status: 'implemented',
      automation: true,
      lastValidated: '2024-01-20',
      evidence: ['Policy Document', 'Implementation Guide', 'Audit Log']
    },
    {
      id: 'au-02',
      name: 'Audit Events',
      category: 'Audit & Accountability',
      status: 'implemented',
      automation: true,
      lastValidated: '2024-01-19',
      evidence: ['Event List', 'Log Analysis', 'Monitoring Dashboard']
    },
    {
      id: 'cm-02',
      name: 'Baseline Configuration',
      category: 'Configuration Management',
      status: 'partial',
      automation: false,
      lastValidated: '2024-01-18',
      evidence: ['Configuration Templates', 'Baseline Documentation']
    },
    {
      id: 'ia-02',
      name: 'Identification & Authentication',
      category: 'Identification & Authentication',
      status: 'implemented',
      automation: true,
      lastValidated: '2024-01-20',
      evidence: ['MFA Implementation', 'Identity Provider Config', 'Access Logs']
    }
  ]);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'compliant':
      case 'implemented': 
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'in-progress':
      case 'partial': 
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      case 'non-compliant':
      case 'not-implemented': 
        return <AlertTriangle className="h-4 w-4 text-red-500" />;
      default: 
        return <Shield className="h-4 w-4" />;
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'soc2': return <FileCheck className="h-4 w-4" />;
      case 'fedramp': return <Shield className="h-4 w-4" />;
      case 'iso27001': return <Lock className="h-4 w-4" />;
      case 'cmmc': return <UserCheck className="h-4 w-4" />;
      default: return <Shield className="h-4 w-4" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'compliant': return 'text-green-600 bg-green-50';
      case 'in-progress': return 'text-yellow-600 bg-yellow-50';
      case 'non-compliant': return 'text-red-600 bg-red-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const runComplianceValidation = (frameworkId: string) => {
    setFrameworks(prev => prev.map(fw => 
      fw.id === frameworkId 
        ? { ...fw, status: 'in-progress' as const }
        : fw
    ));
    
    // Simulate validation process
    setTimeout(() => {
      setFrameworks(prev => prev.map(fw => 
        fw.id === frameworkId 
          ? { 
              ...fw, 
              status: 'compliant' as const,
              coverage: Math.min(fw.coverage + 2, 100),
              validatedControls: Math.min(fw.validatedControls + 2, fw.controls)
            }
          : fw
      ));
    }, 2000);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-foreground">Compliance & Security Enhancement</h2>
          <p className="text-muted-foreground">Multi-framework compliance automation and security controls</p>
        </div>
        <Badge variant="secondary" className="bg-primary/10 text-primary">
          Phase 5 Implementation
        </Badge>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {frameworks.map((framework) => (
          <Card key={framework.id} className="relative">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  {getTypeIcon(framework.type)}
                  <CardTitle className="text-sm">{framework.name}</CardTitle>
                </div>
                {getStatusIcon(framework.status)}
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">Coverage</span>
                  <span className="font-medium">{framework.coverage}%</span>
                </div>
                <Progress value={framework.coverage} className="h-1" />
              </div>
              
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground">Controls</p>
                <p className="text-sm font-bold">
                  {framework.validatedControls}/{framework.controls}
                </p>
              </div>

              <div className="space-y-1">
                <p className="text-xs text-muted-foreground">Next Assessment</p>
                <p className="text-xs">{new Date(framework.nextAssessment).toLocaleDateString()}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="soc2">SOC 2</TabsTrigger>
          <TabsTrigger value="fedramp">FedRAMP</TabsTrigger>
          <TabsTrigger value="iso27001">ISO 27001</TabsTrigger>
          <TabsTrigger value="security">Security Controls</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <TrendingUp className="h-4 w-4" />
                  <span>Compliance Dashboard</span>
                </CardTitle>
                <CardDescription>Overall compliance status and trends</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Overall Compliance Score</span>
                    <span className="font-bold text-lg">89%</span>
                  </div>
                  <Progress value={89} className="h-2" />
                  
                  <div className="grid grid-cols-2 gap-4 mt-4">
                    <div className="text-center">
                      <p className="text-2xl font-bold text-green-600">673</p>
                      <p className="text-xs text-muted-foreground">Implemented Controls</p>
                    </div>
                    <div className="text-center">
                      <p className="text-2xl font-bold text-yellow-600">88</p>
                      <p className="text-xs text-muted-foreground">In Progress</p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Zap className="h-4 w-4" />
                  <span>Automation Status</span>
                </CardTitle>
                <CardDescription>Automated compliance validation and monitoring</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Automated Controls</span>
                    <span className="font-medium">485/673</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Real-time Monitoring</span>
                    <Badge variant="default">Active</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Continuous Validation</span>
                    <Badge variant="default">Enabled</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Auto-remediation</span>
                    <Badge variant="secondary">Configuring</Badge>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Security Controls Matrix</CardTitle>
              <CardDescription>Implementation status across all frameworks</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {securityControls.map((control) => (
                  <div key={control.id} className="flex items-center justify-between p-3 border rounded-lg">
                    <div className="flex items-center space-x-3">
                      {getStatusIcon(control.status)}
                      <div>
                        <p className="font-medium text-sm">{control.name}</p>
                        <p className="text-xs text-muted-foreground">
                          {control.category} • {control.id.toUpperCase()}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      {control.automation && (
                        <Badge variant="outline" className="text-xs">
                          <Zap className="h-3 w-3 mr-1" />
                          Auto
                        </Badge>
                      )}
                      <Badge variant={control.status === 'implemented' ? 'default' : 'secondary'}>
                        {control.status}
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="soc2">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <FileCheck className="h-4 w-4" />
                <span>SOC 2 Type II Compliance</span>
              </CardTitle>
              <CardDescription>Service Organization Control 2 audit requirements</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-4">
                  <h4 className="font-medium">Trust Service Criteria</h4>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Security</span>
                      <Badge variant="default">100%</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Availability</span>
                      <Badge variant="default">98%</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Processing Integrity</span>
                      <Badge variant="default">95%</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Confidentiality</span>
                      <Badge variant="default">100%</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Privacy</span>
                      <Badge variant="secondary">N/A</Badge>
                    </div>
                  </div>
                </div>
                <div className="space-y-4">
                  <h4 className="font-medium">Audit Readiness</h4>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Evidence Collection</span>
                      <Switch defaultChecked />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Control Testing</span>
                      <Switch defaultChecked />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Documentation</span>
                      <Switch defaultChecked />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Continuous Monitoring</span>
                      <Switch defaultChecked />
                    </div>
                  </div>
                </div>
              </div>
              <div className="flex space-x-2">
                <Button onClick={() => runComplianceValidation('soc2-type2')}>
                  Run Validation
                </Button>
                <Button variant="outline">Generate Report</Button>
                <Button variant="outline">Schedule Assessment</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="fedramp">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Shield className="h-4 w-4" />
                <span>FedRAMP Moderate Authorization</span>
              </CardTitle>
              <CardDescription>Federal Risk and Authorization Management Program</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-4 md:grid-cols-3">
                <div className="space-y-2">
                  <h4 className="font-medium">Security Controls</h4>
                  <ul className="text-sm text-muted-foreground space-y-1">
                    <li>• NIST 800-53 Rev 4/5</li>
                    <li>• 325 security controls</li>
                    <li>• Control enhancements</li>
                    <li>• Continuous monitoring</li>
                  </ul>
                </div>
                <div className="space-y-2">
                  <h4 className="font-medium">Assessment Process</h4>
                  <ul className="text-sm text-muted-foreground space-y-1">
                    <li>• Security package review</li>
                    <li>• 3PAO assessment</li>
                    <li>• ConMon implementation</li>
                    <li>• ATO authorization</li>
                  </ul>
                </div>
                <div className="space-y-2">
                  <h4 className="font-medium">Current Status</h4>
                  <ul className="text-sm text-muted-foreground space-y-1">
                    <li>• Controls: 276/325 implemented</li>
                    <li>• Documentation: 90% complete</li>
                    <li>• Testing: In progress</li>
                    <li>• Timeline: On track</li>
                  </ul>
                </div>
              </div>
              <div className="flex space-x-2">
                <Button onClick={() => runComplianceValidation('fedramp-moderate')}>
                  Validate Controls
                </Button>
                <Button variant="outline">Generate SSP</Button>
                <Button variant="outline">ConMon Dashboard</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="iso27001">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Lock className="h-4 w-4" />
                <span>ISO 27001:2022 Certification</span>
              </CardTitle>
              <CardDescription>Information Security Management System</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-4">
                  <h4 className="font-medium">Annex A Controls</h4>
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>A.5 Information Security Policies</span>
                      <Badge variant="default">5/5</Badge>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span>A.6 Organization of Information Security</span>
                      <Badge variant="default">7/7</Badge>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span>A.7 Human Resource Security</span>
                      <Badge variant="default">6/6</Badge>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span>A.8 Asset Management</span>
                      <Badge variant="secondary">9/10</Badge>
                    </div>
                  </div>
                </div>
                <div className="space-y-4">
                  <h4 className="font-medium">ISMS Status</h4>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Risk Assessment</span>
                      <Badge variant="default">Complete</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Risk Treatment</span>
                      <Badge variant="default">Implemented</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Internal Audit</span>
                      <Badge variant="default">Passed</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Management Review</span>
                      <Badge variant="secondary">Scheduled</Badge>
                    </div>
                  </div>
                </div>
              </div>
              <div className="flex space-x-2">
                <Button onClick={() => runComplianceValidation('iso27001')}>
                  Run Assessment
                </Button>
                <Button variant="outline">Risk Register</Button>
                <Button variant="outline">ISMS Manual</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="security">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Settings className="h-4 w-4" />
                <span>Advanced Security Controls</span>
              </CardTitle>
              <CardDescription>Zero-trust architecture and threat detection</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-4">
                  <h4 className="font-medium">Zero Trust Implementation</h4>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Identity Verification</span>
                      <Switch defaultChecked />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Device Trust</span>
                      <Switch defaultChecked />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Network Segmentation</span>
                      <Switch defaultChecked />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Least Privilege Access</span>
                      <Switch defaultChecked />
                    </div>
                  </div>
                </div>
                <div className="space-y-4">
                  <h4 className="font-medium">Threat Detection</h4>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Behavioral Analysis</span>
                      <Badge variant="default">Active</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">ML Anomaly Detection</span>
                      <Badge variant="default">Training</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Threat Intelligence</span>
                      <Badge variant="default">Integrated</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Auto Response</span>
                      <Badge variant="secondary">Configuring</Badge>
                    </div>
                  </div>
                </div>
              </div>
              <div className="flex space-x-2">
                <Button>Configure Security</Button>
                <Button variant="outline">Threat Dashboard</Button>
                <Button variant="outline">Security Posture</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};