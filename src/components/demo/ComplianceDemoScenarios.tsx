import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  PlayCircle, 
  Shield, 
  Target,
  Clock,
  CheckCircle,
  AlertTriangle,
  Zap,
  FileText,
  Eye,
  Settings,
  Users,
  Building,
  Globe,
  DollarSign,
  Gauge
} from 'lucide-react';

interface DemoScenario {
  id: string;
  title: string;
  description: string;
  targetAudience: string[];
  duration: string;
  complexity: 'Basic' | 'Intermediate' | 'Advanced';
  frameworks: string[];
  features: string[];
  roi: {
    timeReduction: string;
    costSavings: string;
    riskMitigation: string;
  };
  script: {
    setup: string[];
    demonstration: string[];
    outcomes: string[];
  };
}

const demoScenarios: DemoScenario[] = [
  {
    id: 'dod-contractor',
    title: 'DoD Contractor CMMC Readiness',
    description: 'Demonstrate automated CMMC Level 2 compliance preparation for defense contractors',
    targetAudience: ['Defense Contractors', 'Prime Contractors', 'Sub Contractors', 'C3PAOs'],
    duration: '15 minutes',
    complexity: 'Advanced',
    frameworks: ['CMMC 2.0', 'NIST 800-171', 'DFARS'],
    features: [
      'Automated Asset Discovery',
      'Evidence Collection',
      'POA&M Generation',
      'Control Gap Analysis',
      'Remediation Orchestration'
    ],
    roi: {
      timeReduction: '70% reduction in compliance prep time',
      costSavings: '$150K average audit cost savings',
      riskMitigation: '95% control automation coverage'
    },
    script: {
      setup: [
        'Start with simulated DoD contractor environment',
        'Show fragmented security tool landscape',
        'Display current manual compliance process pain points'
      ],
      demonstration: [
        'Launch automated infrastructure discovery',
        'Connect to AWS, M365, Okta, Splunk integrations',
        'Execute real-time evidence collection',
        'Generate automated POA&M with remediation plans',
        'Show control mapping across CMMC/NIST frameworks',
        'Demonstrate one-click remediation execution'
      ],
      outcomes: [
        'Complete CMMC readiness dashboard',
        'Audit-ready evidence packages',
        'Automated remediation of 23 control gaps',
        '90-day CMMC certification roadmap'
      ]
    }
  },
  {
    id: 'ot-manufacturer',
    title: 'OT Manufacturing Security',
    description: 'Showcase OT/ICS security monitoring and incident response for manufacturing environments',
    targetAudience: ['Manufacturing CISOs', 'OT Security Teams', 'Plant Managers', 'MSPs'],
    duration: '12 minutes',
    complexity: 'Advanced',
    frameworks: ['IEC 62443', 'NIST Cybersecurity Framework', 'NERC CIP'],
    features: [
      'OT Asset Discovery',
      'ICS Protocol Monitoring',
      'Threat Intelligence',
      'Incident Response Automation',
      'Safety System Integration'
    ],
    roi: {
      timeReduction: '60% faster incident response',
      costSavings: '40% reduction in downtime costs',
      riskMitigation: '99.9% uptime with security monitoring'
    },
    script: {
      setup: [
        'Display manufacturing facility network topology',
        'Show HMI interfaces and SCADA systems',
        'Demonstrate current blind spots in OT visibility'
      ],
      demonstration: [
        'Deploy passive OT monitoring sensors',
        'Discover Modbus, DNP3, and Ethernet/IP devices',
        'Show real-time protocol analysis and baselines',
        'Trigger simulated OT security incident',
        'Execute automated incident response playbook',
        'Demonstrate safety-aware remediation actions'
      ],
      outcomes: [
        'Complete OT asset inventory and risk assessment',
        'Real-time OT security monitoring dashboard',
        'Automated threat detection and response',
        'Compliance reporting for IEC 62443'
      ]
    }
  },
  {
    id: 'msp-multi-tenant',
    title: 'MSP Multi-Tenant SOC',
    description: 'Multi-tenant compliance management and automated reporting for MSP/MSSP clients',
    targetAudience: ['MSP Owners', 'MSSP Directors', 'Channel Partners', 'SMB Decision Makers'],
    duration: '10 minutes',
    complexity: 'Intermediate',
    frameworks: ['SOC 2', 'HIPAA', 'PCI DSS', 'ISO 27001'],
    features: [
      'Multi-Tenant Management',
      'Automated Client Reporting',
      'Compliance-as-a-Service',
      'White-Label Dashboards',
      'Margin Optimization'
    ],
    roi: {
      timeReduction: '80% reduction in report generation',
      costSavings: '15-point margin improvement',
      riskMitigation: 'Automated compliance for 100+ clients'
    },
    script: {
      setup: [
        'Show MSP managing 50+ diverse clients',
        'Display manual compliance reporting overhead',
        'Highlight margin pressure and scaling challenges'
      ],
      demonstration: [
        'Configure multi-tenant compliance engine',
        'Show per-client compliance dashboards',
        'Generate automated SOC 2/HIPAA reports',
        'Demonstrate white-label client portals',
        'Execute cross-client security analytics',
        'Show margin impact and pricing models'
      ],
      outcomes: [
        'Automated compliance for entire client base',
        'White-label client compliance portals',
        'Monthly automated compliance reporting',
        '15-point gross margin improvement'
      ]
    }
  },
  {
    id: 'enterprise-devsecops',
    title: 'Enterprise DevSecOps Pipeline',
    description: 'Shift-left compliance with automated policy enforcement in CI/CD pipelines',
    targetAudience: ['Enterprise CISOs', 'DevSecOps Teams', 'Cloud Architects', 'Auditors'],
    duration: '13 minutes',
    complexity: 'Advanced',
    frameworks: ['SOC 2', 'FedRAMP', 'PCI DSS', 'ISO 27001'],
    features: [
      'Policy-as-Code',
      'Pipeline Integration',
      'Compliance Gates',
      'Drift Detection',
      'Immutable Audit Trails'
    ],
    roi: {
      timeReduction: '90% faster audit preparation',
      costSavings: '60% reduction in remediation costs',
      riskMitigation: 'Zero policy drift tolerance'
    },
    script: {
      setup: [
        'Show enterprise multi-cloud environment',
        'Display current manual policy enforcement',
        'Highlight policy drift and compliance gaps'
      ],
      demonstration: [
        'Integrate compliance engine with CI/CD pipelines',
        'Show policy-as-code enforcement gates',
        'Demonstrate real-time drift detection',
        'Execute automated policy remediation',
        'Generate continuous compliance evidence',
        'Show immutable audit trail generation'
      ],
      outcomes: [
        'Fully automated compliance pipeline',
        'Zero-drift policy enforcement',
        'Continuous audit readiness',
        'Automated FedRAMP/SOC 2 evidence'
      ]
    }
  }
];

export const ComplianceDemoScenarios: React.FC = () => {
  const [selectedScenario, setSelectedScenario] = useState<DemoScenario>(demoScenarios[0]);
  const [demoPhase, setDemoPhase] = useState<'setup' | 'demo' | 'outcomes'>('setup');

  const executeDemo = (scenario: DemoScenario) => {
    setSelectedScenario(scenario);
    setDemoPhase('setup');
  };

  const nextPhase = () => {
    if (demoPhase === 'setup') setDemoPhase('demo');
    else if (demoPhase === 'demo') setDemoPhase('outcomes');
    else setDemoPhase('setup');
  };

  const getComplexityColor = (complexity: string) => {
    switch (complexity) {
      case 'Basic': return 'bg-green-500/20 text-green-400';
      case 'Intermediate': return 'bg-yellow-500/20 text-yellow-400';
      case 'Advanced': return 'bg-red-500/20 text-red-400';
      default: return 'bg-gray-500/20 text-gray-400';
    }
  };

  const getPhaseIcon = (phase: string) => {
    switch (phase) {
      case 'setup': return <Settings className="h-4 w-4" />;
      case 'demo': return <PlayCircle className="h-4 w-4" />;
      case 'outcomes': return <CheckCircle className="h-4 w-4" />;
      default: return <Settings className="h-4 w-4" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card className="bg-gradient-to-r from-blue-900/40 to-purple-900/40 border-blue-500/30">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-white">
            <Eye className="h-6 w-6 text-blue-400" />
            Compliance Demo Center
          </CardTitle>
          <CardDescription className="text-blue-200">
            Interactive demo scenarios for discovery calls and proof-of-concept presentations
          </CardDescription>
        </CardHeader>
      </Card>

      {/* Demo Scenarios Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {demoScenarios.map((scenario) => (
          <Card 
            key={scenario.id} 
            className={`bg-black/40 border-slate-600/30 cursor-pointer transition-all hover:border-blue-500/50 ${
              selectedScenario.id === scenario.id ? 'border-blue-500 bg-blue-900/20' : ''
            }`}
            onClick={() => setSelectedScenario(scenario)}
          >
            <CardHeader>
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <Badge className={getComplexityColor(scenario.complexity)}>
                      {scenario.complexity}
                    </Badge>
                    <Badge variant="outline" className="text-blue-400 border-blue-400">
                      {scenario.duration}
                    </Badge>
                  </div>
                  <CardTitle className="text-white text-lg">{scenario.title}</CardTitle>
                  <CardDescription className="text-gray-300 mt-2">
                    {scenario.description}
                  </CardDescription>
                </div>
                <Button
                  onClick={(e) => {
                    e.stopPropagation();
                    executeDemo(scenario);
                  }}
                  size="sm"
                  className="bg-blue-600 hover:bg-blue-700"
                >
                  <PlayCircle className="h-4 w-4 mr-1" />
                  Demo
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div>
                  <h4 className="font-medium text-white mb-2 flex items-center gap-2">
                    <Users className="h-4 w-4 text-blue-400" />
                    Target Audience
                  </h4>
                  <div className="flex flex-wrap gap-1">
                    {scenario.targetAudience.map((audience, index) => (
                      <Badge key={index} variant="secondary" className="text-xs">
                        {audience}
                      </Badge>
                    ))}
                  </div>
                </div>
                
                <div>
                  <h4 className="font-medium text-white mb-2 flex items-center gap-2">
                    <Shield className="h-4 w-4 text-green-400" />
                    Frameworks
                  </h4>
                  <div className="flex flex-wrap gap-1">
                    {scenario.frameworks.map((framework, index) => (
                      <Badge key={index} variant="outline" className="text-xs">
                        {framework}
                      </Badge>
                    ))}
                  </div>
                </div>
                
                <div className="grid grid-cols-3 gap-2 text-xs">
                  <div className="text-center p-2 bg-green-900/20 rounded">
                    <div className="text-green-400 font-semibold">{scenario.roi.timeReduction}</div>
                    <div className="text-gray-400">Time Saved</div>
                  </div>
                  <div className="text-center p-2 bg-blue-900/20 rounded">
                    <div className="text-blue-400 font-semibold">{scenario.roi.costSavings}</div>
                    <div className="text-gray-400">Cost Impact</div>
                  </div>
                  <div className="text-center p-2 bg-purple-900/20 rounded">
                    <div className="text-purple-400 font-semibold">{scenario.roi.riskMitigation}</div>
                    <div className="text-gray-400">Risk Reduction</div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Selected Demo Details */}
      <Card className="bg-black/40 border-blue-500/30">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-white flex items-center gap-2">
              <Target className="h-5 w-5 text-blue-400" />
              {selectedScenario.title} - Demo Script
            </CardTitle>
            <div className="flex items-center gap-2">
              <Badge className="bg-blue-500/20 text-blue-400">
                Phase: {demoPhase.charAt(0).toUpperCase() + demoPhase.slice(1)}
              </Badge>
              <Button onClick={nextPhase} size="sm">
                {getPhaseIcon(demoPhase)}
                Next Phase
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Tabs value={demoPhase} className="w-full">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="setup">Setup</TabsTrigger>
              <TabsTrigger value="demo">Demonstration</TabsTrigger>
              <TabsTrigger value="outcomes">Outcomes</TabsTrigger>
            </TabsList>

            <TabsContent value="setup" className="space-y-4">
              <Alert>
                <Settings className="h-4 w-4" />
                <AlertDescription>
                  Preparation phase: Set the stage and establish pain points before the demonstration
                </AlertDescription>
              </Alert>
              <div className="space-y-3">
                {selectedScenario.script.setup.map((step, index) => (
                  <div key={index} className="flex items-start gap-3 p-3 bg-slate-800/40 rounded">
                    <div className="w-6 h-6 rounded-full bg-blue-600 text-white text-xs flex items-center justify-center font-bold mt-0.5">
                      {index + 1}
                    </div>
                    <div className="text-gray-300">{step}</div>
                  </div>
                ))}
              </div>
            </TabsContent>

            <TabsContent value="demo" className="space-y-4">
              <Alert>
                <PlayCircle className="h-4 w-4" />
                <AlertDescription>
                  Core demonstration: Show the solution capabilities and automated workflows
                </AlertDescription>
              </Alert>
              <div className="space-y-3">
                {selectedScenario.script.demonstration.map((step, index) => (
                  <div key={index} className="flex items-start gap-3 p-3 bg-slate-800/40 rounded">
                    <div className="w-6 h-6 rounded-full bg-green-600 text-white text-xs flex items-center justify-center font-bold mt-0.5">
                      {index + 1}
                    </div>
                    <div className="text-gray-300">{step}</div>
                  </div>
                ))}
              </div>
            </TabsContent>

            <TabsContent value="outcomes" className="space-y-4">
              <Alert>
                <CheckCircle className="h-4 w-4" />
                <AlertDescription>
                  Results phase: Highlight achieved outcomes and business value
                </AlertDescription>
              </Alert>
              <div className="space-y-3">
                {selectedScenario.script.outcomes.map((outcome, index) => (
                  <div key={index} className="flex items-start gap-3 p-3 bg-slate-800/40 rounded">
                    <CheckCircle className="w-5 h-5 text-green-500 mt-0.5" />
                    <div className="text-gray-300">{outcome}</div>
                  </div>
                ))}
              </div>
              
              {/* ROI Summary */}
              <Card className="bg-green-900/20 border-green-500/30 mt-6">
                <CardHeader>
                  <CardTitle className="text-green-400 flex items-center gap-2">
                    <DollarSign className="h-5 w-5" />
                    Business Impact Summary
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="text-center p-4 bg-green-800/20 rounded">
                      <Clock className="h-8 w-8 text-green-400 mx-auto mb-2" />
                      <div className="text-xl font-bold text-green-400">{selectedScenario.roi.timeReduction}</div>
                      <div className="text-sm text-gray-300">Time Efficiency</div>
                    </div>
                    <div className="text-center p-4 bg-blue-800/20 rounded">
                      <DollarSign className="h-8 w-8 text-blue-400 mx-auto mb-2" />
                      <div className="text-xl font-bold text-blue-400">{selectedScenario.roi.costSavings}</div>
                      <div className="text-sm text-gray-300">Cost Reduction</div>
                    </div>
                    <div className="text-center p-4 bg-purple-800/20 rounded">
                      <Shield className="h-8 w-8 text-purple-400 mx-auto mb-2" />
                      <div className="text-xl font-bold text-purple-400">{selectedScenario.roi.riskMitigation}</div>
                      <div className="text-sm text-gray-300">Risk Mitigation</div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      {/* Feature Showcase */}
      <Card className="bg-black/40 border-slate-600/30">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Zap className="h-5 w-5 text-yellow-400" />
            Featured Capabilities - {selectedScenario.title}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {selectedScenario.features.map((feature, index) => (
              <div key={index} className="flex items-center gap-3 p-3 bg-slate-800/40 rounded">
                <Gauge className="h-5 w-5 text-blue-400" />
                <span className="text-white font-medium">{feature}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};