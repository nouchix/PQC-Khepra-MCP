
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Checkbox } from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { 
  Clock, 
  Shield, 
  Bell, 
  CheckCircle,
  AlertTriangle,
  Calendar,
  Zap
} from 'lucide-react';
import { WizardData } from '../DataSourcesWizard';

interface ScheduleOption {
  id: string;
  title: string;
  description: string;
  frequency: string;
  icon: React.ElementType;
  recommended?: boolean;
}

interface STIGRuleSet {
  id: string;
  title: string;
  description: string;
  version: string;
  applicableEnvironments: string[];
  severity: 'Critical' | 'High' | 'Medium';
  rulesCount: number;
}

interface ComplianceFramework {
  id: string;
  title: string;
  description: string;
  requirements: number;
  applicable: boolean;
}

const SCHEDULE_OPTIONS: ScheduleOption[] = [
  {
    id: 'continuous',
    title: 'Continuous Monitoring',
    description: 'Real-time compliance monitoring with immediate alerts',
    frequency: '24/7',
    icon: Zap,
    recommended: true
  },
  {
    id: 'daily',
    title: 'Daily Scans',
    description: 'Automated daily compliance assessments',
    frequency: 'Once per day',
    icon: Calendar
  },
  {
    id: 'weekly',
    title: 'Weekly Scans',
    description: 'Comprehensive weekly compliance reviews',
    frequency: 'Once per week',
    icon: Clock
  },
  {
    id: 'monthly',
    title: 'Monthly Scans',
    description: 'Monthly compliance reports and assessments',
    frequency: 'Once per month',
    icon: Calendar
  }
];

const STIG_RULE_SETS: STIGRuleSet[] = [
  {
    id: 'windows-server-2022',
    title: 'Windows Server 2022 STIG',
    description: 'Security Technical Implementation Guide for Windows Server 2022',
    version: 'V1R3',
    applicableEnvironments: ['servers-windows', 'cloud-aws', 'cloud-azure', 'cloud-gcp'],
    severity: 'Critical',
    rulesCount: 267
  },
  {
    id: 'rhel-9',
    title: 'Red Hat Enterprise Linux 9 STIG',
    description: 'STIG for RHEL 9 operating system',
    version: 'V1R1',
    applicableEnvironments: ['servers-linux', 'cloud-aws', 'cloud-azure', 'cloud-gcp'],
    severity: 'Critical',
    rulesCount: 332
  },
  {
    id: 'ubuntu-20-04',
    title: 'Ubuntu 20.04 LTS STIG',
    description: 'STIG for Ubuntu 20.04 LTS',
    version: 'V1R7',
    applicableEnvironments: ['servers-linux', 'cloud-aws', 'cloud-azure'],
    severity: 'High',
    rulesCount: 298
  },
  {
    id: 'kubernetes',
    title: 'Kubernetes STIG',
    description: 'Security requirements for Kubernetes clusters',
    version: 'V1R4',
    applicableEnvironments: ['containers-k8s'],
    severity: 'Critical',
    rulesCount: 142
  },
  {
    id: 'cisco-ios',
    title: 'Cisco IOS STIG',
    description: 'Network device security configuration',
    version: 'V2R5',
    applicableEnvironments: ['network-infrastructure'],
    severity: 'High',
    rulesCount: 89
  },
  {
    id: 'industrial-control-systems',
    title: 'Industrial Control Systems STIG',
    description: 'Security requirements for ICS/SCADA systems',
    version: 'V1R2',
    applicableEnvironments: ['industrial-plc', 'industrial-scada', 'energy-solar', 'energy-wind', 'energy-battery'],
    severity: 'Critical',
    rulesCount: 156
  }
];

const COMPLIANCE_FRAMEWORKS: ComplianceFramework[] = [
  {
    id: 'fisma',
    title: 'FISMA (Federal Information Security Management Act)',
    description: 'Federal cybersecurity framework requirements',
    requirements: 325,
    applicable: true
  },
  {
    id: 'nist-800-53',
    title: 'NIST 800-53',
    description: 'Security and Privacy Controls for Information Systems',
    requirements: 946,
    applicable: true
  },
  {
    id: 'iso-27001',
    title: 'ISO 27001',
    description: 'Information Security Management Systems',
    requirements: 114,
    applicable: true
  },
  {
    id: 'pci-dss',
    title: 'PCI DSS',
    description: 'Payment Card Industry Data Security Standard',
    requirements: 78,
    applicable: false
  }
];

interface ScanningConfigStepProps {
  data: WizardData;
  onUpdate: (updates: Partial<WizardData>) => void;
}

export const ScanningConfigStep: React.FC<ScanningConfigStepProps> = ({
  data,
  onUpdate
}) => {
  const updateScanningConfig = (field: string, value: any) => {
    onUpdate({
      scanningConfig: {
        ...data.scanningConfig,
        [field]: value
      }
    });
  };

  const toggleSTIGRuleSet = (ruleSetId: string, checked: boolean) => {
    const updatedRuleSets = checked
      ? [...data.scanningConfig.stigRuleSets, ruleSetId]
      : data.scanningConfig.stigRuleSets.filter(id => id !== ruleSetId);
    
    updateScanningConfig('stigRuleSets', updatedRuleSets);
  };

  const toggleFramework = (frameworkId: string, checked: boolean) => {
    const updatedFrameworks = checked
      ? [...data.scanningConfig.frameworks, frameworkId]
      : data.scanningConfig.frameworks.filter(id => id !== frameworkId);
    
    updateScanningConfig('frameworks', updatedFrameworks);
  };

  const getApplicableRuleSets = () => {
    return STIG_RULE_SETS.filter(ruleSet =>
      ruleSet.applicableEnvironments.some(env => data.environments.includes(env))
    );
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'bg-red-500/10 text-red-600 border-red-500/20';
      case 'High': return 'bg-orange-500/10 text-orange-600 border-orange-500/20';
      case 'Medium': return 'bg-yellow-500/10 text-yellow-600 border-yellow-500/20';
      default: return 'bg-gray-500/10 text-gray-600 border-gray-500/20';
    }
  };

  const applicableRuleSets = getApplicableRuleSets();

  return (
    <div className="space-y-6">
      <div className="text-center space-y-2">
        <h3 className="text-lg font-semibold">Configure STIG Compliance Scanning</h3>
        <p className="text-muted-foreground">
          Set up automated scanning schedules and select applicable STIG rule sets.
        </p>
      </div>

      {/* Scanning Schedule */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Clock className="h-5 w-5 text-primary" />
            <span>Scanning Schedule</span>
          </CardTitle>
          <CardDescription>
            Choose how frequently to perform STIG compliance assessments
          </CardDescription>
        </CardHeader>
        <CardContent>
          <RadioGroup
            value={data.scanningConfig.schedule}
            onValueChange={(value) => updateScanningConfig('schedule', value)}
            className="space-y-3"
          >
            {SCHEDULE_OPTIONS.map((option) => (
              <div key={option.id} className="flex items-start space-x-3">
                <RadioGroupItem value={option.id} id={option.id} className="mt-1" />
                <div className="flex-1 space-y-1">
                  <Label htmlFor={option.id} className="cursor-pointer">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <option.icon className="h-4 w-4" />
                        <span className="font-medium">{option.title}</span>
                        {option.recommended && (
                          <Badge variant="default" className="text-xs">
                            Recommended
                          </Badge>
                        )}
                      </div>
                      <Badge variant="secondary" className="text-xs">
                        {option.frequency}
                      </Badge>
                    </div>
                    <p className="text-sm text-muted-foreground mt-1">
                      {option.description}
                    </p>
                  </Label>
                </div>
              </div>
            ))}
          </RadioGroup>
        </CardContent>
      </Card>

      {/* STIG Rule Sets */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Shield className="h-5 w-5 text-primary" />
            <span>STIG Rule Sets</span>
          </CardTitle>
          <CardDescription>
            Select STIG benchmarks applicable to your infrastructure
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {applicableRuleSets.map((ruleSet) => (
              <div key={ruleSet.id} className="flex items-start space-x-3 p-3 border rounded-lg">
                <Checkbox
                  id={ruleSet.id}
                  checked={data.scanningConfig.stigRuleSets.includes(ruleSet.id)}
                  onCheckedChange={(checked) => toggleSTIGRuleSet(ruleSet.id, checked as boolean)}
                  className="mt-1"
                />
                <div className="flex-1 space-y-2">
                  <Label htmlFor={ruleSet.id} className="cursor-pointer">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className="font-medium">{ruleSet.title}</span>
                        <Badge variant="outline" className="text-xs">
                          {ruleSet.version}
                        </Badge>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Badge 
                          variant="outline"
                          className={`text-xs ${getSeverityColor(ruleSet.severity)}`}
                        >
                          {ruleSet.severity}
                        </Badge>
                        <Badge variant="secondary" className="text-xs">
                          {ruleSet.rulesCount} rules
                        </Badge>
                      </div>
                    </div>
                    <p className="text-sm text-muted-foreground">
                      {ruleSet.description}
                    </p>
                  </Label>
                </div>
              </div>
            ))}
          </div>

          {applicableRuleSets.length === 0 && (
            <div className="text-center py-8 text-muted-foreground">
              <AlertTriangle className="h-8 w-8 mx-auto mb-2" />
              <p>No STIG rule sets found for your selected environments.</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Compliance Frameworks */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <CheckCircle className="h-5 w-5 text-primary" />
            <span>Compliance Frameworks</span>
          </CardTitle>
          <CardDescription>
            Additional compliance frameworks to map STIG findings against
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {COMPLIANCE_FRAMEWORKS.map((framework) => (
              <div 
                key={framework.id} 
                className={`flex items-start space-x-3 p-3 border rounded-lg ${
                  !framework.applicable ? 'opacity-50' : ''
                }`}
              >
                <Checkbox
                  id={framework.id}
                  checked={data.scanningConfig.frameworks.includes(framework.id)}
                  onCheckedChange={(checked) => toggleFramework(framework.id, checked as boolean)}
                  disabled={!framework.applicable}
                  className="mt-1"
                />
                <div className="flex-1">
                  <Label htmlFor={framework.id} className={`cursor-pointer ${!framework.applicable ? 'cursor-not-allowed' : ''}`}>
                    <div className="flex items-center justify-between">
                      <span className="font-medium">{framework.title}</span>
                      <Badge variant="secondary" className="text-xs">
                        {framework.requirements} requirements
                      </Badge>
                    </div>
                    <p className="text-sm text-muted-foreground">
                      {framework.description}
                    </p>
                  </Label>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Notification Settings */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Bell className="h-5 w-5 text-primary" />
            <span>Notification Settings</span>
          </CardTitle>
          <CardDescription>
            Configure alerts and reporting preferences
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center space-x-2">
            <Checkbox
              id="notifications"
              checked={data.scanningConfig.notifications}
              onCheckedChange={(checked) => updateScanningConfig('notifications', checked)}
            />
            <Label htmlFor="notifications" className="cursor-pointer">
              <div>
                <span className="font-medium">Enable Real-time Notifications</span>
                <p className="text-sm text-muted-foreground">
                  Receive immediate alerts for critical STIG compliance violations and scan completion
                </p>
              </div>
            </Label>
          </div>
        </CardContent>
      </Card>

      {data.scanningConfig.stigRuleSets.length > 0 && (
        <Card className="bg-primary/5 border-primary/20">
          <CardContent className="pt-6">
            <div className="flex items-center space-x-3">
              <CheckCircle className="h-5 w-5 text-primary" />
              <div>
                <h4 className="font-medium">
                  Configuration Complete: {data.scanningConfig.stigRuleSets.length} STIG rule sets selected
                </h4>
                <p className="text-sm text-muted-foreground">
                  Scanning schedule: {data.scanningConfig.schedule} • 
                  Frameworks: {data.scanningConfig.frameworks.length} selected •
                  Notifications: {data.scanningConfig.notifications ? 'Enabled' : 'Disabled'}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};