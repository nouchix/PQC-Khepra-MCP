
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { 
  CheckCircle, 
  Settings, 
  Shield, 
  Clock, 
  Bell,
  Server,
  Key,
  Zap,
  AlertTriangle
} from 'lucide-react';
import { WizardData } from '../DataSourcesWizard';

interface ReviewConfirmationStepProps {
  data: WizardData;
  organizationId: string;
}

export const ReviewConfirmationStep: React.FC<ReviewConfirmationStepProps> = ({
  data,
  organizationId
}) => {
  const getEnvironmentTitle = (envId: string) => {
    const titles: Record<string, string> = {
      'cloud-aws': 'AWS Cloud Infrastructure',
      'cloud-azure': 'Microsoft Azure',
      'cloud-gcp': 'Google Cloud Platform',
      'servers-windows': 'Windows Servers',
      'servers-linux': 'Linux Servers',
      'containers-docker': 'Docker Containers',
      'containers-k8s': 'Kubernetes Clusters',
      'industrial-plc': 'PLCs and RTUs',
      'industrial-scada': 'SCADA Systems',
      'energy-solar': 'Solar Power Systems',
      'energy-wind': 'Wind Power Systems',
      'energy-battery': 'Battery Storage Systems',
      'network-infrastructure': 'Network Infrastructure'
    };
    return titles[envId] || envId;
  };

  const getConnectionMethodTitle = (methodId: string) => {
    const titles: Record<string, string> = {
      'ssh-winrm': 'SSH / WinRM',
      'api-credentials': 'API Credentials',
      'snmp': 'SNMP Monitoring',
      'industrial-protocols': 'Industrial Protocols',
      'container-agents': 'Container Agents',
      'agentless-scanning': 'Agentless Network Scanning'
    };
    return titles[methodId] || methodId;
  };

  const getSTIGRuleSetTitle = (ruleSetId: string) => {
    const titles: Record<string, string> = {
      'windows-server-2022': 'Windows Server 2022 STIG',
      'rhel-9': 'Red Hat Enterprise Linux 9 STIG',
      'ubuntu-20-04': 'Ubuntu 20.04 LTS STIG',
      'kubernetes': 'Kubernetes STIG',
      'cisco-ios': 'Cisco IOS STIG',
      'industrial-control-systems': 'Industrial Control Systems STIG'
    };
    return titles[ruleSetId] || ruleSetId;
  };

  const getFrameworkTitle = (frameworkId: string) => {
    const titles: Record<string, string> = {
      'fisma': 'FISMA',
      'nist-800-53': 'NIST 800-53',
      'iso-27001': 'ISO 27001',
      'pci-dss': 'PCI DSS'
    };
    return titles[frameworkId] || frameworkId;
  };

  const getScheduleTitle = (schedule: string) => {
    const titles: Record<string, string> = {
      'continuous': 'Continuous Monitoring (24/7)',
      'daily': 'Daily Scans',
      'weekly': 'Weekly Scans',
      'monthly': 'Monthly Scans'
    };
    return titles[schedule] || schedule;
  };

  const estimatedAssets = Object.keys(data.connectionMethods).length * 15; // Rough estimate
  const totalRules = data.scanningConfig.stigRuleSets.length * 200; // Rough estimate

  return (
    <div className="space-y-6">
      <div className="text-center space-y-2">
        <h3 className="text-lg font-semibold">Review & Deploy Configuration</h3>
        <p className="text-muted-foreground">
          Review your STIG-Connector configuration before deployment.
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="text-center">
          <CardContent className="pt-6">
            <Server className="h-8 w-8 mx-auto text-primary mb-2" />
            <div className="text-2xl font-bold">{data.environments.length}</div>
            <p className="text-sm text-muted-foreground">Environment Types</p>
          </CardContent>
        </Card>
        
        <Card className="text-center">
          <CardContent className="pt-6">
            <Shield className="h-8 w-8 mx-auto text-primary mb-2" />
            <div className="text-2xl font-bold">{data.scanningConfig.stigRuleSets.length}</div>
            <p className="text-sm text-muted-foreground">STIG Rule Sets</p>
          </CardContent>
        </Card>
        
        <Card className="text-center">
          <CardContent className="pt-6">
            <Zap className="h-8 w-8 mx-auto text-primary mb-2" />
            <div className="text-2xl font-bold">~{estimatedAssets}</div>
            <p className="text-sm text-muted-foreground">Expected Assets</p>
          </CardContent>
        </Card>
      </div>

      {/* Environment Configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Server className="h-5 w-5 text-primary" />
            <span>Environment Configuration</span>
          </CardTitle>
          <CardDescription>
            Infrastructure types and connection methods
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {data.environments.map((envType, index) => (
              <div key={envType}>
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="font-medium">{getEnvironmentTitle(envType)}</h4>
                    <p className="text-sm text-muted-foreground">
                      Connection: {getConnectionMethodTitle(data.connectionMethods[envType])}
                    </p>
                  </div>
                  <Badge variant="outline">
                    <CheckCircle className="h-3 w-3 mr-1" />
                    Configured
                  </Badge>
                </div>
                {index < data.environments.length - 1 && <Separator className="mt-4" />}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Scanning Configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Settings className="h-5 w-5 text-primary" />
            <span>Scanning Configuration</span>
          </CardTitle>
          <CardDescription>
            STIG compliance monitoring settings
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {/* Schedule */}
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Clock className="h-4 w-4 text-muted-foreground" />
                <span className="font-medium">Scanning Schedule</span>
              </div>
              <Badge variant="outline">
                {getScheduleTitle(data.scanningConfig.schedule)}
              </Badge>
            </div>

            <Separator />

            {/* STIG Rule Sets */}
            <div>
              <div className="flex items-center space-x-2 mb-3">
                <Shield className="h-4 w-4 text-muted-foreground" />
                <span className="font-medium">STIG Rule Sets ({data.scanningConfig.stigRuleSets.length})</span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {data.scanningConfig.stigRuleSets.map((ruleSetId) => (
                  <Badge key={ruleSetId} variant="secondary" className="justify-start">
                    {getSTIGRuleSetTitle(ruleSetId)}
                  </Badge>
                ))}
              </div>
            </div>

            {data.scanningConfig.frameworks.length > 0 && (
              <>
                <Separator />
                
                {/* Compliance Frameworks */}
                <div>
                  <div className="flex items-center space-x-2 mb-3">
                    <CheckCircle className="h-4 w-4 text-muted-foreground" />
                    <span className="font-medium">Compliance Frameworks ({data.scanningConfig.frameworks.length})</span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {data.scanningConfig.frameworks.map((frameworkId) => (
                      <Badge key={frameworkId} variant="outline">
                        {getFrameworkTitle(frameworkId)}
                      </Badge>
                    ))}
                  </div>
                </div>
              </>
            )}

            <Separator />

            {/* Notifications */}
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Bell className="h-4 w-4 text-muted-foreground" />
                <span className="font-medium">Real-time Notifications</span>
              </div>
              <Badge variant={data.scanningConfig.notifications ? "default" : "secondary"}>
                {data.scanningConfig.notifications ? "Enabled" : "Disabled"}
              </Badge>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Deployment Information */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Key className="h-5 w-5 text-primary" />
            <span>Deployment Information</span>
          </CardTitle>
          <CardDescription>
            What happens when you deploy this configuration
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="flex items-start space-x-3">
              <div className="bg-primary text-primary-foreground rounded-full w-6 h-6 flex items-center justify-center text-sm font-bold mt-0.5">1</div>
              <div>
                <h4 className="font-medium">STIG-Connector Initialization</h4>
                <p className="text-sm text-muted-foreground">
                  Polymorphic API connector will be configured with your connection details and credentials
                </p>
              </div>
            </div>
            
            <div className="flex items-start space-x-3">
              <div className="bg-primary text-primary-foreground rounded-full w-6 h-6 flex items-center justify-center text-sm font-bold mt-0.5">2</div>
              <div>
                <h4 className="font-medium">STIG Rules Synchronization</h4>
                <p className="text-sm text-muted-foreground">
                  Download and configure {totalRules}+ DISA STIG rules from OpenControls API
                </p>
              </div>
            </div>
            
            <div className="flex items-start space-x-3">
              <div className="bg-primary text-primary-foreground rounded-full w-6 h-6 flex items-center justify-center text-sm font-bold mt-0.5">3</div>
              <div>
                <h4 className="font-medium">Asset Discovery</h4>
                <p className="text-sm text-muted-foreground">
                  Discover and inventory infrastructure assets in configured environments
                </p>
              </div>
            </div>
            
            <div className="flex items-start space-x-3">
              <div className="bg-primary text-primary-foreground rounded-full w-6 h-6 flex items-center justify-center text-sm font-bold mt-0.5">4</div>
              <div>
                <h4 className="font-medium">Initial STIG Assessment</h4>
                <p className="text-sm text-muted-foreground">
                  Execute baseline compliance scan across all discovered assets
                </p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Security Notice */}
      <Card className="border-yellow-500/20 bg-yellow-500/5">
        <CardContent className="pt-6">
          <div className="flex items-start space-x-3">
            <AlertTriangle className="h-5 w-5 text-yellow-600 mt-0.5" />
            <div>
              <h4 className="font-medium text-yellow-800">Security & Privacy Notice</h4>
              <p className="text-sm text-yellow-700 mt-1">
                All connection credentials are encrypted at rest and in transit. The STIG-Connector uses 
                read-only access where possible and follows principle of least privilege. No sensitive 
                data leaves your organization without explicit authorization.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Ready to Deploy */}
      <Card className="bg-primary/5 border-primary/20">
        <CardContent className="pt-6">
          <div className="flex items-center space-x-3">
            <CheckCircle className="h-5 w-5 text-primary" />
            <div>
              <h4 className="font-medium">Ready to Deploy</h4>
              <p className="text-sm text-muted-foreground">
                Configuration validated. Click "Deploy" to initialize the STIG-Connector 
                and begin automated compliance monitoring for organization: {organizationId}
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};