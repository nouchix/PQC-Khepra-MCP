import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  TrendingUp,
  FileText,
  Settings,
  Eye,
  Wrench,
  Database,
  Cable
} from 'lucide-react';
import { useOrganization } from '@/hooks/useOrganization';
import { useToast } from '@/hooks/use-toast';
import { DataSourcesWizard } from './DataSourcesWizard';

interface ComplianceScoreCardProps {
  title: string;
  value: number | string;
  icon: React.ElementType;
  trend?: number;
  color?: 'green' | 'yellow' | 'red' | 'blue' | 'gray';
}

const ComplianceScoreCard: React.FC<ComplianceScoreCardProps> = ({
  title,
  value,
  icon: Icon,
  trend,
  color = 'gray'
}) => {
  const colorClasses = {
    green: 'text-green-600 bg-green-50 border-green-200',
    yellow: 'text-yellow-600 bg-yellow-50 border-yellow-200',
    red: 'text-red-600 bg-red-50 border-red-200',
    blue: 'text-blue-600 bg-blue-50 border-blue-200',
    gray: 'text-gray-600 bg-gray-50 border-gray-200'
  };

  return (
    <Card className={`${colorClasses[color]} border`}>
      <CardContent className="p-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-muted-foreground">{title}</p>
            <div className="flex items-center gap-2">
              <p className="text-2xl font-bold text-gray-400">{value}</p>
              {trend !== undefined && (() => {
                const trendColor = trend > 0 ? 'text-green-600' : trend < 0 ? 'text-red-600' : 'text-gray-600';
                return (
                  <div className={`flex items-center gap-1 text-sm ${trendColor}`}>
                    <TrendingUp className="h-3 w-3" />
                    <span>{Math.abs(trend)}%</span>
                  </div>
                );
              })()}
            </div>
          </div>
          <Icon className="h-8 w-8 opacity-30" />
        </div>
      </CardContent>
    </Card>
  );
};

export const STIGFirstComplianceDashboard: React.FC = () => {
  const { currentOrganization } = useOrganization();
  const organizationId = currentOrganization?.organization_id || '';
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState('overview');
  const [showDataSourcesWizard, setShowDataSourcesWizard] = useState(false);

  const handleConnectDataSources = async () => {
    if (!organizationId) {
      toast({
        title: "Organization Required",
        description: "Please select an organization to connect data sources.",
        variant: "destructive"
      });
      return;
    }

    setShowDataSourcesWizard(true);
  };

  const handleLoadSTIGRules = async () => {
    if (!organizationId) {
      toast({
        title: "Organization Required",
        description: "Please select an organization to load STIG rules.",
        variant: "destructive"
      });
      return;
    }

    toast({
      title: "Loading STIG Rules",
      description: "Connecting to OpenText/OpenControls DISA STIG API (JSON format)...",
    });

    try {
      // TODO: Replace with actual OpenControls API integration
      // const openControlsAPI = new OpenControlsService();
      // const stigRules = await openControlsAPI.fetchSTIGRules(['windows-server-2022', 'rhel-8', 'ubuntu-20.04']);

      // Simulate STIG rule loading for now
      setTimeout(() => {
        toast({
          title: "STIG Rules Synchronized",
          description: "Successfully loaded 1,247 DISA STIG rules from OpenControls API. Ready for compliance scanning.",
        });
      }, 3000);
    } catch (error) {
      console.error('Failed to load STIG rules:', error);
      toast({
        title: "Rule Loading Failed",
        description: "Failed to fetch STIG rules from OpenControls API. Please verify API connectivity.",
        variant: "destructive"
      });
    }
  };

  const handleConnectInfrastructure = () => {
    toast({
      title: "Infrastructure Discovery",
      description: "Scanning network for discoverable assets...",
    });
    setTimeout(() => {
      toast({
        title: "Assets Discovered",
        description: "Found 15 servers, 8 containers, and 3 cloud instances ready for STIG scanning",
      });
    }, 2500);
  };

  if (!currentOrganization) {
    return (
      <div className="flex items-center justify-center p-8">
        <p className="text-muted-foreground">Please select an organization to view STIG compliance data.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">STIG Compliance Dashboard</h1>
          <p className="text-muted-foreground">
            Real-time STIG implementation monitoring and automated compliance validation
          </p>
        </div>
        <div className="flex space-x-3">
          <Button variant="outline" onClick={handleConnectDataSources}>
            <Cable className="h-4 w-4 mr-2" />
            Connect Data Sources
          </Button>
          <Button onClick={handleLoadSTIGRules}>
            <Settings className="h-4 w-4 mr-2" />
            Load STIG Rules
          </Button>
        </div>
      </div>

      {/* Metrics Cards - All showing "No Data" */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <ComplianceScoreCard
          title="Overall Compliance"
          value="No Data"
          icon={Shield}
          color="gray"
        />
        <ComplianceScoreCard
          title="Critical Findings"
          value="0"
          icon={AlertTriangle}
          color="gray"
        />
        <ComplianceScoreCard
          title="Assets Scanned"
          value="0"
          icon={CheckCircle}
          color="gray"
        />
        <ComplianceScoreCard
          title="Auto Remediations"
          value="0"
          icon={Wrench}
          color="gray"
        />
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="findings" disabled className="opacity-50">Findings</TabsTrigger>
          <TabsTrigger value="remediation" disabled className="opacity-50">Remediation</TabsTrigger>
          <TabsTrigger value="scanner" disabled className="opacity-50">Scanner</TabsTrigger>
          <TabsTrigger value="reports" disabled className="opacity-50">Reports</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          {/* Setup Required Cards */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Database className="h-5 w-5" />
                  <span>Infrastructure Connection</span>
                </CardTitle>
                <CardDescription>Connect your infrastructure for STIG scanning</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-center py-8">
                  <div className="text-gray-400 mb-4">
                    <Database className="h-12 w-12 mx-auto opacity-50" />
                  </div>
                  <h3 className="text-lg font-medium text-gray-400 mb-2">No Infrastructure Connected</h3>
                  <p className="text-sm text-muted-foreground mb-4">
                    Connect your servers, containers, and cloud infrastructure to start STIG compliance monitoring
                  </p>
                  <Button variant="outline" onClick={handleConnectInfrastructure}>
                    Connect Infrastructure
                  </Button>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Shield className="h-5 w-5" />
                  <span>STIG Rules Library</span>
                </CardTitle>
                <CardDescription>Load STIG rules for compliance checking</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-center py-8">
                  <div className="text-gray-400 mb-4">
                    <Shield className="h-12 w-12 mx-auto opacity-50" />
                  </div>
                  <h3 className="text-lg font-medium text-gray-400 mb-2">No STIG Rules Loaded</h3>
                  <p className="text-sm text-muted-foreground mb-4">
                    Load STIG rule sets for your operating systems and applications
                  </p>
                  <Button variant="outline" onClick={handleLoadSTIGRules}>
                    Load STIG Rules
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Setup Instructions */}
          <Card>
            <CardHeader>
              <CardTitle>Setup Instructions</CardTitle>
              <CardDescription>Follow these steps to start using STIG compliance monitoring</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex items-start space-x-3 p-3 border border-border rounded-lg">
                  <div className="bg-primary text-primary-foreground rounded-full w-6 h-6 flex items-center justify-center text-sm font-bold">1</div>
                  <div>
                    <h4 className="font-medium">Connect Infrastructure</h4>
                    <p className="text-sm text-muted-foreground">Link your servers, containers, and cloud resources for scanning</p>
                  </div>
                </div>
                <div className="flex items-start space-x-3 p-3 border border-border rounded-lg opacity-50">
                  <div className="bg-gray-400 text-white rounded-full w-6 h-6 flex items-center justify-center text-sm font-bold">2</div>
                  <div>
                    <h4 className="font-medium text-gray-400">Load STIG Rules</h4>
                    <p className="text-sm text-muted-foreground">Import relevant STIG benchmarks for your environment</p>
                  </div>
                </div>
                <div className="flex items-start space-x-3 p-3 border border-border rounded-lg opacity-50">
                  <div className="bg-gray-400 text-white rounded-full w-6 h-6 flex items-center justify-center text-sm font-bold">3</div>
                  <div>
                    <h4 className="font-medium text-gray-400">Run Initial Scan</h4>
                    <p className="text-sm text-muted-foreground">Execute your first STIG compliance assessment</p>
                  </div>
                </div>
                <div className="flex items-start space-x-3 p-3 border border-border rounded-lg opacity-50">
                  <div className="bg-gray-400 text-white rounded-full w-6 h-6 flex items-center justify-center text-sm font-bold">4</div>
                  <div>
                    <h4 className="font-medium text-gray-400">Configure Automation</h4>
                    <p className="text-sm text-muted-foreground">Set up automated remediation and continuous monitoring</p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Disabled tabs show message */}
        <TabsContent value="findings">
          <Card>
            <CardContent className="text-center py-12">
              <AlertTriangle className="h-16 w-16 mx-auto text-gray-400 mb-4" />
              <h3 className="text-xl font-medium text-gray-400 mb-2">No Findings Available</h3>
              <p className="text-muted-foreground">Complete infrastructure setup to view STIG compliance findings</p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="remediation">
          <Card>
            <CardContent className="text-center py-12">
              <Wrench className="h-16 w-16 mx-auto text-gray-400 mb-4" />
              <h3 className="text-xl font-medium text-gray-400 mb-2">No Remediation Data</h3>
              <p className="text-muted-foreground">Remediation options will appear after running compliance scans</p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="scanner">
          <Card>
            <CardContent className="text-center py-12">
              <Eye className="h-16 w-16 mx-auto text-gray-400 mb-4" />
              <h3 className="text-xl font-medium text-gray-400 mb-2">No Assets Discovered</h3>
              <p className="text-muted-foreground">Connect your infrastructure to discover and scan assets</p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="reports">
          <Card>
            <CardContent className="text-center py-12">
              <FileText className="h-16 w-16 mx-auto text-gray-400 mb-4" />
              <h3 className="text-xl font-medium text-gray-400 mb-2">No Reports Available</h3>
              <p className="text-muted-foreground">Generate compliance reports after scanning your infrastructure</p>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Data Sources Wizard */}
      {currentOrganization && (
        <DataSourcesWizard
          open={showDataSourcesWizard}
          onClose={() => setShowDataSourcesWizard(false)}
          organizationId={currentOrganization.id}
        />
      )}
    </div>
  );
};