import { useState } from 'react';
import { PageLayout } from '@/components/PageLayout';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { IndustryIntegrationHub } from '@/components/integrations/IndustryIntegrationHub';
import { IntegrationHub } from '@/components/IntegrationHub';
import { IntegrationMarketplace } from '@/components/marketplace/IntegrationMarketplace';
import { MondayIntegrationCard } from '@/components/integrations/MondayIntegrationCard';
import { MondaySyncSettings } from '@/components/integrations/MondaySyncSettings';
import { KhepraVPSIntegration } from '@/components/khepra/KhepraVPSIntegration';
import { useIndustryIntegrations } from '@/hooks/useIndustryIntegrations';
import { useIntegrations } from '@/hooks/useIntegrations';
import { useToast } from '@/hooks/use-toast';
import { useOrganizationContext } from '@/components/OrganizationProvider';
import { PolymorphicIngestionEngine } from '@/components/discovery/PolymorphicIngestionEngine';
import {
  Plug,
  TrendingUp,
  AlertCircle,
  CheckCircle,
  Activity,
  Shield,
  Settings,
  Plus,
  ExternalLink,
  Cloud,
  Zap
} from 'lucide-react';

const IntegrationStatusCard = ({ title, value, icon: Icon, status = 'normal', description }: any) => (
  <Card>
    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
      <CardTitle className="text-sm font-medium">{title}</CardTitle>
      <Icon className={`h-4 w-4 ${status === 'success' ? 'text-green-500' : status === 'warning' ? 'text-yellow-500' : status === 'error' ? 'text-red-500' : 'text-muted-foreground'}`} />
    </CardHeader>
    <CardContent>
      <div className="text-2xl font-bold">{value}</div>
      {description && <p className="text-xs text-muted-foreground">{description}</p>}
    </CardContent>
  </Card>
);

const IntegrationHealthDashboard = () => {
  const { userIntegrations } = useIndustryIntegrations();
  const { integrations } = useIntegrations();

  const totalIntegrations = userIntegrations.length + integrations.length;
  const activeIntegrations = userIntegrations.filter(i => i.status === 'connected').length +
    integrations.filter(i => i.status === 'CONNECTED').length;
  const failedIntegrations = userIntegrations.filter(i => i.status === 'error').length +
    integrations.filter(i => i.status === 'ERROR').length;
  const healthScore = totalIntegrations > 0 ? Math.round((activeIntegrations / totalIntegrations) * 100) : 0;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <IntegrationStatusCard
          title="Total Integrations"
          value={totalIntegrations}
          icon={Plug}
          description="Connected security tools"
        />
        <IntegrationStatusCard
          title="Active Connections"
          value={activeIntegrations}
          icon={CheckCircle}
          status="success"
          description="Successfully connected"
        />
        <IntegrationStatusCard
          title="Integration Health"
          value={`${healthScore}%`}
          icon={TrendingUp}
          status={healthScore > 90 ? 'success' : healthScore > 70 ? 'warning' : 'error'}
          description="Overall system health"
        />
        <IntegrationStatusCard
          title="Issues Detected"
          value={failedIntegrations}
          icon={AlertCircle}
          status={failedIntegrations > 0 ? 'error' : 'success'}
          description="Connections with problems"
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5" />
            Integration Health Score
          </CardTitle>
          <CardDescription>
            Overall health and performance of your security integrations
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Health Score</span>
              <span className="text-sm text-muted-foreground">{healthScore}%</span>
            </div>
            <Progress value={healthScore} className="h-2" />
            <div className="flex justify-between text-xs text-muted-foreground">
              <span>Critical</span>
              <span>Good</span>
              <span>Excellent</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

const QuickSetupCards = ({ setActiveTab }: { setActiveTab: (tab: string) => void }) => {
  const { toast } = useToast();

  const popularIntegrations = [
    { name: 'Splunk SIEM', icon: '🔍', category: 'SIEM', status: 'ready', type: 'SIEM' },
    { name: 'CrowdStrike Falcon', icon: '🛡️', category: 'EDR', status: 'ready', type: 'ENDPOINT' },
    { name: 'Microsoft Sentinel', icon: '☁️', category: 'Cloud SIEM', status: 'ready', type: 'CLOUD' },
    { name: 'Palo Alto Networks', icon: '🔥', category: 'FIREWALL', status: 'ready', type: 'FIREWALL' }
  ];

  const handleQuickSetup = (integration: typeof popularIntegrations[0]) => {
    setActiveTab('active');
    setTimeout(() => {
      toast({
        title: "Quick Setup",
        description: `Setting up ${integration.name} integration...`,
      });
    }, 100);
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      {popularIntegrations.map((integration, index) => (
        <Card key={index} className="cursor-pointer hover:shadow-md transition-shadow">
          <CardHeader className="pb-4">
            <div className="flex items-center justify-between">
              <span className="text-2xl">{integration.icon}</span>
              <Badge variant="secondary">{integration.category}</Badge>
            </div>
            <CardTitle className="text-sm">{integration.name}</CardTitle>
          </CardHeader>
          <CardContent>
            <Button
              size="sm"
              className="w-full"
              onClick={() => handleQuickSetup(integration)}
            >
              <Plus className="h-4 w-4 mr-2" />
              Quick Setup
            </Button>
          </CardContent>
        </Card>
      ))}
    </div>
  );
};

const IntegrationRecommendations = ({ setActiveTab }: { setActiveTab: (tab: string) => void }) => {
  const { toast } = useToast();

  const recommendations = [
    {
      title: 'Enable SIEM Integration',
      description: 'Connect your SIEM platform for centralized security monitoring',
      priority: 'high',
      action: 'Configure Now',
      actionType: 'configure'
    },
    {
      title: 'Set Up EDR Connection',
      description: 'Endpoint detection and response for comprehensive threat visibility',
      priority: 'medium',
      action: 'Learn More',
      actionType: 'learn'
    },
    {
      title: 'Cloud Security Integration',
      description: 'Monitor your cloud infrastructure security posture',
      priority: 'medium',
      action: 'Explore Options',
      actionType: 'explore'
    }
  ];

  const handleRecommendationAction = (rec: typeof recommendations[0]) => {
    switch (rec.actionType) {
      case 'configure':
        setActiveTab('active');
        toast({
          title: "Opening Integration Setup",
          description: "Redirecting to integration configuration...",
        });
        break;
      case 'learn':
        globalThis.open('/integration-guide/custom-api', '_blank');
        break;
      case 'explore':
        setActiveTab('marketplace');
        toast({
          title: "Opening Marketplace",
          description: "Exploring available integrations...",
        });
        break;
    }
  };

  return (
    <div className="space-y-4">
      {recommendations.map((rec, index) => (
        <Card key={index}>
          <CardContent className="pt-6">
            <div className="flex items-start justify-between">
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <h4 className="font-medium">{rec.title}</h4>
                  <Badge variant={rec.priority === 'high' ? 'destructive' : 'secondary'}>
                    {rec.priority}
                  </Badge>
                </div>
                <p className="text-sm text-muted-foreground">{rec.description}</p>
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleRecommendationAction(rec)}
              >
                {rec.action}
                <ExternalLink className="h-4 w-4 ml-2" />
              </Button>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
};

export default function IntegrationsPage() {
  const [activeTab, setActiveTab] = useState('overview');
  const [showMondaySettings, setShowMondaySettings] = useState(false);
  const { toast } = useToast();
  const { userIntegrations } = useIndustryIntegrations();
  const { currentOrganization } = useOrganizationContext();

  const handleSettings = () => {
    toast({
      title: "Integration Settings",
      description: "Opening integration configuration panel...",
    });
  };

  const handleAddIntegration = () => {
    setActiveTab('active');
    toast({
      title: "Add Integration",
      description: "Switching to Active Integrations tab to add new integration...",
    });
  };

  return (
    <PageLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-foreground">Strategic Integration Hub</h1>
            <p className="text-muted-foreground">Connect Sentinel Intelligence with diverse environments via standard or polymorphic connectors</p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" onClick={handleSettings}>
              <Settings className="h-4 w-4 mr-2" />
              Settings
            </Button>
            <Button onClick={handleAddIntegration}>
              <Plus className="h-4 w-4 mr-2" />
              Add Integration
            </Button>
          </div>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid w-full grid-cols-7 overflow-x-auto h-auto p-1 bg-slate-100/50">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="polymorphic" className="text-indigo-600 font-bold flex items-center gap-2">
              <Zap className="w-3 h-3" />
              Polymorphic Connector
            </TabsTrigger>
            <TabsTrigger value="active">Active Integrations</TabsTrigger>
            <TabsTrigger value="marketplace">Marketplace</TabsTrigger>
            <TabsTrigger value="industry">Industry Hub</TabsTrigger>
            <TabsTrigger value="analytics">Analytics</TabsTrigger>
            <TabsTrigger value="recommendations">Recommendations</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-6">
            <IntegrationHealthDashboard />
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2 space-y-6">
                <Card>
                  <CardHeader>
                    <CardTitle>Quick Setup</CardTitle>
                    <CardDescription>Get started with popular security integrations</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <QuickSetupCards setActiveTab={setActiveTab} />
                  </CardContent>
                </Card>
              </div>
              <Card>
                <CardHeader>
                  <CardTitle>Recommended Actions</CardTitle>
                  <CardDescription>Optimize your security integration setup</CardDescription>
                </CardHeader>
                <CardContent>
                  <IntegrationRecommendations setActiveTab={setActiveTab} />
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="polymorphic">
            {currentOrganization ? (
              <PolymorphicIngestionEngine organizationId={currentOrganization.organization_id} />
            ) : (
              <Card className="p-12 text-center">
                <Cloud className="w-12 h-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-bold">Organization Context Missing</h3>
                <p className="text-slate-500">Please select an organization to use the Polymorphic Engine.</p>
              </Card>
            )}
          </TabsContent>

          <TabsContent value="active">
            <div className="space-y-8">
              <div className="space-y-4">
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <Shield className="h-5 w-5 text-primary" />
                  Private Infrastructure (Hybrid Model)
                </h3>
                <KhepraVPSIntegration {...({} as any)} />
              </div>
              <div className="space-y-4">
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <Plug className="h-5 w-5 text-primary" />
                  SaaS & Enterprise Connectors
                </h3>
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <MondayIntegrationCard onConfigure={() => setShowMondaySettings(true)} />
                </div>
              </div>
              <IntegrationHub />
            </div>
          </TabsContent>

          <TabsContent value="marketplace">
            <IntegrationMarketplace />
          </TabsContent>

          <TabsContent value="industry">
            <IndustryIntegrationHub />
          </TabsContent>

          <TabsContent value="analytics" className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <Card>
                <CardHeader><CardTitle className="text-sm">Data Ingestion Rate</CardTitle></CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{userIntegrations.length > 0 ? `${(userIntegrations.length * 0.8).toFixed(1)}k/min` : '0/min'}</div>
                  <p className="text-xs text-muted-foreground">Events per minute</p>
                </CardContent>
              </Card>
              <Card>
                <CardHeader><CardTitle className="text-sm">Average Latency</CardTitle></CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{userIntegrations.length > 0 ? '85ms' : 'N/A'}</div>
                  <p className="text-xs text-muted-foreground">Response time</p>
                </CardContent>
              </Card>
              <Card>
                <CardHeader><CardTitle className="text-sm">Uptime</CardTitle></CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">99.98%</div>
                  <p className="text-xs text-muted-foreground">Platform reliability</p>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="recommendations">
            <IntegrationRecommendations setActiveTab={setActiveTab} />
          </TabsContent>
        </Tabs>

        <MondaySyncSettings open={showMondaySettings} onOpenChange={setShowMondaySettings} />
      </div>
    </PageLayout>
  );
}