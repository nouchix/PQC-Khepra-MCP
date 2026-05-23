import { useState } from 'react';
import { ConsoleLayout } from '@/components/console/ConsoleLayout';
import { DashboardToggle } from '@/components/DashboardToggle';
import { TrustScoreDashboard } from '@/components/deployment/TrustScoreDashboard';
import { RiskBasedAutomationEngine } from '@/components/deployment/RiskBasedAutomationEngine';
import { CustomerConfidenceJourney } from '@/components/deployment/CustomerConfidenceJourney';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { useUserProfile } from '@/hooks/useUserProfile';
import { useDeploymentProfiles } from '@/hooks/useDeploymentProfiles';
import {
  Shield,
  Settings,
  TrendingUp,
  Users,
  AlertTriangle,
  Loader2
} from 'lucide-react';
import { IndustryType } from '@/types/deployment';

const DeploymentManagementHome = () => {
  const { profile } = useUserProfile();
  const [selectedOrganization] = useState('org-1'); // Mock organization ID

  const {
    deploymentSettings,
    trustMetrics,
    loading,
    upgradeAutomationLevel,
    switchDeploymentProfile
  } = useDeploymentProfiles(selectedOrganization);

  // Awaiting real integration with remediation engine
  const pendingActions: any[] = [];

  const tabs = [
    { id: 'deployment', title: 'Deployment Management', path: '/deployment', isActive: true },
    { id: 'infrastructure', title: 'Infrastructure', path: '/infrastructure' },
    { id: 'security', title: 'Security', path: '/security' },
    { id: 'monitoring', title: 'Monitoring', path: '/monitoring' },
    { id: 'compliance', title: 'Compliance', path: '/compliance-automation' },
  ];

  const handleApproveAction = (actionId: string) => {
    console.log('Approving action:', actionId);
    // Implementation for approving remediation action
  };

  const handleDenyAction = (actionId: string) => {
    console.log('Denying action:', actionId);
    // Implementation for denying remediation action
  };

  const handleExecuteAction = (actionId: string) => {
    console.log('Executing action:', actionId);
    // Implementation for executing remediation action
  };

  const handleAdvanceStage = () => {
    console.log('Advancing deployment stage');
    // Implementation for advancing confidence journey stage
  };

  const handleCustomizeJourney = () => {
    console.log('Customizing deployment journey');
    // Implementation for customizing deployment journey
  };

  if (loading) {
    return (
      <ConsoleLayout
        currentSection="deployment"
        browserNav={{
          title: 'Deployment Management',
          subtitle: 'Customer deployment profiles and trust-based automation',
          tabs,
          showAddTab: false,
          rightContent: <DashboardToggle />
        }}
      >
        <div className="flex items-center justify-center min-h-96">
          <div className="flex items-center space-x-2">
            <Loader2 className="h-6 w-6 animate-spin" />
            <span>Loading deployment settings...</span>
          </div>
        </div>
      </ConsoleLayout>
    );
  }

  if (!deploymentSettings || !trustMetrics) {
    return (
      <ConsoleLayout
        currentSection="deployment"
        browserNav={{
          title: 'Deployment Management',
          subtitle: 'Customer deployment profiles and trust-based automation',
          tabs,
          showAddTab: false,
          rightContent: <DashboardToggle />
        }}
      >
        <Card>
          <CardContent className="flex items-center justify-center p-8">
            <div className="text-center space-y-4">
              <AlertTriangle className="h-12 w-12 text-warning mx-auto" />
              <div>
                <h3 className="text-lg font-semibold">Deployment Settings Not Found</h3>
                <p className="text-muted-foreground">
                  Unable to load deployment configuration for this organization.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </ConsoleLayout>
    );
  }

  return (
    <ConsoleLayout
      currentSection="deployment"
      browserNav={{
        title: 'Deployment Management',
        subtitle: 'Customer deployment profiles and trust-based automation',
        tabs,
        showAddTab: false,
        rightContent: <DashboardToggle />
      }}
    >
      <div className="space-y-6">
        <Tabs defaultValue="overview" className="w-full">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="overview" className="flex items-center space-x-2">
              <Shield className="h-4 w-4" />
              <span>Trust Overview</span>
            </TabsTrigger>
            <TabsTrigger value="automation" className="flex items-center space-x-2">
              <Settings className="h-4 w-4" />
              <span>Risk Automation</span>
            </TabsTrigger>
            <TabsTrigger value="journey" className="flex items-center space-x-2">
              <TrendingUp className="h-4 w-4" />
              <span>Confidence Journey</span>
            </TabsTrigger>
            <TabsTrigger value="customers" className="flex items-center space-x-2">
              <Users className="h-4 w-4" />
              <span>Customer Profiles</span>
            </TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-6 mt-6">
            <TrustScoreDashboard
              organizationId={selectedOrganization}
              deploymentProfile={deploymentSettings.activeProfile}
              trustMetrics={trustMetrics}
              onUpgradeAutomation={upgradeAutomationLevel}
              onViewDetails={() => console.log('View detailed analytics')}
            />
          </TabsContent>

          <TabsContent value="automation" className="space-y-6 mt-6">
            <RiskBasedAutomationEngine
              organizationId={selectedOrganization}
              deploymentProfile={deploymentSettings.activeProfile}
              currentTrustScore={trustMetrics.currentScore}
              pendingActions={pendingActions}
              onApproveAction={handleApproveAction}
              onDenyAction={handleDenyAction}
              onExecuteAction={handleExecuteAction}
            />
          </TabsContent>

          <TabsContent value="journey" className="space-y-6 mt-6">
            <CustomerConfidenceJourney
              organizationId={selectedOrganization}
              industry={deploymentSettings.activeProfile.industry}
              currentTrustScore={trustMetrics.currentScore}
              successfulActions={trustMetrics.successfulActions}
              daysInCurrentStage={0} // Awaiting real journey tracking
              onAdvanceStage={handleAdvanceStage}
              onCustomizeJourney={handleCustomizeJourney}
            />
          </TabsContent>

          <TabsContent value="customers" className="space-y-6 mt-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Users className="h-5 w-5" />
                  <span>Industry-Specific Deployment Profiles</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {(['banking', 'enterprise', 'smb', 'government', 'healthcare'] as IndustryType[]).map((industry) => (
                    <Card
                      key={industry}
                      className={`cursor-pointer transition-all hover:shadow-md ${deploymentSettings.activeProfile.industry === industry
                          ? 'border-primary bg-primary/5'
                          : ''
                        }`}
                      onClick={() => switchDeploymentProfile(industry)}
                    >
                      <CardContent className="p-4">
                        <div className="text-center space-y-2">
                          <h4 className="font-semibold capitalize">{industry}</h4>
                          <p className="text-sm text-muted-foreground">
                            {industry === 'banking' && 'Ultra-conservative with comprehensive monitoring'}
                            {industry === 'enterprise' && 'Balanced approach with graduated automation'}
                            {industry === 'smb' && 'High automation with basic oversight'}
                            {industry === 'government' && 'Maximum security with audit trails'}
                            {industry === 'healthcare' && 'HIPAA-compliant with patient data focus'}
                          </p>
                          {deploymentSettings.activeProfile.industry === industry && (
                            <div className="text-xs text-primary font-medium">Active Profile</div>
                          )}
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </ConsoleLayout>
  );
};

export default DeploymentManagementHome;