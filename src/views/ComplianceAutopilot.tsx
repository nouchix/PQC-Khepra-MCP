
import { ConsoleLayout } from '@/components/console/ConsoleLayout';
import { CMMCDashboard } from '@/components/compliance/CMMCDashboard';
import { CMMCSTIGBridge } from '@/components/compliance/CMMCSTIGBridge';
import { DashboardToggle } from '@/components/DashboardToggle';
import { useOrganizationContext } from '@/components/OrganizationProvider';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

const ComplianceAutopilot = () => {
  const { currentOrganization } = useOrganizationContext();

  const tabs = [
    { id: 'stig-dashboard', title: 'STIG Dashboard', path: '/stig-dashboard' },
    { id: 'compliance-autopilot', title: 'Compliance Autopilot', path: '/compliance-autopilot', isActive: true },
    { id: 'compliance-reports', title: 'Reports', path: '/compliance-reports' },
    { id: 'evidence-collection', title: 'Evidence', path: '/evidence-collection' },
    { id: 'billing', title: 'Billing', path: '/billing' },
  ];

  return (
    <ConsoleLayout 
      currentSection="compliance-autopilot"
      browserNav={{
        title: 'CMMC Compliance Autopilot',
        subtitle: 'Automated CMMC-to-STIG bridge with evidence collection',
        tabs,
        showAddTab: false,
        rightContent: <DashboardToggle />
      }}
    >
      {currentOrganization && (
        <Tabs defaultValue="cmmc-dashboard" className="space-y-4">
          <TabsList>
            <TabsTrigger value="cmmc-dashboard">CMMC Dashboard</TabsTrigger>
            <TabsTrigger value="stig-bridge">STIG Bridge Autopilot</TabsTrigger>
          </TabsList>
          
          <TabsContent value="cmmc-dashboard">
            <CMMCDashboard organizationId={currentOrganization.id} />
          </TabsContent>
          
          <TabsContent value="stig-bridge">
            <CMMCSTIGBridge organizationId={currentOrganization.id} />
          </TabsContent>
        </Tabs>
      )}
    </ConsoleLayout>
  );
};

export default ComplianceAutopilot;