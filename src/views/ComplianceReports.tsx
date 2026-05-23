
import { ConsoleLayout } from '@/components/console/ConsoleLayout';
import { STIGComplianceReports } from '@/components/compliance/STIGComplianceReports';
import { DashboardToggle } from '@/components/DashboardToggle';
import { useOrganizationContext } from '@/components/OrganizationProvider';
import { Card, CardContent } from '@/components/ui/card';
import { Building2 } from 'lucide-react';

const ComplianceReports = () => {
  const { currentOrganization } = useOrganizationContext();

  const tabs = [
    { id: 'stig-dashboard', title: 'STIG Dashboard', path: '/stig-dashboard' },
    { id: 'asset-scanning', title: 'Asset Scanning', path: '/asset-scanning' },
    { id: 'compliance-reports', title: 'Reports', path: '/compliance-reports', isActive: true },
    { id: 'evidence-collection', title: 'Evidence', path: '/evidence-collection' },
    { id: 'billing', title: 'Billing', path: '/billing' },
  ];

  return (
    <ConsoleLayout 
      currentSection="compliance-reports"
      browserNav={{
        title: 'STIG Compliance Reports',
        subtitle: 'Generate and view CMMC-to-STIG compliance reports',
        tabs,
        showAddTab: false,
        rightContent: <DashboardToggle />
      }}
    >
      {currentOrganization ? (
        <STIGComplianceReports organizationId={currentOrganization.id} />
      ) : (
        <div className="flex items-center justify-center h-64 p-6">
          <Card className="max-w-sm w-full">
            <CardContent className="flex flex-col items-center text-center gap-4 p-8">
              <Building2 className="h-10 w-10 text-muted-foreground" />
              <div>
                <p className="font-semibold text-foreground">No Organization Found</p>
                <p className="text-sm text-muted-foreground mt-1">
                  You are not a member of any organization yet. Contact your administrator to gain access to compliance reports.
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </ConsoleLayout>
  );
};

export default ComplianceReports;