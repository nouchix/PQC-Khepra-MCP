
import { ConsoleLayout } from '@/components/console/ConsoleLayout';
import { EnhancedSTIGConnector } from '@/components/discovery/EnhancedSTIGConnector';
import { DashboardToggle } from '@/components/DashboardToggle';
import { useOrganizationContext } from '@/components/OrganizationProvider';
import { Card, CardContent } from '@/components/ui/card';
import { Building2 } from 'lucide-react';

const AssetScanning = () => {
  const { currentOrganization } = useOrganizationContext();

  const tabs = [
    { id: 'stig-dashboard', title: 'STIG Dashboard', path: '/stig-dashboard' },
    { id: 'asset-scanning', title: 'Asset Scanning', path: '/asset-scanning', isActive: true },
    { id: 'compliance-reports', title: 'Reports', path: '/compliance-reports' },
    { id: 'evidence-collection', title: 'Evidence', path: '/evidence-collection' },
    { id: 'billing', title: 'Billing', path: '/billing' },
  ];

  return (
    <ConsoleLayout 
      currentSection="asset-scanning"
      browserNav={{
        title: 'TRL10 STIG Asset Scanner & Service Mapper',
        subtitle: 'Real-time network discovery with CLI monitoring and service mapping',
        tabs,
        showAddTab: false,
        rightContent: <DashboardToggle />
      }}
    >
      {currentOrganization ? (
        <EnhancedSTIGConnector organizationId={currentOrganization.id} />
      ) : (
        <div className="flex items-center justify-center h-64 p-6">
          <Card className="max-w-sm w-full">
            <CardContent className="flex flex-col items-center text-center gap-4 p-8">
              <Building2 className="h-10 w-10 text-muted-foreground" />
              <div>
                <p className="font-semibold text-foreground">No Organization Found</p>
                <p className="text-sm text-muted-foreground mt-1">
                  You are not a member of any organization yet. Contact your administrator or create one to begin asset scanning.
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </ConsoleLayout>
  );
};

export default AssetScanning;