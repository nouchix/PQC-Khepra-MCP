
import { ConsoleLayout } from '@/components/console/ConsoleLayout';
import { EnhancedSTIGConnector } from '@/components/discovery/EnhancedSTIGConnector';
import { DashboardToggle } from '@/components/DashboardToggle';
import { useOrganizationContext } from '@/components/OrganizationProvider';

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
      {currentOrganization && (
        <EnhancedSTIGConnector organizationId={currentOrganization.organization_id} />
      )}
    </ConsoleLayout>
  );
};

export default AssetScanning;