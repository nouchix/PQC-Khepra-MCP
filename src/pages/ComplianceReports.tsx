
import { ConsoleLayout } from '@/components/console/ConsoleLayout';
import { STIGComplianceReports } from '@/components/compliance/STIGComplianceReports';
import { DashboardToggle } from '@/components/DashboardToggle';
import { useOrganizationContext } from '@/components/OrganizationProvider';

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
      {currentOrganization && (
        <STIGComplianceReports organizationId={currentOrganization.organization_id} />
      )}
    </ConsoleLayout>
  );
};

export default ComplianceReports;