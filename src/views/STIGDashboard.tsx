
import { ConsoleLayout } from '@/components/console/ConsoleLayout';
import { MVP1Dashboard } from '@/components/compliance/MVP1Dashboard';
import { DashboardToggle } from '@/components/DashboardToggle';

const STIGDashboard = () => {
  const tabs = [
    { id: 'stig-dashboard', title: 'Dashboard', path: '/stig-dashboard', isActive: true },
    { id: 'asset-scanning', title: 'Drift Detection', path: '/asset-scanning' },
    { id: 'dod', title: 'STIG Registry', path: '/dod' },
    { id: 'compliance-reports', title: 'Baselines', path: '/compliance-reports' },
    { id: 'evidence-collection', title: 'Evidence', path: '/evidence-collection' },
    { id: 'billing', title: 'Billing', path: '/billing' },
  ];

  return (
    <ConsoleLayout 
      currentSection="stig-dashboard"
      browserNav={{
        title: 'STIG Compliance Platform - MVP 1.0 Beta',
        subtitle: 'Configuration management, AI verification, and drift detection',
        tabs,
        showAddTab: false,
        rightContent: <DashboardToggle />
      }}
    >
      <MVP1Dashboard />
    </ConsoleLayout>
  );
};

export default STIGDashboard;