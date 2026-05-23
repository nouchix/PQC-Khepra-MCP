
import { ConsoleLayout } from '@/components/console/ConsoleLayout';
import { DashboardToggle } from '@/components/DashboardToggle';
import DeploymentOrchestrationDashboard from './DeploymentOrchestrationDashboard';
import { useUserProfile } from '@/hooks/useUserProfile';

const DeploymentOrchestrationHome = () => {
  const { profile } = useUserProfile();

  const tabs = [
    { id: 'dod', title: 'Deployment Orchestration', path: '/dod', isActive: true },
    { id: 'infrastructure', title: 'Infrastructure', path: '/infrastructure' },
    { id: 'security', title: 'Security', path: '/security' },
    { id: 'monitoring', title: 'Monitoring', path: '/monitoring' },
    { id: 'compliance', title: 'Compliance', path: '/compliance-automation' },
  ];

  return (
    <ConsoleLayout 
      currentSection="dod"
      browserNav={{
        title: 'Deployment Orchestration Dashboard',
        subtitle: 'Graph-based security platform deployment and management',
        tabs,
        showAddTab: false,
        rightContent: <DashboardToggle />
      }}
    >
      <DeploymentOrchestrationDashboard />
    </ConsoleLayout>
  );
};

export default DeploymentOrchestrationHome;