import { useMemo, useState, useEffect } from 'react';
import { ConsoleLayout } from '@/components/console/ConsoleLayout';
import { ConsoleHome } from '@/components/console/ConsoleHome';
import { useUserProfile } from '@/hooks/useUserProfile';
import { DashboardToggle } from '@/components/DashboardToggle';
import { useOnboarding } from '@/hooks/useOnboarding';
import { EnhancedOnboarding } from '@/components/onboarding/EnhancedOnboarding';
import { AWSDeploymentStatus } from '@/components/AWSDeploymentStatus';

const ConsoleDashboard = () => {
  const { profile } = useUserProfile();
  const { showOnboarding, setShowOnboarding, completeRoleBasedTour } = useOnboarding();
  const [isNewUser, setIsNewUser] = useState(false);

  useEffect(() => {
    // Show onboarding for users who haven't seen it yet (based on localStorage)
    const hasSeenOnboarding = localStorage.getItem('has_seen_onboarding');
    
    if (profile && !hasSeenOnboarding) {
      setIsNewUser(true);
      setShowOnboarding(true);
    }
  }, [profile, setShowOnboarding]);

  const handleOnboardingComplete = () => {
    localStorage.setItem('has_seen_onboarding', 'true');
    completeRoleBasedTour();
    setIsNewUser(false);
  };

  const tabs = useMemo(() => {
    const baseTabs = [
      { id: 'dashboard', title: 'Dashboard', path: '/dashboard', isActive: true },
      { id: 'deployment', title: 'AWS Deployment', path: '/dashboard?view=deployment', hasNotification: false },
      { id: 'dod', title: 'DOD Operations', path: '/dod', hasNotification: true },
      { id: 'security', title: 'Security', path: '/security' },
      { id: 'infrastructure', title: 'Infrastructure', path: '/infrastructure' },
      { id: 'integrations', title: 'Integrations', path: '/integration-guide' },
      { id: 'cmmc', title: 'CMMC Compliance', path: '/compliance-automation' },
      { id: 'threat-feeds', title: 'Threat Feeds', path: '/dashboard?view=threat-feeds' },
      { id: 'ai-asoc', title: 'AI ASOC', path: '/dashboard?view=ai-asoc' },
      { id: 'analytics', title: 'Analytics', path: '/dashboard?view=analytics' },
      { id: 'alerts', title: 'Alerts', path: '/dashboard?view=alerts' },
      { id: 'billing', title: 'Billing', path: '/billing' },
    ];

    if (profile?.master_admin) {
      baseTabs.push({ id: 'master-admin', title: 'Master Admin', path: '/admin' });
    } else if (profile?.role === 'admin') {
      baseTabs.push({ id: 'admin', title: 'Admin Console', path: '/admin' });
    }

    return baseTabs;
  }, [profile]);

  return (
    <>
      <ConsoleLayout 
        currentSection="home"
        browserNav={{
          title: 'Secure Platform Operations',
          subtitle: 'Department of Defense certified security infrastructure management',
          tabs,
          showAddTab: true,
          rightContent: <DashboardToggle />
        }}
      >
        <ConsoleHome />
      </ConsoleLayout>

      {/* Enhanced Onboarding for New Users */}
      <EnhancedOnboarding
        open={showOnboarding && isNewUser}
        onClose={() => setShowOnboarding(false)}
        onComplete={handleOnboardingComplete}
      />
    </>
  );
};

export default ConsoleDashboard;