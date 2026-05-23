import { useState, useEffect } from 'react';
import { ConsoleLayout } from '@/components/console/ConsoleLayout';
import { MVP1Dashboard } from '@/components/compliance/MVP1Dashboard';
import { DashboardToggle } from '@/components/DashboardToggle';
import { TermsAcceptance } from '@/components/legal/TermsAcceptance';
import { PapyrusGenie } from '@/components/onboarding/PapyrusGenie';
import GuidedTour from '@/components/GuidedTour';
import { useUserAgreements } from '@/hooks/useUserAgreements';
import { useAuth } from '@/hooks/useAuth';

const STIGDashboard = () => {
  const { user } = useAuth();
  const { hasAcceptedAll, checkAgreementStatus } = useUserAgreements();
  const [showTerms, setShowTerms] = useState(false);

  useEffect(() => {
    if (user && !hasAcceptedAll) {
      checkAgreementStatus(user.id).then(accepted => {
        if (!accepted) {
          setShowTerms(true);
        }
      });
    }
  }, [user, hasAcceptedAll, checkAgreementStatus]);

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

      {/* Required Legal Terms Modal - Triggered if not yet accepted */}
      <TermsAcceptance
        open={showTerms}
        onOpenChange={setShowTerms}
        onAccepted={() => {
          setShowTerms(false);
        }}
      />

      {/* Proactive AI Assistant */}
      <PapyrusGenie />

      {/* Guided Tour - triggered by ?tour=true from onboarding */}
      <GuidedTour />
    </ConsoleLayout>
  );
};

export default STIGDashboard;