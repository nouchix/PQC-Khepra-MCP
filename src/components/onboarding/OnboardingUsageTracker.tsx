import { useEffect } from 'react';
import { useResourceTracker } from '@/hooks/useResourceTracker';
import { useOrganization } from '@/hooks/useOrganization';

interface OnboardingUsageTrackerProps {
  step: string;
  action: string;
  metadata?: Record<string, any>;
}

export const OnboardingUsageTracker = ({ step, action, metadata }: OnboardingUsageTrackerProps) => {
  const { trackApiCall, trackResource } = useResourceTracker();
  const { currentOrganization } = useOrganization();

  useEffect(() => {
    const trackOnboardingStep = async () => {
      if (!currentOrganization) return;

      // Track as API call for basic usage
      await trackApiCall(1, {
        onboarding_step: step,
        action: action,
        organization_id: currentOrganization.id,
        timestamp: new Date().toISOString(),
        ...metadata
      });

      // Track compute-intensive steps separately
      if (['security_assessment', 'compliance_scan', 'threat_analysis'].includes(action)) {
        const computeTime = action === 'compliance_scan' ? 0.5 : 0.1; // Hours
        await trackResource('compute', computeTime, 'cpu_hours', `onboarding_${action}`, {
          step,
          action,
          ...metadata
        });
      }

      // Track compliance scans during onboarding
      if (action === 'compliance_scan') {
        await trackResource('compliance_scans', 1, 'scans', 'onboarding_compliance_scan', {
          step,
          frameworks: metadata?.frameworks || [],
          ...metadata
        });
      }

      // Track threat analysis during security assessment
      if (action === 'threat_analysis') {
        const threatCount = metadata?.threat_count || 10;
        await trackResource('threats_analyzed', threatCount, 'threats', 'onboarding_threat_analysis', {
          step,
          analysis_type: 'initial_assessment',
          ...metadata
        });
      }
    };

    trackOnboardingStep().catch(console.error);
  }, [step, action, metadata, currentOrganization, trackApiCall, trackResource]);

  return null; // This is a tracking component with no UI
};

// Hook for easy onboarding usage tracking
export const useOnboardingTracker = () => {
  const { trackApiCall, trackResource } = useResourceTracker();
  const { currentOrganization } = useOrganization();

  const trackOnboardingEvent = async (
    eventType: 'step_completed' | 'feature_explored' | 'integration_tested' | 'setup_finished',
    details: Record<string, any>
  ) => {
    if (!currentOrganization) return;

    await trackApiCall(1, {
      event_type: eventType,
      organization_id: currentOrganization.id,
      timestamp: new Date().toISOString(),
      ...details
    });

    // Track compute usage for resource-intensive onboarding actions
    if (details.compute_intensive) {
      const computeHours = details.estimated_compute_hours || 0.1;
      await trackResource('compute', computeHours, 'cpu_hours', `onboarding_${eventType}`, details);
    }
  };

  const trackInitialSetup = async (orgData: {
    name: string;
    industry: string;
    size: string;
    securityRequirements: string[];
  }) => {
    await trackOnboardingEvent('setup_finished', {
      organization_name: orgData.name,
      industry: orgData.industry,
      organization_size: orgData.size,
      security_frameworks_count: orgData.securityRequirements.length,
      security_frameworks: orgData.securityRequirements,
      compute_intensive: true,
      estimated_compute_hours: 1.0 // Initial setup and configuration
    });
  };

  const trackFeatureDemo = async (featureName: string, duration: number) => {
    await trackOnboardingEvent('feature_explored', {
      feature_name: featureName,
      demo_duration_seconds: duration,
      compute_intensive: featureName.includes('AI') || featureName.includes('analysis'),
      estimated_compute_hours: featureName.includes('AI') ? 0.05 : 0.01
    });
  };

  const trackIntegrationTest = async (integrationType: string, success: boolean) => {
    await trackOnboardingEvent('integration_tested', {
      integration_type: integrationType,
      test_success: success,
      compute_intensive: true,
      estimated_compute_hours: 0.1
    });
  };

  return {
    trackOnboardingEvent,
    trackInitialSetup,
    trackFeatureDemo,
    trackIntegrationTest
  };
};