import { useEffect } from 'react';
import { useTrialStatus } from '@/hooks/useTrialStatus';
import { useResourceTracker } from '@/hooks/useResourceTracker';
import { useAuth } from '@/hooks/useAuth';
import { supabase } from '@/integrations/supabase/client';

interface UsageEvent {
  event_type: string;
  feature_accessed: string;
  metadata?: Record<string, any>;
}

export const useUsageTracker = () => {
  const { user } = useAuth();
  const { trialStatus } = useTrialStatus();
  const { trackApiCall, trackResource } = useResourceTracker();

  const trackUsage = async (eventType: string, featureAccessed: string, metadata?: Record<string, any>) => {
    if (!user || !trialStatus.isBetaActive) return;

    try {
      // Track in audit logs for behavior analysis
      await supabase.rpc('log_user_action', {
        action_type: eventType,
        resource_type: 'feature_usage',
        resource_id: featureAccessed,
        details: {
          feature_accessed: featureAccessed,
          plan_type: trialStatus.planType,
          ...metadata
        }
      });

      // Also track as billable API call usage
      await trackApiCall(1, {
        event_type: eventType,
        feature_accessed: featureAccessed,
        plan_type: trialStatus.planType,
        ...metadata
      });
    } catch (error) {
      console.error('Error tracking usage:', error);
    }
  };

  const trackFeatureAccess = (featureName: string, featureType: 'basic' | 'customization' | 'reminders' | 'grace_mode' | 'premium' | 'enterprise') => {
    trackUsage('feature_accessed', featureName, { feature_type: featureType });
  };

  const trackUpgradePrompt = (promptLocation: string, action: 'shown' | 'clicked' | 'dismissed') => {
    trackUsage('upgrade_prompt', promptLocation, { action });
  };

  const trackBetaEvent = (eventType: 'beta_started' | 'upgrade_to_plus' | 'conversion') => {
    trackUsage('beta_event', eventType, { plan_type: trialStatus.planType });
  };

  // Track compute-intensive operations
  const trackComputeUsage = async (operation: string, duration: number) => {
    const cpuHours = duration / 3600; // Convert seconds to hours
    await trackResource('compute', cpuHours, 'cpu_hours', operation, {
      operation,
      duration_seconds: duration
    });
  };

  // Track threat analysis operations
  const trackThreatAnalysisUsage = async (threatCount: number = 1, analysisType?: string) => {
    await trackResource('threats_analyzed', threatCount, 'threats', 'threat_analysis', {
      analysis_type: analysisType || 'standard',
      timestamp: new Date().toISOString()
    });
  };

  // Track compliance scans
  const trackComplianceScanUsage = async (scanType: string, controlsChecked: number) => {
    await trackResource('compliance_scans', 1, 'scans', 'compliance_scan', {
      scan_type: scanType,
      controls_checked: controlsChecked,
      timestamp: new Date().toISOString()
    });
  };

  return {
    trackFeatureAccess,
    trackUpgradePrompt,
    trackBetaEvent,
    trackUsage,
    trackComputeUsage,
    trackThreatAnalysisUsage,
    trackComplianceScanUsage
  };
};

// Component to automatically track page visits
export const UsageTracker = ({ pageName }: { pageName: string }) => {
  const { trackFeatureAccess } = useUsageTracker();

  useEffect(() => {
    trackFeatureAccess(pageName, 'basic');
  }, [pageName, trackFeatureAccess]);

  return null;
};