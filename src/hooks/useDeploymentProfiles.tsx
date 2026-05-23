import { useState, useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';
import { 
  IndustryType, 
  DeploymentProfile, 
  OrganizationDeploymentSettings,
  INDUSTRY_DEPLOYMENT_TEMPLATES,
  DeploymentHistoryEntry
} from '@/types/deployment';

interface TrustMetrics {
  currentScore: number;
  trend: 'up' | 'down' | 'stable';
  successfulActions: number;
  totalActions: number;
  averageResponseTime: number;
  riskMitigated: number;
  nextPromotionScore: number;
  timeToPromotion: string;
}

export const useDeploymentProfiles = (organizationId: string) => {
  const [deploymentSettings, setDeploymentSettings] = useState<OrganizationDeploymentSettings | null>(null);
  const [trustMetrics, setTrustMetrics] = useState<TrustMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  const loadDeploymentSettings = async () => {
    try {
      const { data: orgSettings, error } = await supabase
        .from('organization_settings')
        .select('*')
        .eq('organization_id', organizationId)
        .single();

      if (error && error.code !== 'PGRST116') {
        throw error;
      }

      // If no settings exist, create default based on SMB profile
      if (!orgSettings) {
        const defaultProfile = INDUSTRY_DEPLOYMENT_TEMPLATES.smb;
        const defaultSettings: OrganizationDeploymentSettings = {
          id: crypto.randomUUID(),
          organizationId,
          activeProfile: defaultProfile,
          confidenceLevel: 60,
          deploymentHistory: [],
          graduationCriteria: {
            successRate: 85,
            minimumActions: 10,
            timeFrameDays: 30,
            riskLevelsHandled: ['low', 'medium']
          },
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        };

        await saveDeploymentSettings(defaultSettings);
        setDeploymentSettings(defaultSettings);
      } else {
        // Parse existing settings
        const securityPolicies = orgSettings.security_policies as any;
        const settings: OrganizationDeploymentSettings = {
          id: orgSettings.id,
          organizationId: orgSettings.organization_id!,
          activeProfile: securityPolicies?.deployment_profile || INDUSTRY_DEPLOYMENT_TEMPLATES.smb,
          confidenceLevel: securityPolicies?.confidence_level || 60,
          deploymentHistory: securityPolicies?.deployment_history || [],
          graduationCriteria: securityPolicies?.graduation_criteria || {
            successRate: 85,
            minimumActions: 10,
            timeFrameDays: 30,
            riskLevelsHandled: ['low', 'medium']
          },
          createdAt: orgSettings.created_at || new Date().toISOString(),
          updatedAt: orgSettings.updated_at || new Date().toISOString()
        };
        setDeploymentSettings(settings);
      }
    } catch (error) {
      console.error('Error loading deployment settings:', error);
      toast({
        title: 'Error',
        description: 'Failed to load deployment settings',
        variant: 'destructive'
      });
    }
  };

  const saveDeploymentSettings = async (settings: OrganizationDeploymentSettings) => {
    try {
      const { error } = await supabase
        .from('organization_settings')
        .upsert({
          organization_id: settings.organizationId,
          security_policies: JSON.parse(JSON.stringify({
            deployment_profile: settings.activeProfile,
            confidence_level: settings.confidenceLevel,
            deployment_history: settings.deploymentHistory,
            graduation_criteria: settings.graduationCriteria
          })),
          updated_at: new Date().toISOString()
        });

      if (error) throw error;

      setDeploymentSettings({ ...settings, updatedAt: new Date().toISOString() });
      toast({
        title: 'Success',
        description: 'Deployment settings saved successfully'
      });
    } catch (error) {
      console.error('Error saving deployment settings:', error);
      toast({
        title: 'Error',
        description: 'Failed to save deployment settings',
        variant: 'destructive'
      });
    }
  };

  const calculateTrustMetrics = async () => {
    try {
      // Get remediation actions for trust calculation
      const { data: actions, error } = await supabase
        .from('agent_actions')
        .select('success, execution_time_ms, risk_score, created_at')
        .eq('organization_id', organizationId)
        .order('created_at', { ascending: false })
        .limit(100);

      if (error) throw error;

      const totalActions = actions?.length || 0;
      const successfulActions = actions?.filter(a => a.success).length || 0;
      const avgResponseTime = totalActions > 0 
        ? Math.round((actions?.reduce((sum, a) => sum + (a.execution_time_ms || 0), 0) || 0) / totalActions / 1000)
        : 0;

      const currentScore = totalActions > 0 ? Math.round((successfulActions / totalActions) * 100) : 60;
      const riskMitigated = actions?.reduce((sum, a) => sum + (a.risk_score || 0), 0) || 0;

      // Determine next promotion score based on current profile
      const nextPromotionScore = deploymentSettings?.activeProfile.trustThresholds.promotion || 85;

      const metrics: TrustMetrics = {
        currentScore,
        trend: 'stable', // Could be calculated based on recent actions
        successfulActions,
        totalActions,
        averageResponseTime: avgResponseTime,
        riskMitigated,
        nextPromotionScore,
        timeToPromotion: estimateTimeToPromotion(currentScore, nextPromotionScore, successfulActions)
      };

      setTrustMetrics(metrics);
    } catch (error) {
      console.error('Error calculating trust metrics:', error);
    }
  };

  const estimateTimeToPromotion = (current: number, target: number, recentActions: number): string => {
    if (current >= target) return 'Eligible now';
    
    const scoreGap = target - current;
    const actionsNeeded = Math.ceil(scoreGap * 2); // Rough estimate
    const dailyActionRate = Math.max(1, Math.round(recentActions / 30)); // Actions per day
    const daysNeeded = Math.ceil(actionsNeeded / dailyActionRate);
    
    if (daysNeeded < 7) return `${daysNeeded} days`;
    if (daysNeeded < 30) return `${Math.ceil(daysNeeded / 7)} weeks`;
    return `${Math.ceil(daysNeeded / 30)} months`;
  };

  const switchDeploymentProfile = async (industry: IndustryType) => {
    if (!deploymentSettings) return;

    const newProfile = INDUSTRY_DEPLOYMENT_TEMPLATES[industry];
    const historyEntry: DeploymentHistoryEntry = {
      timestamp: new Date().toISOString(),
      action: `Switched to ${newProfile.name} profile`,
      success: true,
      riskLevel: 'low',
      automated: false,
      notes: `Manual profile change from ${deploymentSettings.activeProfile.name}`
    };

    const updatedSettings: OrganizationDeploymentSettings = {
      ...deploymentSettings,
      activeProfile: newProfile,
      deploymentHistory: [historyEntry, ...deploymentSettings.deploymentHistory],
      updatedAt: new Date().toISOString()
    };

    await saveDeploymentSettings(updatedSettings);
  };

  const upgradeAutomationLevel = async () => {
    if (!deploymentSettings || !trustMetrics) return;

    const currentLevel = deploymentSettings.activeProfile.automationLevel;
    const canUpgrade = trustMetrics.currentScore >= trustMetrics.nextPromotionScore;

    if (!canUpgrade) {
      toast({
        title: 'Cannot Upgrade',
        description: `Trust score must be at least ${trustMetrics.nextPromotionScore}% to upgrade automation level`,
        variant: 'destructive'
      });
      return;
    }

    // Determine next automation level
    let nextLevel = currentLevel;
    switch (currentLevel) {
      case 'monitor_only':
        nextLevel = 'guided';
        break;
      case 'guided':
        nextLevel = 'semi_automated';
        break;
      case 'semi_automated':
        nextLevel = 'fully_automated';
        break;
    }

    if (nextLevel === currentLevel) {
      toast({
        title: 'Maximum Level',
        description: 'Already at maximum automation level for this profile',
        variant: 'default'
      });
      return;
    }

    const historyEntry: DeploymentHistoryEntry = {
      timestamp: new Date().toISOString(),
      action: `Upgraded automation from ${currentLevel} to ${nextLevel}`,
      success: true,
      riskLevel: 'medium',
      automated: false,
      notes: `Trust score: ${trustMetrics.currentScore}%`
    };

    const updatedProfile = {
      ...deploymentSettings.activeProfile,
      automationLevel: nextLevel
    };

    const updatedSettings: OrganizationDeploymentSettings = {
      ...deploymentSettings,
      activeProfile: updatedProfile,
      deploymentHistory: [historyEntry, ...deploymentSettings.deploymentHistory],
      updatedAt: new Date().toISOString()
    };

    await saveDeploymentSettings(updatedSettings);
    
    toast({
      title: 'Automation Upgraded',
      description: `Successfully upgraded to ${nextLevel.replaceAll('_', ' ')} automation level`
    });
  };

  useEffect(() => {
    if (organizationId) {
      Promise.all([
        loadDeploymentSettings(),
        calculateTrustMetrics()
      ]).finally(() => setLoading(false));
    }
  }, [organizationId]);

  useEffect(() => {
    if (deploymentSettings && !loading) {
      calculateTrustMetrics();
    }
  }, [deploymentSettings, loading]);

  return {
    deploymentSettings,
    trustMetrics,
    loading,
    switchDeploymentProfile,
    upgradeAutomationLevel,
    saveDeploymentSettings,
    refresh: () => {
      loadDeploymentSettings();
      calculateTrustMetrics();
    }
  };
};