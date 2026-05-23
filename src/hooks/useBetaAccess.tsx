import { useState, useEffect } from 'react';
import { useAuth } from './useAuth';
import { supabase } from '@/integrations/supabase/client';

export interface BetaEnrollment {
  id: string;
  tier: 'trailblazer_beta' | 'mvp_1_beta' | 'mvp_2_pilot';
  max_assets: number;
  current_asset_count: number;
  beta_terms_accepted: boolean;
  cui_acknowledgment_signed: boolean;
  expires_at: string | null;
}

export const BETA_FEATURES = {
  trailblazer_beta: {
    stig_registry_view: true,
    ai_verification: true, // Mock only
    evidence_bundles: false,
    asset_scanning: false,
    drift_detection: false,
    remediation: false,
    max_assets: 0,
  },
  mvp_1_beta: {
    stig_registry_view: true,
    ai_verification: true,
    evidence_bundles: true, // Non-CUI only
    asset_scanning: true,
    drift_detection: false,
    remediation: false,
    max_assets: 50,
  },
  mvp_2_pilot: {
    stig_registry_view: true,
    ai_verification: true,
    evidence_bundles: true,
    asset_scanning: true,
    drift_detection: true, // Preview
    remediation: true, // Preview with rollback
    max_assets: 250,
  }
};

export const useBetaAccess = () => {
  const { user } = useAuth();
  const [enrollment, setEnrollment] = useState<BetaEnrollment | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (user) {
      checkBetaEnrollment();
    } else {
      setLoading(false);
    }
  }, [user]);

  const checkBetaEnrollment = async () => {
    if (!user) return;
    
    try {
      const { data, error } = await supabase
        .from('beta_enrollments')
        .select('*')
        .eq('user_id', user.id)
        .or(`expires_at.is.null,expires_at.gt.${new Date().toISOString()}`)
        .maybeSingle();

      if (error && error.code !== 'PGRST116') {
        console.error('Error fetching beta enrollment:', error);
      }

      setEnrollment(data as BetaEnrollment | null);
    } catch (error) {
      console.error('Error checking beta enrollment:', error);
    } finally {
      setLoading(false);
    }
  };

  const canAccessFeature = (feature: keyof typeof BETA_FEATURES.mvp_2_pilot) => {
    if (!enrollment || !enrollment.beta_terms_accepted || !enrollment.cui_acknowledgment_signed) {
      return false;
    }

    return BETA_FEATURES[enrollment.tier][feature] === true;
  };

  const canAddAsset = () => {
    if (!enrollment) return false;
    return enrollment.current_asset_count < enrollment.max_assets;
  };

  const scanForCUI = async (data: any) => {
    try {
      const { data: scanResult, error } = await supabase.functions.invoke('scan-for-cui', {
        body: {
          data,
          enrollment_id: enrollment?.id
        }
      });

      if (error) throw error;
      return scanResult;
    } catch (error) {
      console.error('CUI scan error:', error);
      return { allowed: false, error: 'Scan failed' };
    }
  };

  return {
    enrollment,
    loading,
    hasBetaAccess: !!enrollment?.beta_terms_accepted && !!enrollment?.cui_acknowledgment_signed,
    canAccessFeature,
    canAddAsset,
    scanForCUI,
    checkBetaEnrollment
  };
};