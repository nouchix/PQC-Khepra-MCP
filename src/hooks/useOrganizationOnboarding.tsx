import { useState, useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

export interface OnboardingPhase {
  phase: string;
  status: 'pending' | 'in_progress' | 'completed';
  completed_at: string | null;
}

export interface OrganizationOnboardingData {
  id: string;
  organization_id: string;
  current_phase: string;
  phase_status: Record<string, OnboardingPhase>;
  intake_data?: any;
  discovery_results?: any;
  integration_config?: any;
  training_progress?: any;
  assigned_lead?: string;
  technical_lead?: string;
  milestones?: any[];
  started_at: string;
  completed_at?: string;
}

export function useOrganizationOnboarding(organizationId: string | undefined) {
  const [onboarding, setOnboarding] = useState<OrganizationOnboardingData | null>(null);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  useEffect(() => {
    if (!organizationId) return;
    fetchOnboarding();
  }, [organizationId]);

  const fetchOnboarding = async () => {
    if (!organizationId) return;

    try {
      const { data, error } = await supabase
        .from('organization_onboarding')
        .select('*')
        .eq('organization_id', organizationId)
        .maybeSingle();

      if (error) throw error;

      if (!data) {
        // Create new onboarding record
        const { data: newOnboarding, error: createError } = await supabase
          .from('organization_onboarding')
          .insert({
            organization_id: organizationId,
            user_id: organizationId,
            current_phase: 'pre_onboarding',
          })
          .select()
          .single();

        if (createError) throw createError;
        setOnboarding(newOnboarding as unknown as OrganizationOnboardingData);
      } else {
        setOnboarding(data as unknown as OrganizationOnboardingData);
      }
    } catch (error) {
      console.error('Error fetching onboarding:', error);
      toast({
        title: 'Error',
        description: 'Failed to load onboarding data',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  const updatePhase = async (
    phase: string,
    status: 'pending' | 'in_progress' | 'completed'
  ) => {
    if (!onboarding) return;

    const updatedPhaseStatus = {
      ...onboarding.phase_status,
      [phase]: {
        phase,
        status,
        completed_at: status === 'completed' ? new Date().toISOString() : null,
      },
    };

    try {
      const { error } = await supabase
        .from('organization_onboarding')
        .update({
          current_phase: phase,
          phase_status: updatedPhaseStatus as any,
        })
        .eq('id', onboarding.id);

      if (error) throw error;

      setOnboarding({
        ...onboarding,
        current_phase: phase,
        phase_status: updatedPhaseStatus,
      });

      toast({
        title: 'Phase Updated',
        description: `Moved to ${phase.replaceAll('_', ' ')} phase`,
      });
    } catch (error) {
      console.error('Error updating phase:', error);
      toast({
        title: 'Error',
        description: 'Failed to update phase',
        variant: 'destructive',
      });
    }
  };

  const saveIntakeData = async (data: any) => {
    if (!onboarding) return;

    try {
      const { error } = await supabase
        .from('organization_onboarding')
        .update({ intake_data: data })
        .eq('id', onboarding.id);

      if (error) throw error;

      setOnboarding({ ...onboarding, intake_data: data });
    } catch (error) {
      console.error('Error saving intake data:', error);
      throw error;
    }
  };

  const saveDiscoveryResults = async (data: any) => {
    if (!onboarding) return;

    try {
      const { error } = await supabase
        .from('organization_onboarding')
        .update({ discovery_results: data })
        .eq('id', onboarding.id);

      if (error) throw error;

      setOnboarding({ ...onboarding, discovery_results: data });
    } catch (error) {
      console.error('Error saving discovery results:', error);
      throw error;
    }
  };

  const saveIntegrationConfig = async (data: any) => {
    if (!onboarding) return;

    try {
      const { error } = await supabase
        .from('organization_onboarding')
        .update({ integration_config: data })
        .eq('id', onboarding.id);

      if (error) throw error;

      setOnboarding({ ...onboarding, integration_config: data });
    } catch (error) {
      console.error('Error saving integration config:', error);
      throw error;
    }
  };

  const completeOnboarding = async () => {
    if (!onboarding) return;

    try {
      const { error } = await supabase
        .from('organization_onboarding')
        .update({
          completed_at: new Date().toISOString(),
          current_phase: 'go_live',
        })
        .eq('id', onboarding.id);

      if (error) throw error;

      toast({
        title: 'Onboarding Complete!',
        description: 'Welcome to continuous compliance monitoring',
      });
    } catch (error) {
      console.error('Error completing onboarding:', error);
      throw error;
    }
  };

  return {
    onboarding,
    loading,
    updatePhase,
    saveIntakeData,
    saveDiscoveryResults,
    saveIntegrationConfig,
    completeOnboarding,
    refetch: fetchOnboarding,
  };
}
