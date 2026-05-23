import { useState, useEffect } from 'react';
import { useAuth } from '@/hooks/useAuth';
import { useUserProfile } from '@/hooks/useUserProfile';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

export interface OnboardingStep {
  id: string;
  title: string;
  description: string;
  completed: boolean;
  required: boolean;
  action?: () => void;
}

export const useOnboarding = () => {
  const { user } = useAuth();
  const { profile, updateProfile } = useUserProfile();
  const { toast } = useToast();
  const [currentStep, setCurrentStep] = useState(0);
  const [showOnboarding, setShowOnboarding] = useState(false);
  const [showRoleBasedTour, setShowRoleBasedTour] = useState(false);

  const sendWelcomeEmail = async () => {
    if (!user || !profile) return;

    try {
      const { error } = await supabase.functions.invoke('send-welcome-email', {
        body: {
          userId: user.id,
          email: user.email,
          fullName: profile.full_name,
          organizationName: null // We'll add this when organization context is available
        }
      });

      if (error) throw error;

      toast({
        title: "Welcome Email Sent",
        description: "Check your inbox for important getting started information.",
        variant: "default"
      });
    } catch (error: any) {
      console.error('Error sending welcome email:', error);
      // Don't show error to user as this is not critical
    }
  };

  const steps: OnboardingStep[] = [
    {
      id: 'aws_setup',
      title: 'Account Creation',
      description: 'Create your SouHimBou AI account with email verification',
      completed: !!(user && profile?.full_name),
      required: true
    },
    {
      id: 'mfa',
      title: 'Multi-Factor Authentication',
      description: 'Secure your account with MFA (Required)',
      completed: false, // Will be updated when MFA component integration is complete
      required: true
    },
    {
      id: 'identity_verification',
      title: 'Identity Verification',
      description: 'Verify your phone number and complete security check',
      completed: false, // Will be updated when phone verification is complete
      required: true
    },
    {
      id: 'application_setup',
      title: 'Application Configuration',
      description: 'Configure your KHEPRA Protocol application',
      completed: false,
      required: true
    },
    {
      id: 'account_checklist',
      title: 'Complete Setup',
      description: 'Finalize account setup and billing configuration',
      completed: false,
      required: true
    },
    {
      id: 'welcome_email',
      title: 'Welcome Information',
      description: 'Receive important getting started resources',
      completed: false, // Could track if email was successfully sent
      required: false,
      action: sendWelcomeEmail
    }
  ];

  const completedSteps = steps.filter(step => step.completed).length;
  const totalSteps = steps.length;
  const progress = (completedSteps / totalSteps) * 100;
  const isOnboardingComplete = steps.filter(step => step.required).every(step => step.completed);

  useEffect(() => {
    // Show onboarding if user exists but onboarding isn't complete
    if (user && profile && !isOnboardingComplete) {
      // Check if user is new (created within last 24 hours)
      const userCreatedAt = new Date(user.created_at);
      const isNewUser = Date.now() - userCreatedAt.getTime() < 24 * 60 * 60 * 1000;
      
      if (isNewUser) {
        setShowOnboarding(true);
      }
    }
  }, [user, profile, isOnboardingComplete]);

  const completeStep = async (stepId: string, data?: any) => {
    const step = steps.find(s => s.id === stepId);
    if (!step || !user) return;

    try {
      switch (stepId) {
        case 'profile':
          if (data) {
            await updateProfile(data);
          }
          break;
        case 'security':
          if (data?.security_clearance) {
            await updateProfile({ security_clearance: data.security_clearance });
          }
          break;
        case 'mfa':
          // MFA completion is handled by the MFA component
          break;
        case 'welcome_email':
          if (step.action) {
            await step.action();
          }
          break;
        case 'explore':
          // Mark as completed - could store this in user preferences
          break;
      }

      // Log completion
      await supabase.rpc('log_user_action', {
        action_type: 'onboarding_step_completed',
        resource_type: 'onboarding',
        resource_id: stepId,
        details: { step: stepId, data }
      });

      toast({
        title: "Step Completed",
        description: `${step.title} has been completed successfully.`,
        variant: "default"
      });

    } catch (error: any) {
      toast({
        title: "Error",
        description: `Failed to complete ${step.title}: ${error.message}`,
        variant: "destructive"
      });
    }
  };

  const skipOnboarding = async () => {
    setShowOnboarding(false);
    
    await supabase.rpc('log_user_action', {
      action_type: 'onboarding_skipped',
      resource_type: 'onboarding',
      details: { 
        skipped_at: new Date().toISOString(),
        completed_steps: completedSteps,
        total_steps: totalSteps
      }
    });
  };

  const restartOnboarding = () => {
    setCurrentStep(0);
    setShowOnboarding(true);
  };

  const nextStep = () => {
    if (currentStep < steps.length - 1) {
      setCurrentStep(currentStep + 1);
    }
  };

  const previousStep = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const goToStep = (stepIndex: number) => {
    if (stepIndex >= 0 && stepIndex < steps.length) {
      setCurrentStep(stepIndex);
    }
  };

  const startRoleBasedTour = () => {
    setShowRoleBasedTour(true);
  };

  const completeRoleBasedTour = () => {
    setShowRoleBasedTour(false);
    setShowOnboarding(false);
    
    // Mark tour as completed in user preferences
    supabase.rpc('log_user_action', {
      action_type: 'role_based_tour_completed',
      resource_type: 'onboarding',
      details: { 
        completed_at: new Date().toISOString(),
        user_role: profile?.role || 'viewer'
      }
    });
  };

  return {
    steps,
    currentStep,
    showOnboarding,
    setShowOnboarding,
    showRoleBasedTour,
    setShowRoleBasedTour,
    completedSteps,
    totalSteps,
    progress,
    isOnboardingComplete,
    completeStep,
    skipOnboarding,
    restartOnboarding,
    nextStep,
    previousStep,
    goToStep,
    startRoleBasedTour,
    completeRoleBasedTour
  };
};