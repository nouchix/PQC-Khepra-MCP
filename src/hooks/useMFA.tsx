import { useState, useCallback } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/hooks/useAuth';

interface MFAFactor {
  id: string;
  type: 'totp';
  status: 'verified' | 'unverified';
  friendly_name?: string;
}

interface MFAEnrollmentData {
  factorId: string;
  qrCode: string;
  secret: string;
  uri: string;
}

interface MFAState {
  isEnabled: boolean;
  isLoading: boolean;
  factors: MFAFactor[];
  enrollmentData: MFAEnrollmentData | null;
  error: string | null;
}

export const useMFA = () => {
  const { user } = useAuth();
  const { toast } = useToast();
  
  const [state, setState] = useState<MFAState>({
    isEnabled: false,
    isLoading: false,
    factors: [],
    enrollmentData: null,
    error: null
  });

  const setLoading = (loading: boolean) => {
    setState(prev => ({ ...prev, isLoading: loading }));
  };

  const setError = (error: string | null) => {
    setState(prev => ({ ...prev, error }));
  };

  const clearError = () => setError(null);

  // Check current MFA status
  const checkMFAStatus = useCallback(async () => {
    if (!user) return;

    try {
      setLoading(true);
      clearError();

      const { data, error } = await supabase.auth.mfa.listFactors();
      
      if (error) throw error;

      const factors: MFAFactor[] = data?.totp?.map(factor => ({
        id: factor.id,
        type: 'totp' as const,
        status: factor.status as 'verified' | 'unverified',
        friendly_name: factor.friendly_name
      })) || [];

      const isEnabled = factors.some(factor => factor.status === 'verified');

      setState(prev => ({
        ...prev,
        isEnabled,
        factors,
        isLoading: false
      }));

      return { isEnabled, factors };
    } catch (error: any) {
      console.error('Error checking MFA status:', error);
      setError(`Failed to check MFA status: ${error.message}`);
      setLoading(false);
      return { isEnabled: false, factors: [] };
    }
  }, [user]);

  // Clean up any existing unverified factors
  const cleanupUnverifiedFactors = useCallback(async () => {
    try {
      const { data } = await supabase.auth.mfa.listFactors();
      
      if (data?.totp) {
        for (const factor of data.totp) {
          if (factor.status === 'unverified') {
            console.log('Cleaning up unverified factor:', factor.id);
            await supabase.auth.mfa.unenroll({ factorId: factor.id });
          }
        }
      }
      
      // Wait a moment for cleanup to complete
      await new Promise(resolve => setTimeout(resolve, 500));
    } catch (error) {
      console.warn('Error during cleanup:', error);
    }
  }, []);

  // Start MFA enrollment
  const startEnrollment = useCallback(async () => {
    if (!user) {
      setError('User not authenticated');
      return null;
    }

    try {
      setLoading(true);
      clearError();

      // Clean up any existing unverified factors first
      await cleanupUnverifiedFactors();

      // Enroll new factor
      const { data, error } = await supabase.auth.mfa.enroll({
        factorType: 'totp',
        friendlyName: `${user.email || 'User'}'s Authenticator`
      });

      if (error) throw error;

      if (!data?.totp) {
        throw new Error('No TOTP data returned from enrollment');
      }

      const enrollmentData: MFAEnrollmentData = {
        factorId: data.id,
        qrCode: data.totp.qr_code,
        secret: data.totp.secret,
        uri: data.totp.uri
      };

      setState(prev => ({
        ...prev,
        enrollmentData,
        isLoading: false
      }));

      console.log('MFA enrollment started successfully:', data.id);
      return enrollmentData;
    } catch (error: any) {
      console.error('Error starting MFA enrollment:', error);
      setError(`Failed to start MFA setup: ${error.message}`);
      setLoading(false);
      return null;
    }
  }, [user, cleanupUnverifiedFactors]);

  // Verify MFA code
  const verifyCode = useCallback(async (code: string): Promise<boolean> => {
    if (!state.enrollmentData) {
      setError('No enrollment in progress');
      return false;
    }

    try {
      setLoading(true);
      clearError();

      // Create challenge
      const { data: challengeData, error: challengeError } = await supabase.auth.mfa.challenge({
        factorId: state.enrollmentData.factorId
      });

      if (challengeError) throw challengeError;

      if (!challengeData?.id) {
        throw new Error('No challenge ID returned');
      }

      console.log('Challenge created:', challengeData.id);

      // Verify the code
      const { data: verifyData, error: verifyError } = await supabase.auth.mfa.verify({
        factorId: state.enrollmentData.factorId,
        challengeId: challengeData.id,
        code: code.trim()
      });

      if (verifyError) throw verifyError;

      console.log('MFA verification successful');

      // Update state
      setState(prev => ({
        ...prev,
        isEnabled: true,
        enrollmentData: null,
        isLoading: false
      }));

      // Refresh factors list
      await checkMFAStatus();

      toast({
        title: "MFA Enabled Successfully",
        description: "Two-factor authentication is now active on your account.",
      });

      return true;
    } catch (error: any) {
      console.error('Error verifying MFA code:', error);
      setError(`Verification failed: ${error.message}`);
      setLoading(false);
      return false;
    }
  }, [state.enrollmentData, checkMFAStatus, toast]);

  // Cancel enrollment
  const cancelEnrollment = useCallback(async () => {
    if (state.enrollmentData) {
      try {
        await supabase.auth.mfa.unenroll({ factorId: state.enrollmentData.factorId });
      } catch (error) {
        console.warn('Error canceling enrollment:', error);
      }
    }

    setState(prev => ({
      ...prev,
      enrollmentData: null,
      error: null
    }));
  }, [state.enrollmentData]);

  // Disable MFA
  const disableMFA = useCallback(async (): Promise<boolean> => {
    if (!user) return false;

    try {
      setLoading(true);
      clearError();

      const { data } = await supabase.auth.mfa.listFactors();
      
      if (data?.totp) {
        for (const factor of data.totp) {
          if (factor.status === 'verified') {
            await supabase.auth.mfa.unenroll({ factorId: factor.id });
          }
        }
      }

      // Update profile
      await supabase
        .from('profiles')
        .update({
          mfa_enabled: false,
          mfa_backup_codes: null
        })
        .eq('user_id', user.id);

      setState(prev => ({
        ...prev,
        isEnabled: false,
        factors: [],
        isLoading: false
      }));

      toast({
        title: "MFA Disabled",
        description: "Two-factor authentication has been disabled.",
      });

      return true;
    } catch (error: any) {
      console.error('Error disabling MFA:', error);
      setError(`Failed to disable MFA: ${error.message}`);
      setLoading(false);
      return false;
    }
  }, [user, toast]);

  // Generate backup codes using cryptographically secure random values
  const generateBackupCodes = useCallback((): string[] => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const codes: string[] = [];
    for (let i = 0; i < 8; i++) {
      const randomBytes = crypto.getRandomValues(new Uint8Array(6));
      const code = Array.from(randomBytes).map(b => chars[b % chars.length]).join('');
      codes.push(code);
    }
    return codes;
  }, []);

  return {
    // State
    isEnabled: state.isEnabled,
    isLoading: state.isLoading,
    factors: state.factors,
    enrollmentData: state.enrollmentData,
    error: state.error,
    
    // Actions
    checkMFAStatus,
    startEnrollment,
    verifyCode,
    cancelEnrollment,
    disableMFA,
    generateBackupCodes,
    clearError
  };
};