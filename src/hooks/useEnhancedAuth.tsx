import { useState, useEffect } from 'react';
import { useAuth } from './useAuth';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';

interface AuthSecurityState {
  isAccountLocked: boolean;
  failedAttempts: number;
  deviceTrusted: boolean;
  sessionRisk: 'low' | 'medium' | 'high' | 'critical';
  mfaRequired: boolean;
  passwordStrength?: {
    score: number;
    isStrong: boolean;
    feedback: string[];
  };
}

interface EnhancedAuthResult {
  securityState: AuthSecurityState;
  signInSecure: (email: string, password: string) => Promise<{ error: any; requiresMfa?: boolean }>;
  checkAccountSecurity: () => Promise<void>;
  validatePasswordStrength: (password: string) => Promise<void>;
  trustCurrentDevice: (deviceName: string) => Promise<void>;
  recordSecurityEvent: (eventType: string, riskLevel: string, details?: any) => Promise<void>;
}

export const useEnhancedAuth = (): EnhancedAuthResult => {
  const { user, signIn } = useAuth();
  const [securityState, setSecurityState] = useState<AuthSecurityState>({
    isAccountLocked: false,
    failedAttempts: 0,
    deviceTrusted: false,
    sessionRisk: 'low',
    mfaRequired: false,
  });

  // Generate device fingerprint for security tracking
  const generateDeviceFingerprint = (): string => {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    if (ctx) {
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillText('Device fingerprint', 2, 2);
    }
    
    const fingerprint = [
      navigator.userAgent,
      navigator.language,
      screen.width + 'x' + screen.height,
      new Date().getTimezoneOffset(),
      canvas.toDataURL(),
      navigator.platform,
      navigator.cookieEnabled,
    ].join('|');
    
    return btoa(fingerprint).substring(0, 32);
  };

  const signInSecure = async (email: string, password: string) => {
    try {
      // Check if account is locked before attempting login
      const { data: isLocked } = await supabase.rpc('is_account_locked', {
        user_email: email
      });

      if (isLocked) {
        setSecurityState(prev => ({ ...prev, isAccountLocked: true }));
        toast.error('Account temporarily locked due to security concerns. Please try again later.');
        return { error: { message: 'Account locked' } };
      }

      // Attempt login
      const { error } = await signIn(email, password);
      
      if (error) {
        // Record failed login attempt
        await supabase.rpc('record_failed_login', {
          user_email: email,
          client_ip: null, // Will be detected server-side
          client_user_agent: navigator.userAgent
        });
        
        // Record security event
        await recordSecurityEvent('failed_login', 'medium', {
          email,
          error_type: error.message,
          device_fingerprint: generateDeviceFingerprint()
        });

        setSecurityState(prev => ({ 
          ...prev, 
          failedAttempts: prev.failedAttempts + 1 
        }));

        return { error };
      }

      // Successful login - check device trust and record security event
      await checkDeviceTrust();
      await recordSecurityEvent('successful_login', 'low', {
        email,
        device_fingerprint: generateDeviceFingerprint()
      });

      return { error: null };

    } catch (err) {
      console.error('Enhanced auth error:', err);
      return { error: err };
    }
  };

  const checkDeviceTrust = async () => {
    if (!user) return;

    const deviceFingerprint = generateDeviceFingerprint();
    
    try {
      const { data: trustedDevice } = await supabase
        .from('trusted_devices')
        .select('*')
        .eq('user_id', user.id)
        .eq('device_fingerprint', deviceFingerprint)
        .eq('is_active', true)
        .single();

      if (trustedDevice) {
        setSecurityState(prev => ({ ...prev, deviceTrusted: true }));
        
        // Update last used timestamp
        await supabase
          .from('trusted_devices')
          .update({ last_used: new Date().toISOString() })
          .eq('id', trustedDevice.id);
      } else {
        setSecurityState(prev => ({ 
          ...prev, 
          deviceTrusted: false, 
          sessionRisk: 'medium' 
        }));
        
        toast.warning('New device detected. Consider adding this device to your trusted devices for enhanced security.');
      }
    } catch (error) {
      console.error('Error checking device trust:', error);
    }
  };

  const trustCurrentDevice = async (deviceName: string) => {
    if (!user) return;

    const deviceFingerprint = generateDeviceFingerprint();
    
    try {
      await supabase
        .from('trusted_devices')
        .upsert({
          user_id: user.id,
          device_fingerprint: deviceFingerprint,
          device_name: deviceName,
          ip_address: null, // Will be detected server-side
          user_agent: navigator.userAgent,
          trusted_at: new Date().toISOString(),
          last_used: new Date().toISOString(),
          expires_at: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(), // 90 days
        });

      setSecurityState(prev => ({ ...prev, deviceTrusted: true }));
      toast.success('Device added to trusted devices successfully.');
      
      await recordSecurityEvent('device_trusted', 'low', {
        device_name: deviceName,
        device_fingerprint: deviceFingerprint
      });

    } catch (error) {
      console.error('Error trusting device:', error);
      toast.error('Failed to add device to trusted devices.');
    }
  };

  const validatePasswordStrength = async (password: string) => {
    try {
      const { data: strength } = await supabase.rpc('validate_password_strength', {
        password
      });

      if (strength && typeof strength === 'object' && 'score' in strength) {
        const typedStrength = strength as unknown as {
          score: number;
          is_strong: boolean;
          feedback: string[];
        };
        setSecurityState(prev => ({
          ...prev,
          passwordStrength: {
            score: typedStrength.score,
            isStrong: typedStrength.is_strong,
            feedback: typedStrength.feedback
          }
        }));
      }
    } catch (error) {
      console.error('Error validating password strength:', error);
    }
  };

  const recordSecurityEvent = async (eventType: string, riskLevel: string, details: any = {}) => {
    if (!user) return;

    try {
      await supabase
        .from('session_security_events')
        .insert({
          user_id: user.id,
          event_type: eventType,
          risk_level: riskLevel,
          device_fingerprint: generateDeviceFingerprint(),
          user_agent: navigator.userAgent,
          details: details
        });
    } catch (error) {
      console.error('Error recording security event:', error);
    }
  };

  const checkAccountSecurity = async () => {
    if (!user) return;

    try {
      // Check recent security events
      const { data: recentEvents } = await supabase
        .from('session_security_events')
        .select('*')
        .eq('user_id', user.id)
        .gte('created_at', new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString())
        .order('created_at', { ascending: false });

      if (recentEvents) {
        const highRiskEvents = recentEvents.filter(e => e.risk_level === 'high' || e.risk_level === 'critical');
        
        if (highRiskEvents.length > 0) {
          setSecurityState(prev => ({ ...prev, sessionRisk: 'high' }));
          toast.warning('High-risk security activity detected. Please review your account security.');
        }
      }

      // Check device trust
      await checkDeviceTrust();

    } catch (error) {
      console.error('Error checking account security:', error);
    }
  };

  useEffect(() => {
    if (user) {
      checkAccountSecurity();
    }
  }, [user]);

  return {
    securityState,
    signInSecure,
    checkAccountSecurity,
    validatePasswordStrength,
    trustCurrentDevice,
    recordSecurityEvent
  };
};