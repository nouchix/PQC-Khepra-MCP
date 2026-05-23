import { useState, useEffect, useCallback } from 'react';
import { useAuth } from './useAuth';
import { useOrganization } from './useOrganization';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from './use-toast';
import { AdinkraAlgebraicEngine } from '@/khepra/aae/AdinkraEngine';

interface AuthenticationRisk {
  level: 'low' | 'medium' | 'high' | 'critical';
  factors: string[];
  score: number;
  requiresReauth: boolean;
}

interface DeviceFingerprint {
  userAgent: string;
  screen: string;
  timezone: string;
  language: string;
  platform: string;
  cookieEnabled: boolean;
  doNotTrack: string;
  canvas: string;
  culturalFingerprint?: string;
}

interface ContinuousAuthState {
  isMonitoring: boolean;
  lastValidation: Date | null;
  riskLevel: AuthenticationRisk['level'];
  deviceTrusted: boolean;
  sessionValid: boolean;
  requiresReauth: boolean;
}

export function useContinuousAuth() {
  const { user } = useAuth();
  const { currentOrganization } = useOrganization();
  const { toast } = useToast();
  
  const [authState, setAuthState] = useState<ContinuousAuthState>({
    isMonitoring: false,
    lastValidation: null,
    riskLevel: 'low',
    deviceTrusted: false,
    sessionValid: true,
    requiresReauth: false
  });

  // Generate device fingerprint
  const generateDeviceFingerprint = useCallback((): DeviceFingerprint => {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    if (ctx) {
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillText('Device fingerprint', 2, 2);
    }

    const baseFingerprint = {
      userAgent: navigator.userAgent,
      screen: `${screen.width}x${screen.height}x${screen.colorDepth}`,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      language: navigator.language,
      platform: navigator.platform,
      cookieEnabled: navigator.cookieEnabled,
      doNotTrack: navigator.doNotTrack || 'unspecified',
      canvas: canvas.toDataURL()
    };

    // Generate KHEPRA cultural fingerprint
    const fingerprintData = JSON.stringify(baseFingerprint);
    const culturalFingerprint = AdinkraAlgebraicEngine.generateFingerprint(
      fingerprintData, 
      ['Eban', 'Nyame'] // Protection + Authority symbols
    );

    return {
      ...baseFingerprint,
      culturalFingerprint
    };
  }, []);

  // Calculate authentication risk
  const calculateAuthRisk = useCallback(async (fingerprint: DeviceFingerprint): Promise<AuthenticationRisk> => {
    const factors: string[] = [];
    let score = 0;

    // Check for known device
    if (!authState.deviceTrusted) {
      factors.push('Unknown device');
      score += 30;
    }

    // Check session age
    const sessionAge = authState.lastValidation 
      ? (Date.now() - authState.lastValidation.getTime()) / (1000 * 60)
      : 0;
    
    if (sessionAge > 120) { // 2 hours
      factors.push('Long session duration');
      score += 20;
    }

    // Check for unusual timezone
    const now = new Date();
    const hour = now.getHours();
    if (hour < 6 || hour > 22) {
      factors.push('Unusual login time');
      score += 15;
    }

    // Determine risk level
    let level: AuthenticationRisk['level'] = 'low';
    if (score >= 70) level = 'critical';
    else if (score >= 50) level = 'high';
    else if (score >= 30) level = 'medium';

    return {
      level,
      factors,
      score,
      requiresReauth: score >= 50
    };
  }, [authState.deviceTrusted, authState.lastValidation]);

  // Verify device trust
  const verifyDeviceTrust = useCallback(async (fingerprint: DeviceFingerprint): Promise<boolean> => {
    if (!user || !currentOrganization) return false;

    try {
      const fingerprintHash = btoa(JSON.stringify(fingerprint));
      
      const { data: device } = await supabase
        .from('security_devices')
        .select('*')
        .eq('user_id', user.id)
        .eq('device_fingerprint', fingerprintHash)
        .eq('is_trusted', true)
        .maybeSingle();

      if (device) {
        // Update last used
        await supabase
          .from('security_devices')
          .update({ last_used: new Date().toISOString() })
          .eq('id', device.id);
        
        return true;
      }

      return false;
    } catch (error) {
      console.error('Device verification error:', error);
      return false;
    }
  }, [user, currentOrganization]);

  // Register new device
  const registerDevice = useCallback(async (fingerprint: DeviceFingerprint, trustDevice: boolean = false) => {
    if (!user) return;

    try {
      const fingerprintHash = btoa(JSON.stringify(fingerprint));
      
      await supabase
        .from('security_devices')
        .insert({
          user_id: user.id,
          device_fingerprint: fingerprintHash,
          device_name: `${fingerprint.platform} - ${fingerprint.userAgent.split(' ')[0]}`,
          device_type: /Mobile|Android|iPhone|iPad/.test(fingerprint.userAgent) ? 'mobile' : 'desktop',
          location_info: fingerprint.timezone,
          is_trusted: trustDevice,
          trusted_until: trustDevice ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString() : null
        });

      if (trustDevice) {
        toast({
          title: "Device Registered",
          description: "This device has been marked as trusted for 30 days."
        });
      }
    } catch (error) {
      console.error('Device registration error:', error);
    }
  }, [user, toast]);

  // Perform continuous authentication check
  const performAuthCheck = useCallback(async () => {
    if (!user) return;

    const fingerprint = generateDeviceFingerprint();
    const deviceTrusted = await verifyDeviceTrust(fingerprint);
    const risk = await calculateAuthRisk(fingerprint);

    setAuthState(prev => ({
      ...prev,
      lastValidation: new Date(),
      deviceTrusted,
      riskLevel: risk.level,
      requiresReauth: risk.requiresReauth,
      sessionValid: !risk.requiresReauth
    }));

    // Log security event for high risk
    if (risk.level === 'high' || risk.level === 'critical') {
      await supabase.rpc('log_security_event', {
        event_type: 'high_risk_session',
        severity: risk.level.toUpperCase(),
        details: {
          risk_score: risk.score,
          risk_factors: risk.factors,
          device_trusted: deviceTrusted
        }
      });

      toast({
        title: "Security Alert",
        description: `${risk.level === 'critical' ? 'Critical' : 'High'} risk activity detected. Additional verification required.`,
        variant: "destructive"
      });
    }

    // Register device if new
    if (!deviceTrusted) {
      await registerDevice(fingerprint, false);
    }
  }, [user, generateDeviceFingerprint, verifyDeviceTrust, calculateAuthRisk, registerDevice, toast]);

  // Start monitoring
  const startMonitoring = useCallback(() => {
    if (!user) return;

    setAuthState(prev => ({ ...prev, isMonitoring: true }));
    
    // Initial check
    performAuthCheck();
    
    // Periodic checks every 5 minutes
    const interval = setInterval(performAuthCheck, 5 * 60 * 1000);
    
    // Check on page visibility change
    const handleVisibilityChange = () => {
      if (!document.hidden) {
        performAuthCheck();
      }
    };
    
    document.addEventListener('visibilitychange', handleVisibilityChange);
    
    return () => {
      clearInterval(interval);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [user, performAuthCheck]);

  // Stop monitoring
  const stopMonitoring = useCallback(() => {
    setAuthState(prev => ({ ...prev, isMonitoring: false }));
  }, []);

  // Trust current device
  const trustCurrentDevice = useCallback(async () => {
    const fingerprint = generateDeviceFingerprint();
    await registerDevice(fingerprint, true);
    setAuthState(prev => ({ ...prev, deviceTrusted: true }));
  }, [generateDeviceFingerprint, registerDevice]);

  // Force re-authentication
  const forceReauth = useCallback(() => {
    setAuthState(prev => ({ ...prev, requiresReauth: true, sessionValid: false }));
  }, []);

  // Clear re-auth requirement (after successful re-auth)
  const clearReauthRequirement = useCallback(() => {
    setAuthState(prev => ({ 
      ...prev, 
      requiresReauth: false, 
      sessionValid: true,
      lastValidation: new Date()
    }));
  }, []);

  // Auto-start monitoring when user is authenticated
  useEffect(() => {
    if (user && !authState.isMonitoring) {
      const cleanup = startMonitoring();
      return cleanup;
    }
  }, [user, authState.isMonitoring, startMonitoring]);

  return {
    ...authState,
    startMonitoring,
    stopMonitoring,
    trustCurrentDevice,
    forceReauth,
    clearReauthRequirement,
    performAuthCheck
  };
}