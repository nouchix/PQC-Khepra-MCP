import { useState, useEffect, useCallback } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

interface DeviceFingerprint {
  userAgent: string;
  language: string;
  timezone: string;
  screenResolution: string;
  colorDepth: number;
  platform: string;
}

interface SessionSecurityState {
  lastActivity: Date;
  sessionTimeout: number; // minutes
  deviceFingerprint: string;
  isSessionValid: boolean;
  ipAddress: string;
  concurrentSessions: number;
  maxConcurrentSessions: number;
}

export const useSessionSecurity = () => {
  const { toast } = useToast();
  const [sessionState, setSessionState] = useState<SessionSecurityState>({
    lastActivity: new Date(),
    sessionTimeout: 30, // 30 minutes default
    deviceFingerprint: '',
    isSessionValid: true,
    ipAddress: '',
    concurrentSessions: 0,
    maxConcurrentSessions: 3
  });

  // Generate device fingerprint
  const generateDeviceFingerprint = useCallback((): string => {
    const fingerprint: DeviceFingerprint = {
      userAgent: navigator.userAgent,
      language: navigator.language,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      screenResolution: `${screen.width}x${screen.height}`,
      colorDepth: screen.colorDepth,
      platform: navigator.platform
    };

    // Create a hash of the fingerprint data
    const fingerprintString = JSON.stringify(fingerprint);
    let hash = 0;
    for (let i = 0; i < fingerprintString.length; i++) {
      const char = fingerprintString.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    
    return hash.toString(16);
  }, []);

  // Get IP address for session validation
  const getIpAddress = useCallback(async () => {
    try {
      const cached = sessionStorage.getItem('session_ip');
      if (cached) return cached;
      if (typeof navigator !== 'undefined' && navigator.onLine === false) return 'unknown';

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 3000);
      const response = await fetch('https://api.ipify.org?format=json', { signal: controller.signal });
      clearTimeout(timeout);
      if (!response.ok) throw new Error(`IP service responded ${response.status}`);
      const data = await response.json();
      return data.ip || 'unknown';
    } catch (error) {
      if (!sessionStorage.getItem('ip_warned')) {
        console.debug('IP lookup unavailable; continuing without it.');
        sessionStorage.setItem('ip_warned', '1');
      }
      return 'unknown';
    }
  }, []);

  // Initialize device fingerprint and IP tracking
  useEffect(() => {
    const initSecurity = async () => {
      const fingerprint = generateDeviceFingerprint();
      const ipAddress = await getIpAddress();
      
      setSessionState(prev => ({ 
        ...prev, 
        deviceFingerprint: fingerprint,
        ipAddress 
      }));
      
      // Store fingerprint in session storage for comparison
      const storedFingerprint = sessionStorage.getItem('device_fingerprint');
      const storedIp = sessionStorage.getItem('session_ip');
      
      if (!storedFingerprint) {
        sessionStorage.setItem('device_fingerprint', fingerprint);
      } else if (storedFingerprint !== fingerprint) {
        // Device fingerprint mismatch - potential security risk
        logSecurityEvent('device_fingerprint_mismatch', {
          stored: storedFingerprint,
          current: fingerprint,
          security_alert: true
        }, 'medium');
        
        toast({
          title: "Security Alert",
          description: "Device characteristics changed. Please re-authenticate for security.",
          variant: "destructive"
        });
      }

      if (!storedIp && ipAddress !== 'unknown') {
        sessionStorage.setItem('session_ip', ipAddress);
      } else if (storedIp && ipAddress !== 'unknown' && storedIp !== 'unknown' && storedIp !== ipAddress) {
        // IP address change detected
        logSecurityEvent('ip_address_change', {
          stored: storedIp,
          current: ipAddress,
          location_change: true
        }, 'low');
        
        toast({
          title: "Security Alert",
          description: "IP address changed. Session validated for security.",
          variant: "destructive"
        });
      }
    };

    initSecurity();
  }, [generateDeviceFingerprint, getIpAddress, toast]);

  // Log security events using enhanced security logging
  const logSecurityEvent = async (eventType: string, details: Record<string, any> = {}, riskLevel: string = 'low') => {
    try {
      // Use new secure session security logging function
      await supabase.rpc('log_session_security_event', {
        p_event_type: eventType,
        p_risk_level: riskLevel,
        p_device_fingerprint: sessionState.deviceFingerprint,
        p_details: {
          ...details,
          timestamp: new Date().toISOString(),
          session_timeout: sessionState.sessionTimeout,
          concurrent_sessions: sessionState.concurrentSessions
        }
      });
    } catch (error) {
      console.warn('Failed to log security event with new function, falling back to audit logs:', error);
      // Fallback to audit logs if new function fails
      try {
        await supabase.from('audit_logs').insert([{
          action: eventType,
          resource_type: 'session_security',
          details: {
            ...details,
            timestamp: new Date().toISOString(),
            fingerprint: sessionState.deviceFingerprint,
            risk_level: riskLevel
          }
        }]);
      } catch (fallbackError) {
        console.error('Failed to log security event to audit logs as well:', fallbackError);
      }
    }
  };

  // Update last activity
  const updateActivity = useCallback(() => {
    setSessionState(prev => ({
      ...prev,
      lastActivity: new Date(),
      isSessionValid: true
    }));
  }, []);

  // Check session timeout
  const checkSessionTimeout = useCallback(() => {
    const now = new Date();
    const timeDiff = now.getTime() - sessionState.lastActivity.getTime();
    const timeoutMs = sessionState.sessionTimeout * 60 * 1000;

    if (timeDiff > timeoutMs) {
      setSessionState(prev => ({ ...prev, isSessionValid: false }));
      
      logSecurityEvent('session_timeout', {
        lastActivity: sessionState.lastActivity.toISOString(),
        timeoutMinutes: sessionState.sessionTimeout,
        forced_logout: true
      }, 'medium');

      toast({
        title: "Session Expired",
        description: "Your session has expired due to inactivity. Please sign in again.",
        variant: "destructive"
      });

      // Sign out user
      supabase.auth.signOut();
      return false;
    }
    return true;
  }, [sessionState.lastActivity, sessionState.sessionTimeout, toast, logSecurityEvent]);

  // Check concurrent sessions
  const checkConcurrentSessions = useCallback(async () => {
    try {
      const { data, error } = await supabase.from('audit_logs')
        .select('details')
        .eq('action', 'session_created')
        .gte('created_at', new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString())
        .order('created_at', { ascending: false });

      if (error) throw error;

      const activeSessions = data?.length || 0;
      
      if (activeSessions > sessionState.maxConcurrentSessions) {
        logSecurityEvent('concurrent_session_limit_exceeded', {
          activeSessions,
          maxAllowed: sessionState.maxConcurrentSessions,
          potential_compromise: activeSessions > 5
        }, activeSessions > 5 ? 'high' : 'medium');
        
        toast({
          title: "Security Alert",
          description: "Too many active sessions. Please sign out from other devices.",
          variant: "destructive"
        });
        
        return false;
      }
      
      setSessionState(prev => ({ ...prev, concurrentSessions: activeSessions }));
      return true;
    } catch (error) {
      console.warn('Failed to check concurrent sessions:', error);
      return true; // Allow session to continue on error
    }
  }, [sessionState.maxConcurrentSessions, logSecurityEvent, toast]);

  // Refresh session token
  const refreshSession = useCallback(async () => {
    try {
      const { data, error } = await supabase.auth.refreshSession();
      if (error) throw error;
      
      updateActivity();
      await checkConcurrentSessions();
      
      logSecurityEvent('session_refreshed', {
        success: true,
        concurrentSessions: sessionState.concurrentSessions,
        security_validation_passed: true
      }, 'low');
      
      return true;
    } catch (error: any) {
      logSecurityEvent('session_refresh_failed', {
        error: error.message,
        critical_failure: true
      }, 'high');
      
      toast({
        title: "Session Refresh Failed",
        description: "Please sign in again.",
        variant: "destructive"
      });
      
      return false;
    }
  }, [updateActivity, checkConcurrentSessions, logSecurityEvent, toast, sessionState.concurrentSessions]);

  // Set up activity monitoring
  useEffect(() => {
    const activityEvents = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click'];
    
    const handleActivity = () => updateActivity();
    
    activityEvents.forEach(event => {
      document.addEventListener(event, handleActivity, { passive: true });
    });

    return () => {
      activityEvents.forEach(event => {
        document.removeEventListener(event, handleActivity);
      });
    };
  }, [updateActivity]);

  // Set up session timeout checking
  useEffect(() => {
    const interval = setInterval(() => {
      checkSessionTimeout();
    }, 60000); // Check every minute

    return () => clearInterval(interval);
  }, [checkSessionTimeout]);

  // Set up automatic token refresh and security checks
  useEffect(() => {
    const refreshInterval = setInterval(() => {
      if (sessionState.isSessionValid) {
        refreshSession();
        checkConcurrentSessions();
      }
    }, 25 * 60 * 1000); // Refresh every 25 minutes

    return () => clearInterval(refreshInterval);
  }, [sessionState.isSessionValid, refreshSession, checkConcurrentSessions]);

  // Set session timeout
  const setSessionTimeout = useCallback((minutes: number) => {
    setSessionState(prev => ({ ...prev, sessionTimeout: minutes }));
    logSecurityEvent('session_timeout_updated', { newTimeout: minutes, previous: sessionState.sessionTimeout }, 'low');
  }, [logSecurityEvent]);

  return {
    sessionState,
    updateActivity,
    checkSessionTimeout,
    refreshSession,
    checkConcurrentSessions,
    setSessionTimeout,
    deviceFingerprint: sessionState.deviceFingerprint,
    isSessionValid: sessionState.isSessionValid,
    logSecurityEvent
  };
};