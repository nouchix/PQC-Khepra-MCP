import { useState, useEffect, useCallback } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from './useAuth';
import { SecurityValidator } from '@/lib/security';
import { useToast } from './use-toast';

interface SecurityThreat {
  id: string;
  type: 'privilege_escalation' | 'suspicious_login' | 'data_exfiltration' | 'unauthorized_access';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  timestamp: Date;
  metadata: Record<string, any>;
}

interface SecurityMetrics {
  failedLoginAttempts: number;
  suspiciousActivities: number;
  lastSecurityScan: Date | null;
  riskScore: number;
}

export function useAdvancedSecurityMonitor() {
  const [threats, setThreats] = useState<SecurityThreat[]>([]);
  const [metrics, setMetrics] = useState<SecurityMetrics>({
    failedLoginAttempts: 0,
    suspiciousActivities: 0,
    lastSecurityScan: null,
    riskScore: 0
  });
  const [isMonitoring, setIsMonitoring] = useState(false);
  const { user } = useAuth();
  const { toast } = useToast();

  // Rate limiter for security events
  const rateLimiter = SecurityValidator.createRateLimiter(10, 60000); // 10 requests per minute

  const logSecurityEvent = useCallback(async (
    eventType: string,
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
    details: Record<string, any>
  ) => {
    if (!user) return;

    // Apply rate limiting
    if (!rateLimiter(user.id)) {
      console.warn('Security event rate limit exceeded');
      return;
    }

    try {
      await supabase.functions.invoke('security-event-logger', {
        body: {
          event_type: eventType,
          severity,
          details: {
            ...details,
            user_agent: navigator.userAgent,
            timestamp: new Date().toISOString(),
            session_id: (await supabase.auth.getSession()).data.session?.access_token?.substring(0, 8)
          }
        }
      });
    } catch (error) {
      console.error('Failed to log security event:', error);
    }
  }, [user, rateLimiter]);

  const detectPrivilegeEscalation = useCallback(async (attemptedAction: string, targetResource: string) => {
    if (!user) return false;

    try {
      const { data: profile } = await supabase
        .from('profiles')
        .select('role, master_admin')
        .eq('user_id', user.id)
        .single();

      if (!profile) return false;

      // Check recent escalation attempts
      const { data: recentAttempts } = await supabase
        .from('audit_logs')
        .select('*')
        .eq('user_id', user.id)
        .eq('action', 'security_violation')
        .gte('created_at', new Date(Date.now() - 3600000).toISOString()) // Last hour
        .order('created_at', { ascending: false })
        .limit(5);

      if (recentAttempts && recentAttempts.length >= 3) {
        await logSecurityEvent('privilege_escalation_pattern_detected', 'HIGH', {
          attempted_action: attemptedAction,
          target_resource: targetResource,
          recent_attempts_count: recentAttempts.length,
          user_role: profile.role,
          is_master_admin: profile.master_admin
        });

        const newThreat: SecurityThreat = {
          id: `threat_${Date.now()}`,
          type: 'privilege_escalation',
          severity: 'HIGH',
          description: `Multiple privilege escalation attempts detected for user ${user.email}`,
          timestamp: new Date(),
          metadata: {
            attempted_action: attemptedAction,
            target_resource: targetResource,
            attempts_count: recentAttempts.length
          }
        };

        setThreats(prev => [newThreat, ...prev.slice(0, 9)]);
        
        toast({
          title: "Security Alert",
          description: "Suspicious privilege escalation pattern detected",
          variant: "destructive"
        });

        return true;
      }
    } catch (error) {
      console.error('Failed to detect privilege escalation:', error);
    }

    return false;
  }, [user, logSecurityEvent, toast]);

  const monitorSuspiciousActivity = useCallback(async () => {
    if (!user) return;

    try {
      // Check for unusual login patterns
      const { data: recentLogins } = await supabase
        .from('audit_logs')
        .select('*')
        .eq('user_id', user.id)
        .eq('action', 'sign_in')
        .gte('created_at', new Date(Date.now() - 86400000).toISOString()) // Last 24 hours
        .order('created_at', { ascending: false });

      if (recentLogins && recentLogins.length > 10) {
        await logSecurityEvent('unusual_login_pattern', 'MEDIUM', {
          login_count: recentLogins.length,
          time_window: '24_hours'
        });
      }

      // Check for failed authentication attempts
      const { data: failedAttempts } = await supabase
        .from('audit_logs')
        .select('*')
        .eq('action', 'authentication_failed')
        .gte('created_at', new Date(Date.now() - 3600000).toISOString()) // Last hour
        .order('created_at', { ascending: false });

      if (failedAttempts && failedAttempts.length > 5) {
        await logSecurityEvent('excessive_failed_logins', 'HIGH', {
          failed_attempts: failedAttempts.length,
          time_window: '1_hour'
        });

        const newThreat: SecurityThreat = {
          id: `threat_${Date.now()}_login`,
          type: 'suspicious_login',
          severity: 'HIGH',
          description: `Excessive failed login attempts detected`,
          timestamp: new Date(),
          metadata: {
            failed_attempts: failedAttempts.length
          }
        };

        setThreats(prev => [newThreat, ...prev.slice(0, 9)]);
      }

      // Update metrics
      setMetrics(prev => ({
        ...prev,
        failedLoginAttempts: failedAttempts?.length || 0,
        suspiciousActivities: prev.suspiciousActivities + (failedAttempts?.length > 5 ? 1 : 0),
        lastSecurityScan: new Date(),
        riskScore: Math.min(100, prev.riskScore + (failedAttempts?.length > 5 ? 10 : 0))
      }));

    } catch (error) {
      console.error('Failed to monitor suspicious activity:', error);
    }
  }, [user, logSecurityEvent]);

  const startMonitoring = useCallback(() => {
    if (!user || isMonitoring) return;

    setIsMonitoring(true);
    
    // Monitor every 5 minutes
    const interval = setInterval(() => {
      monitorSuspiciousActivity();
    }, 300000);

    // Initial scan
    monitorSuspiciousActivity();

    // Store interval in a ref to prevent re-render issues
    return interval;
  }, [user, isMonitoring, monitorSuspiciousActivity]);

  const stopMonitoring = useCallback(() => {
    setIsMonitoring(false);
  }, []);

  const validateUserAction = useCallback(async (action: string, resource: string, payload?: any) => {
    if (!user) return false;

    // Validate input
    const validationResult = SecurityValidator.validate(payload || {}, {
      action: { required: true, type: 'string', maxLength: 100 },
      resource: { required: true, type: 'string', maxLength: 100 }
    });

    if (!validationResult.isValid) {
      await logSecurityEvent('invalid_input_detected', 'MEDIUM', {
        action,
        resource,
        validation_errors: validationResult.errors
      });
      return false;
    }

    // Check for privilege escalation attempts
    const isEscalation = await detectPrivilegeEscalation(action, resource);
    if (isEscalation) {
      return false;
    }

    // Log valid action
    await logSecurityEvent('user_action_validated', 'LOW', {
      action,
      resource,
      user_id: user.id
    });

    return true;
  }, [user, logSecurityEvent, detectPrivilegeEscalation]);

  // Auto-start monitoring when user is authenticated
  useEffect(() => {
    let intervalId: NodeJS.Timeout;
    
    if (user && !isMonitoring) {
      intervalId = startMonitoring();
    }

    return () => {
      if (intervalId) {
        clearInterval(intervalId);
      }
    };
  }, [user, startMonitoring]);

  return {
    threats,
    metrics,
    isMonitoring,
    logSecurityEvent,
    detectPrivilegeEscalation,
    validateUserAction,
    startMonitoring,
    stopMonitoring
  };
}