import { useState, useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

interface SecurityEvent {
  type: 'login_attempt' | 'login_success' | 'login_failure' | 'password_change' | 'account_locked' | 'suspicious_activity';
  details: Record<string, any>;
  ip_address?: string;
  user_agent?: string;
}

interface SecurityMetrics {
  failedAttempts: number;
  lastAttempt: Date | null;
  isLocked: boolean;
  lockUntil: Date | null;
  suspiciousActivity: boolean;
}

export const useSecurityHardening = () => {
  const { toast } = useToast();
  const [securityMetrics, setSecurityMetrics] = useState<SecurityMetrics>({
    failedAttempts: 0,
    lastAttempt: null,
    isLocked: false,
    lockUntil: null,
    suspiciousActivity: false
  });

  // Enhanced rate limiting with progressive delays
  const getRateLimitDelay = (attempts: number): number => {
    const delays = [0, 1000, 2000, 5000, 10000, 30000, 60000, 300000]; // Progressive delays
    return delays[Math.min(attempts, delays.length - 1)];
  };

  // Log security events using secure audit function
  const logSecurityEvent = async (event: SecurityEvent) => {
    try {
      const { error } = await supabase.rpc('log_system_audit', {
        p_action: event.type,
        p_resource_type: 'authentication',
        p_resource_id: null,
        p_details: {
          ...event.details,
          timestamp: new Date().toISOString(),
          ip_address: event.ip_address || 'unknown',
          user_agent: event.user_agent || navigator.userAgent
        },
        p_user_id: null // Will be handled by the secure function
      });

      if (error) {
        console.error('Failed to log security event:', error);
      }
    } catch (error) {
      console.error('Error logging security event:', error);
    }
  };

  // Enhanced input validation
  const validateInput = (input: string, type: 'email' | 'password' | 'username' | 'text'): { isValid: boolean; error?: string } => {
    // Basic sanitization
    const sanitized = input.trim().replace(/[<>]/g, '');

    if (input !== sanitized) {
      return { isValid: false, error: 'Invalid characters detected' };
    }

    switch (type) {
      case 'email': {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(input)) {
          return { isValid: false, error: 'Invalid email format' };
        }
        if (input.length > 254) {
          return { isValid: false, error: 'Email too long' };
        }
        break;
      }

      case 'password':
        if (input.length < 8) {
          return { isValid: false, error: 'Password must be at least 8 characters' };
        }
        if (input.length > 128) {
          return { isValid: false, error: 'Password too long' };
        }
        if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d])/.test(input)) {
          return { isValid: false, error: 'Password must contain uppercase, lowercase, number, and special character' };
        }
        break;

      case 'username':
        if (input.length < 3 || input.length > 30) {
          return { isValid: false, error: 'Username must be 3-30 characters' };
        }
        if (!/^[a-zA-Z0-9_-]+$/.test(input)) {
          return { isValid: false, error: 'Username can only contain letters, numbers, hyphens, and underscores' };
        }
        break;

      case 'text':
        if (input.length > 1000) {
          return { isValid: false, error: 'Input too long' };
        }
        break;
    }

    return { isValid: true };
  };

  // Check for suspicious activity patterns
  const detectSuspiciousActivity = (attempts: number, timeWindow: number): boolean => {
    const suspiciousPatterns = [
      attempts > 5 && timeWindow < 60000, // More than 5 attempts in 1 minute
      attempts > 10 && timeWindow < 300000, // More than 10 attempts in 5 minutes
      attempts > 20 && timeWindow < 3600000, // More than 20 attempts in 1 hour
    ];

    return suspiciousPatterns.some(pattern => pattern);
  };

  // Enhanced authentication attempt tracking
  const trackAuthAttempt = async (success: boolean, email: string, additionalData?: Record<string, any>) => {
    const now = new Date();
    const currentMetrics = { ...securityMetrics };

    if (success) {
      // Reset on successful login
      setSecurityMetrics({
        failedAttempts: 0,
        lastAttempt: now,
        isLocked: false,
        lockUntil: null,
        suspiciousActivity: false
      });

      await logSecurityEvent({
        type: 'login_success',
        details: {
          email: email.substring(0, 3) + '***', // Obscure email for privacy
          ...additionalData
        }
      });
    } else {
      const newFailedAttempts = currentMetrics.failedAttempts + 1;
      const timeWindow = currentMetrics.lastAttempt ? now.getTime() - currentMetrics.lastAttempt.getTime() : 0;
      const isSuspicious = detectSuspiciousActivity(newFailedAttempts, timeWindow);

      // Progressive lockout
      let lockUntil: Date | null = null;
      let isLocked = false;

      if (newFailedAttempts >= 3) {
        const lockDuration = getRateLimitDelay(newFailedAttempts);
        lockUntil = new Date(now.getTime() + lockDuration);
        isLocked = true;

        await logSecurityEvent({
          type: 'account_locked',
          details: {
            email,
            attempts: newFailedAttempts,
            lockDuration,
            ...additionalData
          }
        });
      }

      if (isSuspicious) {
        await logSecurityEvent({
          type: 'suspicious_activity',
          details: {
            email,
            attempts: newFailedAttempts,
            timeWindow,
            ...additionalData
          }
        });
      }

      setSecurityMetrics({
        failedAttempts: newFailedAttempts,
        lastAttempt: now,
        isLocked,
        lockUntil,
        suspiciousActivity: isSuspicious
      });

      await logSecurityEvent({
        type: 'login_failure',
        details: {
          email: email.substring(0, 3) + '***', // Obscure email for privacy
          attempts: newFailedAttempts,
          ...additionalData
        }
      });
    }
  };

  // Check if account is currently locked
  const isAccountLocked = (): boolean => {
    if (!securityMetrics.isLocked || !securityMetrics.lockUntil) {
      return false;
    }

    const now = new Date();
    if (now > securityMetrics.lockUntil) {
      // Lock expired, reset
      setSecurityMetrics(prev => ({
        ...prev,
        isLocked: false,
        lockUntil: null
      }));
      return false;
    }

    return true;
  };

  // Get time remaining for lockout
  const getLockoutTimeRemaining = (): number => {
    if (!securityMetrics.lockUntil) return 0;
    const now = new Date();
    return Math.max(0, securityMetrics.lockUntil.getTime() - now.getTime());
  };

  // Password strength checker with enhanced rules
  const checkPasswordStrength = (password: string): {
    score: number;
    feedback: string[];
    isStrong: boolean;
  } => {
    const feedback: string[] = [];
    let score = 0;

    // Length check
    if (password.length >= 8) score += 1;
    else feedback.push('At least 8 characters');

    if (password.length >= 12) score += 1;
    else feedback.push('12+ characters for better security');

    // Character variety
    if (/[a-z]/.test(password)) score += 1;
    else feedback.push('Lowercase letter');

    if (/[A-Z]/.test(password)) score += 1;
    else feedback.push('Uppercase letter');

    if (/[0-9]/.test(password)) score += 1;
    else feedback.push('Number');

    if (/[^A-Za-z0-9]/.test(password)) score += 1;
    else feedback.push('Special character');

    // Advanced checks
    if (!/(.)\1{2,}/.test(password)) score += 1;
    else feedback.push('Avoid repeated characters');

    if (!/123|abc|qwe|password|admin/i.test(password)) score += 1;
    else feedback.push('Avoid common patterns');

    return {
      score,
      feedback,
      isStrong: score >= 6
    };
  };

  // Generate CSRF token
  const generateCSRFToken = (): string => {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  };

  // Store CSRF token in session
  const setCSRFToken = (token: string) => {
    sessionStorage.setItem('csrf_token', token);
  };

  // Verify CSRF token
  const verifyCSRFToken = (token: string): boolean => {
    const storedToken = sessionStorage.getItem('csrf_token');
    return storedToken === token;
  };

  return {
    securityMetrics,
    validateInput,
    trackAuthAttempt,
    isAccountLocked,
    getLockoutTimeRemaining,
    checkPasswordStrength,
    logSecurityEvent,
    generateCSRFToken,
    setCSRFToken,
    verifyCSRFToken
  };
};