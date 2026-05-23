import { useState, useEffect, useCallback } from 'react';
import { useAuth } from '@/hooks/useAuth';
import { useUserProfile } from '@/hooks/useUserProfile';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

export type SecurityClearanceLevel = 'UNCLASSIFIED' | 'CONFIDENTIAL' | 'SECRET' | 'TOP_SECRET';

export interface SecurityClearanceState {
  currentClearance: SecurityClearanceLevel;
  canAccess: (requiredLevel: SecurityClearanceLevel) => boolean;
  hasAccess: boolean;
  loading: boolean;
  error: string | null;
}

const CLEARANCE_HIERARCHY: Record<SecurityClearanceLevel, number> = {
  'UNCLASSIFIED': 0,
  'CONFIDENTIAL': 1,
  'SECRET': 2,
  'TOP_SECRET': 3
};

export const useSecurityClearance = (requiredLevel?: SecurityClearanceLevel) => {
  const { user } = useAuth();
  const { profile, loading: profileLoading } = useUserProfile();
  const { toast } = useToast();
  
  const [state, setState] = useState<SecurityClearanceState>({
    currentClearance: 'UNCLASSIFIED',
    canAccess: () => false,
    hasAccess: false,
    loading: true,
    error: null
  });

  const canAccess = useCallback((required: SecurityClearanceLevel): boolean => {
    if (!profile) return false;
    
    const currentLevel = (profile.security_clearance as SecurityClearanceLevel) || 'UNCLASSIFIED';
    const currentRank = CLEARANCE_HIERARCHY[currentLevel];
    const requiredRank = CLEARANCE_HIERARCHY[required];
    
    // Master admins can access everything
    if (profile.master_admin) return true;
    
    return currentRank >= requiredRank;
  }, [profile]);

  const logAccessAttempt = useCallback(async (
    resourceType: string,
    resourceId: string,
    requiredClearance: SecurityClearanceLevel,
    accessGranted: boolean
  ) => {
    try {
      await supabase.rpc('log_clearance_access', {
        resource_type: resourceType,
        resource_id: resourceId,
        required_clearance: requiredClearance,
        access_granted: accessGranted
      });
    } catch (error) {
      console.error('Failed to log access attempt:', error);
    }
  }, []);

  const requestElevatedAccess = useCallback(async (
    targetLevel: SecurityClearanceLevel,
    justification: string
  ) => {
    if (!user || !profile) {
      toast({
        title: "Error",
        description: "User not authenticated",
        variant: "destructive"
      });
      return { success: false };
    }

    try {
      // Log the elevation request
      await supabase.from('audit_logs').insert({
        user_id: user.id,
        action: 'security_clearance_elevation_request',
        resource_type: 'security_clearance',
        resource_id: profile.id,
        details: {
          current_clearance: profile.security_clearance,
          requested_clearance: targetLevel,
          justification,
          timestamp: new Date().toISOString()
        }
      });

      toast({
        title: "Request Submitted",
        description: "Your security clearance elevation request has been submitted for review",
      });

      return { success: true };
    } catch (error) {
      console.error('Failed to request elevated access:', error);
      toast({
        title: "Error",
        description: "Failed to submit elevation request",
        variant: "destructive"
      });
      return { success: false };
    }
  }, [user, profile, toast]);

  const validateSecurityAccess = useCallback(async (
    resourceType: string,
    resourceId: string,
    requiredClearance: SecurityClearanceLevel
  ): Promise<boolean> => {
    const hasAccess = canAccess(requiredClearance);
    
    // Log the access attempt
    await logAccessAttempt(resourceType, resourceId, requiredClearance, hasAccess);
    
    if (!hasAccess) {
      toast({
        title: "Access Denied",
        description: `This resource requires ${requiredClearance} clearance or higher`,
        variant: "destructive"
      });
    }
    
    return hasAccess;
  }, [canAccess, logAccessAttempt, toast]);

  useEffect(() => {
    if (profileLoading) {
      setState(prev => ({ ...prev, loading: true }));
      return;
    }

    if (!profile) {
      setState(prev => ({
        ...prev,
        loading: false,
        error: 'No profile found',
        hasAccess: false
      }));
      return;
    }

    // Use security_clearance from user_roles table (fetched in profile)
    const currentClearance = (profile.security_clearance as SecurityClearanceLevel) || 'UNCLASSIFIED';
    const hasRequiredAccess = requiredLevel ? canAccess(requiredLevel) : true;

    setState({
      currentClearance,
      canAccess,
      hasAccess: hasRequiredAccess,
      loading: false,
      error: null
    });
  }, [profile, profileLoading, requiredLevel, canAccess]);

  return {
    ...state,
    requestElevatedAccess,
    validateSecurityAccess,
    logAccessAttempt,
    CLEARANCE_HIERARCHY
  };
};