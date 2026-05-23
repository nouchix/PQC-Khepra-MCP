import { useState } from 'react';
import { useAuth } from './useAuth';
import { useUserProfile } from './useUserProfile';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

export interface UserTierInfo {
  user_id: string;
  email: string;
  username?: string;
  full_name?: string;
  role?: string;
  plan_type?: string;
  is_trial_active?: boolean;
  trial_ends_at?: string;
}

export const useUserTierManagement = () => {
  const { user } = useAuth();
  const { profile } = useUserProfile();
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);

  const isMasterAdmin = () => {
    return profile?.master_admin === true || user?.email === 'apollo6972@proton.me';
  };

  const switchUserTier = async (targetUserId: string, newTier: string) => {
    if (!isMasterAdmin()) {
      toast({
        title: "Access Denied",
        description: "Only the Master Admin can switch user tiers",
        variant: "destructive",
      });
      return false;
    }

    try {
      setLoading(true);

      // Update user's plan type and trial status
      const updates: any = {
        plan_type: newTier
      };

      // Set trial status based on tier
      if (newTier === 'trial') {
        updates.is_trial_active = true;
        updates.trial_ends_at = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString(); // 14 days from now
      } else {
        updates.is_trial_active = false;
        updates.trial_ends_at = null;
      }

      const { error } = await supabase
        .from('profiles')
        .update(updates)
        .eq('user_id', targetUserId);

      if (error) {
        toast({
          title: "Error",
          description: "Failed to update user tier",
          variant: "destructive",
        });
        return false;
      }

      // Log the tier change action
      await supabase.rpc('log_user_action', {
        action_type: 'tier_changed',
        resource_type: 'user_profile',
        resource_id: targetUserId,
        details: { new_tier: newTier, changed_by: user?.id }
      });

      toast({
        title: "Success",
        description: `User tier updated to ${newTier}`,
      });
      return true;
    } catch (error) {
      console.error('Error switching user tier:', error);
      toast({
        title: "Error",
        description: "Failed to update user tier",
        variant: "destructive",
      });
      return false;
    } finally {
      setLoading(false);
    }
  };

  const getAllUsers = async (): Promise<UserTierInfo[]> => {
    if (!isMasterAdmin()) return [];

    try {
      const { data, error } = await supabase
        .from('profiles')
        .select(`
          user_id,
          username,
          full_name,
          role,
          plan_type,
          is_trial_active,
          trial_ends_at
        `);

      if (error) {
        console.error('Error fetching users:', error);
        return [];
      }

      // Get email addresses from auth.users (we need to use a function for this)
      const usersWithEmails = await Promise.all(
        (data || []).map(async (profile) => {
          try {
            // This would need to be implemented as a database function since we can't access auth.users directly
            return {
              ...profile,
              email: 'email_not_available' // Placeholder - would need to implement auth user lookup
            } as UserTierInfo;
          } catch {
            return {
              ...profile,
              email: 'email_not_available'
            } as UserTierInfo;
          }
        })
      );

      return usersWithEmails;
    } catch (error) {
      console.error('Error in getAllUsers:', error);
      return [];
    }
  };

  return {
    isMasterAdmin: isMasterAdmin(),
    switchUserTier,
    getAllUsers,
    loading
  };
};