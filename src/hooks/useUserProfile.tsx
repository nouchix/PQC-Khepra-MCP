import { useState, useEffect } from 'react';
import { useAuth } from './useAuth';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

export interface UserProfile {
  id: string;
  user_id: string;
  username: string | null;
  full_name: string | null;
  department: string | null;
  trial_starts_at: string | null;
  trial_ends_at: string | null;
  is_trial_active: boolean | null;
  plan_type: string | null;
  created_at: string;
  updated_at: string;
  // Role data from user_roles table
  role?: string | null;
  security_clearance?: string | null;
  master_admin?: boolean | null;
}

export const useUserProfile = () => {
  const { user } = useAuth();
  const { toast } = useToast();
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (user) {
      fetchProfile();
    } else {
      setProfile(null);
      setLoading(false);
    }
  }, [user]);

  const fetchProfile = async () => {
    try {
      setLoading(true);
      
      // Fetch profile data
      const { data: profileData, error: profileError } = await supabase
        .from('profiles')
        .select('*')
        .eq('user_id', user?.id)
        .single();

      if (profileError) {
        console.error('Error fetching profile:', profileError);
        setLoading(false);
        return;
      }

      // Fetch role data from user_roles table
      const { data: roleData, error: roleError } = await supabase
        .from('user_roles' as any)
        .select('role, security_clearance, is_master_admin')
        .eq('user_id', user?.id)
        .maybeSingle();

      if (roleError) {
        console.error('Error fetching role:', roleError);
      }

      // Combine profile and role data
      const combinedProfile: any = {
        ...profileData,
        role: (roleData as any)?.role || 'viewer',
        security_clearance: (roleData as any)?.security_clearance || 'UNCLASSIFIED',
        master_admin: (roleData as any)?.is_master_admin || false
      };
      
      setProfile(combinedProfile);
    } catch (error) {
      console.error('Error in fetchProfile:', error);
    } finally {
      setLoading(false);
    }
  };

  const updateProfile = async (updates: Partial<UserProfile>) => {
    if (!user || !profile) return;

    try {
      const { error } = await supabase
        .from('profiles')
        .update(updates)
        .eq('user_id', user.id);

      if (error) {
        toast({
          title: "Error",
          description: "Failed to update profile",
          variant: "destructive",
        });
        return;
      }

      // Log the action
      await supabase.rpc('log_user_action', {
        action_type: 'profile_updated',
        resource_type: 'profile',
        resource_id: profile.id,
        details: updates
      });

      setProfile({ ...profile, ...updates });
      toast({
        title: "Success",
        description: "Profile updated successfully",
      });
    } catch (error) {
      console.error('Error updating profile:', error);
      toast({
        title: "Error",
        description: "Failed to update profile",
        variant: "destructive",
      });
    }
  };

  const isAdmin = () => {
    return profile?.role === 'admin' || profile?.master_admin === true;
  };

  const canViewAllUsers = () => {
    return isAdmin();
  };

  const canManageUsers = () => {
    return isAdmin();
  };

  return {
    profile,
    loading,
    updateProfile,
    isAdmin,
    canViewAllUsers,
    canManageUsers,
    refetch: fetchProfile
  };
};