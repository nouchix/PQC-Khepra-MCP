import { useState, useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';
import { UserProfile } from './useUserProfile';

export const useUserManagement = () => {
  const { toast } = useToast();
  const [users, setUsers] = useState<UserProfile[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      setLoading(true);
      const { data, error } = await supabase
        .from('profiles')
        .select('*')
        .order('created_at', { ascending: false });

      if (error) {
        console.error('Error fetching users:', error);
        toast({
          title: "Error",
          description: "Failed to fetch users",
          variant: "destructive",
        });
        return;
      }

      setUsers(data || []);
    } catch (error) {
      console.error('Error in fetchUsers:', error);
    } finally {
      setLoading(false);
    }
  };

  const updateUserProfile = async (userId: string, updates: Partial<UserProfile>) => {
    try {
      // Separate role-related updates from profile updates
      const roleUpdates: any = {};
      const profileUpdates: any = {};

      // Check if role, security_clearance, or master_admin is being updated
      if ('role' in updates) {
        roleUpdates.role = updates.role;
        delete updates.role;
      }
      if ('security_clearance' in updates) {
        roleUpdates.security_clearance = updates.security_clearance;
        delete updates.security_clearance;
      }
      if ('master_admin' in updates) {
        roleUpdates.is_master_admin = updates.master_admin;
        delete updates.master_admin;
      }

      // Update profile table (non-role fields)
      if (Object.keys(updates).length > 0) {
        const { error: profileError } = await supabase
          .from('profiles')
          .update(updates)
          .eq('user_id', userId);

        if (profileError) {
          toast({
            title: "Error",
            description: "Failed to update user profile",
            variant: "destructive",
          });
          return false;
        }
        Object.assign(profileUpdates, updates);
      }

      // Update user_roles table (role-related fields)
      if (Object.keys(roleUpdates).length > 0) {
        const { error: roleError } = await supabase
          .from('user_roles' as any)
          .update(roleUpdates)
          .eq('user_id', userId);

        if (roleError) {
          toast({
            title: "Error",
            description: "Failed to update user role",
            variant: "destructive",
          });
          return false;
        }
      }

      // Log the action
      await supabase.rpc('log_user_action', {
        action_type: 'user_profile_updated',
        resource_type: 'profile',
        resource_id: userId,
        details: { ...profileUpdates, ...roleUpdates }
      });

      // Refresh user list
      await fetchUsers();

      toast({
        title: "Success",
        description: "User profile updated successfully",
      });
      return true;
    } catch (error) {
      console.error('Error updating user profile:', error);
      toast({
        title: "Error",
        description: "Failed to update user profile",
        variant: "destructive",
      });
      return false;
    }
  };

  const createUserProfile = async (userData: {
    email: string;
    password: string;
    username?: string;
    full_name?: string;
    security_clearance?: string;
    department?: string;
    role?: string;
    master_admin?: boolean;
  }) => {
    try {
      console.log('Creating user with data:', userData);
      
      // Call the create-user edge function
      const { data, error } = await supabase.functions.invoke('create-user', {
        body: userData,
        headers: {
          Authorization: `Bearer ${(await supabase.auth.getSession()).data.session?.access_token}`,
        },
      });

      if (error) {
        console.error('Edge function error:', error);
        toast({
          title: "Error",
          description: `Failed to create user: ${error.message}`,
          variant: "destructive",
        });
        return false;
      }

      if (!data.success) {
        console.error('User creation failed:', data.error);
        toast({
          title: "Error",
          description: `Failed to create user: ${data.error}`,
          variant: "destructive",
        });
        return false;
      }

      console.log('User created successfully:', data.user_id);

      // Wait a bit and then refresh the user list
      setTimeout(async () => {
        await fetchUsers();
      }, 1000);

      toast({
        title: "Success",
        description: "User account created successfully",
      });
      return true;
    } catch (error) {
      console.error('Error creating user:', error);
      toast({
        title: "Error",
        description: "Failed to create user account",
        variant: "destructive",
      });
      return false;
    }
  };

  return {
    users,
    loading,
    fetchUsers,
    updateUserProfile,
    createUserProfile
  };
};