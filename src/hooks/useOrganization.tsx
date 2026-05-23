import { useState, useEffect } from 'react';
import { useAuth } from './useAuth';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

export interface Organization {
  id: string;
  name: string;
  slug: string;
  domain: string | null;
  logo_url: string | null;
  settings: any;
  subscription_tier: string;
  max_users: number;
  max_storage_gb: number;
  created_at: string;
  updated_at: string;
}

export interface UserOrganization {
  id: string;
  user_id: string;
  organization_id: string;
  role: 'owner' | 'admin' | 'member' | 'viewer';
  invited_by: string | null;
  invited_at: string | null;
  joined_at: string | null;
  created_at: string;
  organization: Organization;
}

export interface Subscription {
  id: string;
  organization_id: string;
  plan_type: string;
  status: string;
  billing_cycle: string;
  price_per_month: number | null;
  max_users: number;
  max_storage_gb: number;
  features: any;
  trial_ends_at: string | null;
  billing_period_start: string | null;
  billing_period_end: string | null;
  created_at: string;
  updated_at: string;
}

export const useOrganization = () => {
  const { user } = useAuth();
  const { toast } = useToast();
  const [organizations, setOrganizations] = useState<UserOrganization[]>([]);
  const [currentOrganization, setCurrentOrganization] = useState<UserOrganization | null>(null);
  const [subscription, setSubscription] = useState<Subscription | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (user) {
      fetchUserOrganizations();
    } else {
      setOrganizations([]);
      setCurrentOrganization(null);
      setSubscription(null);
      setLoading(false);
    }
  }, [user]);

  const handleFetchError = async (error: any) => {
    // Detailed logging for debugging
    console.warn('Organization fetch status:', { code: error.code, message: error.message, path: globalThis.location.pathname });

    // If JWT expired, sign out user - this is a critical state transition
    if (error.code === 'PGRST301') {
      await supabase.auth.signOut();
      return;
    }

    // Only show toast for unexpected errors (excluding common transition/empty states)
    if (error.code !== 'PGRST116' && error.message !== 'Unexpected token') {
      // If the error is real (e.g. connection, RLS failure), log it prominently
      console.error('Critical organization load failure:', error);

      // Suppress error toast on public landing page to prevent bad UX for unauthenticated/stale sessions
      if (globalThis.location.pathname === '/') {
        return;
      }

      // Only show toast if we are CERTAIN it's a failure and not just a new user case
      if (user?.id) {
        toast({
          title: "Synchronization Issue",
          description: "Retrying organization data sync...",
          variant: "default", // Less alarming variant
        });
      }
    }
  };

  const fetchUserOrganizations = async () => {
    try {
      setLoading(true);

      // Check if user session is still valid
      const { data: { session } } = await supabase.auth.getSession();
      if (!session) {
        // Session expired, trigger re-authentication
        await supabase.auth.signOut();
        return;
      }

      const { data, error } = await supabase
        .from('user_organizations')
        .select(`
          *,
          organization:organizations(*)
        `)
        .eq('user_id', user?.id)
        .order('created_at', { ascending: false });

      if (error) {
        await handleFetchError(error);
        return;
      }

      // Filter out entries where the joined organization data is missing (e.g. deleted or RLS restricted)
      const validUserOrgs = (data as any[] || [])
        .filter(item => item.organization && typeof item.organization === 'object')
        .map(item => item as UserOrganization);

      if (data && data.length > validUserOrgs.length) {
        console.warn(`Filtered out ${data.length - validUserOrgs.length} invalid organization entries`);
      }

      setOrganizations(validUserOrgs);

      // Set current organization (first one or previously selected)
      if (validUserOrgs.length > 0 && !currentOrganization) {
        const savedOrgId = localStorage.getItem('currentOrganizationId');
        const savedOrg = validUserOrgs.find(org => org.organization_id === savedOrgId);
        setCurrentOrganization(savedOrg || validUserOrgs[0]);
      } else if (validUserOrgs.length === 0) {
        setCurrentOrganization(null);
      }
    } catch (error) {
      console.error('Error in fetchUserOrganizations:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchSubscription = async (organizationId: string) => {
    try {
      const { data, error } = await supabase
        .from('subscriptions')
        .select('*')
        .eq('organization_id', organizationId)
        .single();

      if (error && error.code !== 'PGRST116') {
        console.error('Error fetching subscription:', error);
        return;
      }

      setSubscription(data);
    } catch (error) {
      console.error('Error in fetchSubscription:', error);
    }
  };

  const switchOrganization = async (organizationId: string) => {
    const org = organizations.find(o => o.organization_id === organizationId);
    if (org) {
      setCurrentOrganization(org);
      localStorage.setItem('currentOrganizationId', organizationId);
      await fetchSubscription(organizationId);

      // Log the action
      await supabase.rpc('log_user_action', {
        action_type: 'organization_switched',
        resource_type: 'organization',
        resource_id: organizationId,
        details: { organization_name: org.organization.name }
      });
    }
  };

  const createOrganization = async (name: string, slug: string) => {
    if (!user) return null;

    try {
      // Create organization
      const { data: orgData, error: orgError } = await supabase
        .from('organizations')
        .insert({
          name,
          slug,
          license_tier: 'trial',
          primary_contact_email: ''
        })
        .select()
        .single();

      if (orgError) {
        toast({
          title: "Error",
          description: "Failed to create organization",
          variant: "destructive",
        });
        return null;
      }

      // Add user as owner
      const { error: userOrgError } = await supabase
        .from('user_organizations')
        .insert({
          user_id: user.id,
          organization_id: orgData.id,
          role: 'owner',
          joined_at: new Date().toISOString()
        });

      if (userOrgError) {
        toast({
          title: "Error",
          description: "Failed to assign user to organization",
          variant: "destructive",
        });
        return null;
      }

      // Create default subscription
      await supabase
        .from('subscriptions')
        .insert({
          organization_id: orgData.id,
          plan_type: 'trial',
          status: 'active',
          max_users: 5,
          max_storage_gb: 10,
          trial_ends_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
        });

      toast({
        title: "Success",
        description: "Organization created successfully",
      });

      await fetchUserOrganizations();
      return orgData;
    } catch (error) {
      console.error('Error creating organization:', error);
      toast({
        title: "Error",
        description: "Failed to create organization",
        variant: "destructive",
      });
      return null;
    }
  };

  const updateOrganization = async (organizationId: string, updates: Partial<Organization>) => {
    try {
      const { error } = await supabase
        .from('organizations')
        .update(updates)
        .eq('id', organizationId);

      if (error) {
        toast({
          title: "Error",
          description: "Failed to update organization",
          variant: "destructive",
        });
        return false;
      }

      await fetchUserOrganizations();
      toast({
        title: "Success",
        description: "Organization updated successfully",
      });
      return true;
    } catch (error) {
      console.error('Error updating organization:', error);
      return false;
    }
  };

  const isOwner = () => {
    return currentOrganization?.role === 'owner';
  };

  const isAdmin = () => {
    return currentOrganization?.role === 'owner' || currentOrganization?.role === 'admin';
  };

  const canManageUsers = () => {
    return isAdmin();
  };

  const canManageSubscription = () => {
    return isOwner();
  };

  // Fetch subscription when current organization changes
  useEffect(() => {
    if (currentOrganization) {
      fetchSubscription(currentOrganization.organization_id);
    }
  }, [currentOrganization]);

  return {
    organizations,
    currentOrganization,
    subscription,
    loading,
    switchOrganization,
    createOrganization,
    updateOrganization,
    isOwner,
    isAdmin,
    canManageUsers,
    canManageSubscription,
    refetch: fetchUserOrganizations
  };
};
