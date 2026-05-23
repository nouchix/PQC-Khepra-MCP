import { useState, useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';
import { useOrganization } from '@/hooks/useOrganization';
import { useToast } from '@/hooks/use-toast';

export interface IntegrationLibraryItem {
  id: string;
  name: string;
  provider: string;
  category: 'SIEM' | 'FIREWALL' | 'ENDPOINT' | 'IDENTITY' | 'CLOUD' | 'COMPLIANCE' | 'NETWORK' | 'VULNERABILITY' | 'CUSTOM';
  description: string;
  logo_url?: string;
  documentation_url?: string;
  auth_type: 'oauth2' | 'api_key' | 'basic' | 'certificate' | 'manual';
  required_fields: string[];
  supported_data_types: string[];
  is_popular: boolean;
  is_dod_approved: boolean;
  compliance_standards: string[];
}

export interface UserIntegration {
  id: string;
  user_id: string;
  organization_id: string;
  integration_id: string;
  name: string;
  status: 'connected' | 'disconnected' | 'pending' | 'error' | 'secure_ticket_required';
  config: Record<string, any>;
  last_sync?: string;
  sync_frequency: 'realtime' | 'hourly' | 'daily' | 'weekly' | 'manual';
  health_status: 'healthy' | 'warning' | 'critical' | 'unknown';
  error_message?: string;
  created_at: string;
  updated_at: string;
  integration_library?: IntegrationLibraryItem;
}

export interface IntegrationTicket {
  id: string;
  user_id: string;
  organization_id: string;
  integration_id: string;
  ticket_type: 'new_integration' | 'configuration_change' | 'disconnect' | 'troubleshooting';
  status: 'pending' | 'in_progress' | 'approved' | 'rejected' | 'completed';
  priority: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  justification?: string;
  requested_config: Record<string, any>;
  created_at: string;
  integration_library?: IntegrationLibraryItem;
}

export const useIndustryIntegrations = () => {
  const [library, setLibrary] = useState<IntegrationLibraryItem[]>([]);
  const [userIntegrations, setUserIntegrations] = useState<UserIntegration[]>([]);
  const [tickets, setTickets] = useState<IntegrationTicket[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  const { user } = useAuth();
  const { currentOrganization } = useOrganization();
  const { toast } = useToast();

  // Load integration library
  const loadLibrary = async () => {
    try {
      const { data, error } = await supabase
        .from('integrations_library')
        .select('*')
        .order('is_popular', { ascending: false })
        .order('name');
      
      if (error) throw error;
      setLibrary((data || []) as IntegrationLibraryItem[]);
    } catch (err: any) {
      setError(err.message);
    }
  };

  // Load user integrations
  const loadUserIntegrations = async () => {
    if (!user || !currentOrganization) return;
    
    try {
      const { data, error } = await supabase
        .from('user_integrations')
        .select(`
          *,
          integration_library:integrations_library(*)
        `)
        .eq('organization_id', currentOrganization.id)
        .order('created_at', { ascending: false });
      
      if (error) throw error;
      setUserIntegrations((data || []) as UserIntegration[]);
    } catch (err: any) {
      setError(err.message);
    }
  };

  // Load integration tickets
  const loadTickets = async () => {
    if (!user || !currentOrganization) return;
    
    try {
      const { data, error } = await supabase
        .from('integration_tickets')
        .select(`
          *,
          integration_library:integrations_library(*)
        `)
        .eq('organization_id', currentOrganization.id)
        .order('created_at', { ascending: false });
      
      if (error) throw error;
      setTickets((data || []) as IntegrationTicket[]);
    } catch (err: any) {
      setError(err.message);
    }
  };

  // Connect integration
  const connectIntegration = async (
    integrationLibraryItem: IntegrationLibraryItem,
    config: Record<string, string>,
    isDoDUser: boolean = false
  ) => {
    if (!user || !currentOrganization) {
      throw new Error('User or organization not available');
    }

    try {
      // For DoD users, create a secure ticket instead of direct connection
      if (isDoDUser || integrationLibraryItem.is_dod_approved) {
        const { data: ticket, error: ticketError } = await supabase
          .from('integration_tickets')
          .insert({
            user_id: user.id,
            organization_id: currentOrganization.id,
            integration_id: integrationLibraryItem.id,
            ticket_type: 'new_integration',
            title: `Request: Connect ${integrationLibraryItem.name}`,
            description: `User requests connection to ${integrationLibraryItem.name} (${integrationLibraryItem.provider})`,
            justification: `Business requirement for ${integrationLibraryItem.category} capability`,
            requested_config: config,
            priority: 'medium'
          })
          .select()
          .single();

        if (ticketError) throw ticketError;

        toast({
          title: "Secure Ticket Created",
          description: `Your request to connect ${integrationLibraryItem.name} has been submitted for approval.`,
        });

        await loadTickets();
        return { success: true, ticket_id: ticket.id };
      }

      // For regular users, create direct connection
      const { data: integration, error: integrationError } = await supabase
        .from('user_integrations')
        .insert({
          user_id: user.id,
          organization_id: currentOrganization.id,
          integration_id: integrationLibraryItem.id,
          name: integrationLibraryItem.name,
          status: 'pending',
          config: config,
          sync_frequency: 'hourly',
          created_by: user.id
        })
        .select()
        .single();

      if (integrationError) throw integrationError;

      // Test connection using integration manager
      try {
        const { data: testResult } = await supabase.functions.invoke('integration-manager', {
          body: {
            action: 'test',
            integration_type: integrationLibraryItem.provider.toLowerCase().replace(/\s+/g, '-'),
            config: config,
            integration_id: integration.id
          }
        });

        // Update status based on test result
        const newStatus = testResult?.success ? 'connected' : 'error';
        await supabase
          .from('user_integrations')
          .update({ 
            status: newStatus,
            error_message: testResult?.success ? null : testResult?.error,
            last_sync: testResult?.success ? new Date().toISOString() : null
          })
          .eq('id', integration.id);

      } catch (testError) {
        console.warn('Connection test failed:', testError);
        await supabase
          .from('user_integrations')
          .update({ 
            status: 'error',
            error_message: 'Connection test failed'
          })
          .eq('id', integration.id);
      }

      await loadUserIntegrations();
      return { success: true, integration_id: integration.id };

    } catch (err: any) {
      throw new Error(err.message);
    }
  };

  // Disconnect integration
  const disconnectIntegration = async (integrationId: string) => {
    try {
      const { error } = await supabase
        .from('user_integrations')
        .update({ status: 'disconnected' })
        .eq('id', integrationId);

      if (error) throw error;

      toast({
        title: "Integration Disconnected",
        description: "The integration has been disconnected successfully.",
      });

      await loadUserIntegrations();
      return { success: true };
    } catch (err: any) {
      throw new Error(err.message);
    }
  };

  // Test connection
  const testConnection = async (integrationId: string) => {
    try {
      const integration = userIntegrations.find(i => i.id === integrationId);
      if (!integration) throw new Error('Integration not found');

      // Update status to pending
      await supabase
        .from('user_integrations')
        .update({ status: 'pending' })
        .eq('id', integrationId);

      // Test using integration manager
      const { data: testResult } = await supabase.functions.invoke('integration-manager', {
        body: {
          action: 'test',
          integration_type: integration.integration_library?.provider.toLowerCase().replace(/\s+/g, '-') || 'generic',
          config: integration.config,
          integration_id: integrationId
        }
      });

      // Update status based on result
      const newStatus = testResult?.success ? 'connected' : 'error';
      await supabase
        .from('user_integrations')
        .update({ 
          status: newStatus,
          error_message: testResult?.success ? null : testResult?.error,
          last_sync: testResult?.success ? new Date().toISOString() : null
        })
        .eq('id', integrationId);

      await loadUserIntegrations();
      return { success: testResult?.success, error: testResult?.error };
    } catch (err: any) {
      throw new Error(err.message);
    }
  };

  // Initialize
  useEffect(() => {
    const initialize = async () => {
      setLoading(true);
      await Promise.all([
        loadLibrary(),
        loadUserIntegrations(),
        loadTickets()
      ]);
      setLoading(false);
    };

    initialize();
  }, [user, currentOrganization]);

  return {
    library,
    userIntegrations,
    tickets,
    loading,
    error,
    connectIntegration,
    disconnectIntegration,
    testConnection,
    refetch: async () => {
      await Promise.all([
        loadLibrary(),
        loadUserIntegrations(),
        loadTickets()
      ]);
    }
  };
};