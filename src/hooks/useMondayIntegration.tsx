import { useState, useEffect } from 'react';
import { useOrganization } from './useOrganization';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from './use-toast';

interface MondayConfig {
  id: string;
  workspace_id: string;
  board_mappings: {
    security_findings?: string;
    remediation_pipeline?: string;
    compliance_tracking?: string;
    asset_inventory?: string;
    mvp_development?: string;
    product_roadmap?: string;
    onboarding_journey?: string;
  };
  sync_preferences: {
    sync_frequency: string;
    auto_create_items: boolean;
    bidirectional_sync: boolean;
    sync_comments: boolean;
  };
  is_active: boolean;
  last_sync_at?: string;
}

interface SyncHistory {
  id: string;
  sync_type: string;
  entity_type: string;
  operation: string;
  status: string;
  created_at: string;
  error_message?: string;
}

export const useMondayIntegration = () => {
  const { currentOrganization } = useOrganization();
  const { toast } = useToast();
  const [config, setConfig] = useState<MondayConfig | null>(null);
  const [syncHistory, setSyncHistory] = useState<SyncHistory[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);

  useEffect(() => {
    if (currentOrganization?.id) {
      fetchConfig();
      fetchSyncHistory();
    }
  }, [currentOrganization?.id]);

  const fetchConfig = async () => {
    if (!currentOrganization?.id) return;

    try {
      const { data, error } = await supabase
        .from('monday_integration_config')
        .select('*')
        .eq('organization_id', currentOrganization.id)
        .maybeSingle();

      if (error && error.code !== 'PGRST116') throw error;
      if (data) {
        setConfig({
          ...data,
          board_mappings: data.board_mappings as MondayConfig['board_mappings'],
          sync_preferences: data.sync_preferences as MondayConfig['sync_preferences'],
        });
      }
    } catch (error: any) {
      console.error('Error fetching Monday.com config:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const fetchSyncHistory = async () => {
    if (!currentOrganization?.id) return;

    try {
      const { data, error } = await supabase
        .from('monday_sync_history')
        .select('*')
        .eq('organization_id', currentOrganization.id)
        .order('created_at', { ascending: false })
        .limit(50);

      if (error) throw error;
      setSyncHistory(data || []);
    } catch (error: any) {
      console.error('Error fetching sync history:', error);
    }
  };

  const saveConfig = async (newConfig: Partial<MondayConfig>) => {
    if (!currentOrganization?.id) return;

    try {
      const { data, error } = await supabase
        .from('monday_integration_config')
        .upsert([{
          organization_id: currentOrganization.id,
          workspace_id: newConfig.workspace_id || '',
          board_mappings: newConfig.board_mappings || {},
          sync_preferences: newConfig.sync_preferences || {},
          is_active: newConfig.is_active ?? false,
          api_token_hash: 'managed_by_secrets',
          updated_at: new Date().toISOString(),
        }])
        .select()
        .single();

      if (error) throw error;

      if (data) {
        setConfig({
          ...data,
          board_mappings: data.board_mappings as MondayConfig['board_mappings'],
          sync_preferences: data.sync_preferences as MondayConfig['sync_preferences'],
        });
      }
      
      toast({
        title: 'Configuration Saved',
        description: 'Monday.com integration settings updated successfully',
      });
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message,
        variant: 'destructive',
      });
    }
  };

  const syncEntity = async (
    entityType: 'finding' | 'task' | 'asset' | 'feature',
    entityId: string,
    entityData: any
  ) => {
    if (!currentOrganization?.id || !config?.is_active) {
      toast({
        title: 'Integration Not Active',
        description: 'Please configure Monday.com integration first',
        variant: 'destructive',
      });
      return;
    }

    setIsSyncing(true);
    try {
      const { data, error } = await supabase.functions.invoke('monday-sync', {
        body: {
          organizationId: currentOrganization.id,
          operation: 'create',
          entityType,
          entityId,
          entityData,
        },
      });

      if (error) throw error;

      toast({
        title: 'Synced to Monday.com',
        description: `${entityType} successfully synced`,
      });

      await fetchSyncHistory();
    } catch (error: any) {
      toast({
        title: 'Sync Failed',
        description: error.message,
        variant: 'destructive',
      });
    } finally {
      setIsSyncing(false);
    }
  };

  const syncAll = async () => {
    if (!currentOrganization?.id || !config?.is_active) return;

    setIsSyncing(true);
    try {
      const { data, error } = await supabase.functions.invoke('monday-sync', {
        body: {
          organizationId: currentOrganization.id,
          operation: 'sync_all',
          entityType: 'finding',
        },
      });

      if (error) throw error;

      toast({
        title: 'Bulk Sync Complete',
        description: `Synced ${data.synced} items, ${data.failed} failed`,
      });

      await fetchSyncHistory();
    } catch (error: any) {
      toast({
        title: 'Bulk Sync Failed',
        description: error.message,
        variant: 'destructive',
      });
    } finally {
      setIsSyncing(false);
    }
  };

  const toggleIntegration = async (active: boolean) => {
    await saveConfig({ is_active: active });
  };

  return {
    config,
    syncHistory,
    isLoading,
    isSyncing,
    saveConfig,
    syncEntity,
    syncAll,
    toggleIntegration,
    isConfigured: !!config,
    isActive: config?.is_active || false,
  };
};
