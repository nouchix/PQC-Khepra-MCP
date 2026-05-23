import { useState, useEffect, useCallback } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';
import { useOrganization } from '@/hooks/useOrganization';
import { useToast } from '@/hooks/use-toast';

export interface DeploymentConfig {
    deploymentUrl: string;
    apiKey: string;
    organizationName: string;
    integrationId?: string;
}

export const useKhepraDeployment = () => {
    useAuth(); // auth context required for Supabase RLS
    const { currentOrganization } = useOrganization();
    const { toast } = useToast();

    const [config, setConfig] = useState<DeploymentConfig | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [isUpdating, setIsUpdating] = useState(false);

    const fetchConfig = useCallback(async () => {
        if (!currentOrganization) return;

        setIsLoading(true);
        try {
            const { data, error } = await supabase
                .from('enhanced_open_controls_integrations')
                .select('id, api_endpoint, performance_metrics, integration_name')
                .eq('organization_id', currentOrganization.id)
                .eq('integration_name', 'Khepra VPS Deployment')
                .maybeSingle();

            if (error) throw error;

            if (data) {
                const metrics = data.performance_metrics as any;
                setConfig({
                    deploymentUrl: data.api_endpoint || 'http://localhost:8080',
                    apiKey: metrics?.api_key || '',
                    organizationName: data.integration_name,
                    integrationId: data.id
                });
            } else {
                // Look for any existing Khepra integration if the specific name doesn't match
                const { data: genericData } = await supabase
                    .from('enhanced_open_controls_integrations')
                    .select('id, api_endpoint, performance_metrics, integration_name')
                    .eq('organization_id', currentOrganization.id)
                    .ilike('integration_name', '%Khepra%')
                    .maybeSingle();

                if (genericData) {
                    const metrics = genericData.performance_metrics as any;
                    setConfig({
                        deploymentUrl: genericData.api_endpoint || 'http://localhost:8080',
                        apiKey: metrics?.api_key || '',
                        organizationName: genericData.integration_name,
                        integrationId: genericData.id
                    });
                }
            }
        } catch (error) {
            console.error('Error fetching Khepra deployment config:', error);
        } finally {
            setIsLoading(false);
        }
    }, [currentOrganization]);

    const updateConfig = async (newConfig: Partial<DeploymentConfig>) => {
        if (!currentOrganization) return;

        setIsUpdating(true);
        try {
            const payload = {
                organization_id: currentOrganization.id,
                integration_name: 'Khepra VPS Deployment',
                api_endpoint: newConfig.deploymentUrl || config?.deploymentUrl,
                performance_metrics: {
                    api_key: newConfig.apiKey || config?.apiKey,
                    last_updated: new Date().toISOString()
                }
            };

            let result;
            if (config?.integrationId) {
                result = await supabase
                    .from('enhanced_open_controls_integrations')
                    .update(payload)
                    .eq('id', config.integrationId);
            } else {
                result = await supabase
                    .from('enhanced_open_controls_integrations')
                    .insert(payload);
            }

            if (result.error) throw result.error;

            toast({
                title: "Deployment Updated",
                description: "Khepra environment connection settings have been saved.",
            });

            await fetchConfig();
        } catch (error: any) {
            toast({
                title: "Update Failed",
                description: error.message,
                variant: "destructive"
            });
        } finally {
            setIsUpdating(false);
        }
    };

    useEffect(() => {
        fetchConfig();
    }, [fetchConfig]);

    return {
        config,
        isLoading,
        isUpdating,
        updateConfig,
        refresh: fetchConfig
    };
};
