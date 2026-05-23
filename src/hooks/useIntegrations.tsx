import { useState, useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';

export interface Integration {
  id: string;
  name: string;
  type: 'SIEM' | 'FIREWALL' | 'ENDPOINT' | 'IDENTITY' | 'CLOUD' | 'CUSTOM';
  status: 'CONNECTED' | 'DISCONNECTED' | 'ERROR' | 'PENDING';
  description: string;
  endpoint_url?: string;
  api_key_configured: boolean;
  last_sync?: string;
  sync_frequency: 'REALTIME' | 'HOURLY' | 'DAILY';
  data_types: string[];
  created_at: string;
  updated_at: string;
}

export interface IntegrationTemplate {
  id: string;
  name: string;
  type: Integration['type'];
  description: string;
  logo_url: string;
  documentation_url: string;
  required_fields: string[];
  supported_data_types: string[];
  is_popular: boolean;
}

export const useIntegrations = () => {
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [templates, setTemplates] = useState<IntegrationTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [error] = useState<string | null>(null);

  // Safely get user with error handling - use demo mode if auth fails
  let user = null;
  let isDemo = false;
  try {
    const authHook = useAuth();
    user = authHook.user;
  } catch (e) {
    console.warn('Auth provider not available, using demo mode');
    isDemo = true;
  }

  // Integration templates catalog
  const integrationCatalog: IntegrationTemplate[] = [
    {
      id: 'splunk',
      name: 'Splunk SIEM',
      type: 'SIEM',
      description: 'Enterprise SIEM platform for security monitoring and analytics',
      logo_url: '/api/placeholder/64/64',
      documentation_url: 'https://docs.splunk.com/Documentation/Splunk/latest/RESTAPI',
      required_fields: ['endpoint_url', 'username', 'password'],
      supported_data_types: ['logs', 'alerts', 'incidents', 'threats'],
      is_popular: true
    },
    {
      id: 'elastic',
      name: 'Elastic Stack (ELK)',
      type: 'SIEM',
      description: 'Elasticsearch-based SIEM with API key authentication',
      logo_url: '/api/placeholder/64/64',
      documentation_url: 'https://www.elastic.co/docs/api/doc/elasticsearch/',
      required_fields: ['elasticsearch_url', 'api_key', 'api_key_id'],
      supported_data_types: ['logs', 'alerts', 'incidents', 'metrics', 'threats'],
      is_popular: true
    },
    {
      id: 'palo-alto',
      name: 'Palo Alto Networks',
      type: 'FIREWALL',
      description: 'Next-generation firewall and security platform',
      logo_url: '/api/placeholder/64/64',
      documentation_url: 'https://docs.paloaltonetworks.com/pan-os/9-1/pan-os-panorama-api',
      required_fields: ['endpoint_url', 'api_key'],
      supported_data_types: ['firewall_logs', 'threat_intel', 'policies'],
      is_popular: true
    },
    {
      id: 'crowdstrike',
      name: 'CrowdStrike Falcon',
      type: 'ENDPOINT',
      description: 'Cloud-native endpoint protection platform',
      logo_url: '/api/placeholder/64/64',
      documentation_url: 'https://falcon.crowdstrike.com/documentation',
      required_fields: ['client_id', 'client_secret'],
      supported_data_types: ['endpoint_detections', 'incidents', 'iocs'],
      is_popular: true
    },
    {
      id: 'okta',
      name: 'Okta Identity',
      type: 'IDENTITY',
      description: 'Identity and access management platform',
      logo_url: '/api/placeholder/64/64',
      documentation_url: 'https://developer.okta.com/docs/reference/',
      required_fields: ['domain', 'api_token'],
      supported_data_types: ['auth_logs', 'user_events', 'policies'],
      is_popular: true
    },
    {
      id: 'aws-security',
      name: 'AWS Security Hub',
      type: 'CLOUD',
      description: 'Centralized security findings aggregation service',
      logo_url: '/api/placeholder/64/64',
      documentation_url: 'https://docs.aws.amazon.com/securityhub/latest/APIReference/',
      required_fields: ['access_key_id', 'secret_access_key', 'region'],
      supported_data_types: ['findings', 'insights', 'compliance'],
      is_popular: true
    },
    {
      id: 'microsoft-sentinel',
      name: 'Microsoft Sentinel',
      type: 'SIEM',
      description: 'Cloud-native SIEM and SOAR solution',
      logo_url: '/api/placeholder/64/64',
      documentation_url: 'https://docs.microsoft.com/en-us/rest/api/securityinsights/',
      required_fields: ['tenant_id', 'client_id', 'client_secret'],
      supported_data_types: ['incidents', 'alerts', 'hunting_queries'],
      is_popular: true
    }
  ];

  // Check for configured integrations and show them as active
  const checkConfiguredIntegrations = async (): Promise<Integration[]> => {
    const configuredIntegrations: Integration[] = [];

    // Check if Splunk is configured (we have secrets for it)
    try {
      const { data: splunkTest } = await supabase.functions.invoke('siem-integration', {
        body: {
          action: 'splunk_integration',
          config: {},
          organizationId: 'current'
        }
      });

      if (splunkTest?.results?.configured) {
        configuredIntegrations.push({
          id: 'splunk-active',
          name: 'Splunk Enterprise SIEM',
          type: 'SIEM',
          status: 'CONNECTED',
          description: 'Enterprise SIEM platform for security monitoring and analytics',
          api_key_configured: true,
          last_sync: new Date().toISOString(),
          sync_frequency: 'REALTIME',
          data_types: ['logs', 'alerts', 'incidents', 'threats'],
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        });
      }
    } catch (error) {
      console.error('Splunk integration check failed:', error);
    }

    // Check if Elastic Stack is configured
    try {
      const { data: elasticTest } = await supabase.functions.invoke('siem-integration', {
        body: {
          action: 'elastic_integration',
          config: {},
          organizationId: 'current'
        }
      });

      if (elasticTest?.results?.configured) {
        configuredIntegrations.push({
          id: 'elastic-active',
          name: 'Elastic Stack (ELK) SIEM',
          type: 'SIEM',
          status: 'CONNECTED',
          description: 'Elasticsearch-based SIEM with API key authentication',
          api_key_configured: true,
          last_sync: new Date().toISOString(),
          sync_frequency: 'REALTIME',
          data_types: ['logs', 'alerts', 'incidents', 'metrics', 'threats'],
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        });
      }
    } catch (error) {
      console.error('Elastic integration check failed:', error);
    }

    console.log('🚀 Active integrations found:', configuredIntegrations.length);
    return configuredIntegrations;
  };

  const markIntegrationConnected = (integrationId: string) => {
    setIntegrations(prev => prev.map(int => int.id === integrationId ? { ...int, status: 'CONNECTED', last_sync: new Date().toISOString() } : int));
  };

  const addIntegration = async (template: IntegrationTemplate, config: Record<string, string>) => {
    try {
      // Call the appropriate integration function based on template type
      let result;

      if (template.id === 'splunk') {
        result = await supabase.functions.invoke('siem-integration', {
          body: {
            action: 'splunk_integration',
            config,
            organizationId: 'current'
          }
        });
      } else if (template.id === 'elastic') {
        result = await supabase.functions.invoke('siem-integration', {
          body: {
            action: 'elastic_integration',
            config,
            organizationId: 'current'
          }
        });
      } else {
        // For other integrations, create a local entry
        const newIntegration: Integration = {
          id: `int_${Date.now()}`,
          name: template.name,
          type: template.type,
          status: 'PENDING',
          description: template.description,
          endpoint_url: config.endpoint_url,
          api_key_configured: Boolean(config.api_key || config.client_id),
          sync_frequency: 'HOURLY',
          data_types: template.supported_data_types,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        };

        setIntegrations(prev => [newIntegration, ...prev]);

        // Simulate API call delay for non-Splunk integrations
        setTimeout(() => markIntegrationConnected(newIntegration.id), 3000);
      }

      return { success: true };
    } catch (error: any) {
      return { error: error.message };
    }
  };

  const removeIntegration = async (integrationId: string) => {
    try {
      setIntegrations(prev => prev.filter(int => int.id !== integrationId));

      // Log the action
      await (supabase.rpc as any)('log_user_action', {
        action_type: 'INTEGRATION_REMOVED',
        resource_type: 'integration',
        resource_id: integrationId,
        details: { removed_at: new Date().toISOString() }
      });

      return { success: true };
    } catch (error: any) {
      return { error: error.message };
    }
  };

  const testConnection = async (integrationId: string) => {
    try {
      // For Splunk integration, test the real connection
      if (integrationId === 'splunk-active') {
        setIntegrations(prev =>
          prev.map(int =>
            int.id === integrationId
              ? { ...int, status: 'PENDING' }
              : int
          )
        );

        const result = await supabase.functions.invoke('siem-integration', {
          body: {
            action: 'splunk_integration',
            config: {},
            organizationId: 'current'
          }
        });

        const isConnected = result.data?.results?.configured;

        setIntegrations(prev =>
          prev.map(int =>
            int.id === integrationId
              ? {
                ...int,
                status: isConnected ? 'CONNECTED' : 'ERROR',
                last_sync: new Date().toISOString()
              }
              : int
          )
        );
      } else if (integrationId === 'elastic-active') {
        // For Elastic integration, test the real connection
        setIntegrations(prev =>
          prev.map(int =>
            int.id === integrationId
              ? { ...int, status: 'PENDING' }
              : int
          )
        );

        const result = await supabase.functions.invoke('siem-integration', {
          body: {
            action: 'elastic_integration',
            config: {},
            organizationId: 'current'
          }
        });

        const isConnected = result.data?.results?.configured;

        setIntegrations(prev =>
          prev.map(int =>
            int.id === integrationId
              ? {
                ...int,
                status: isConnected ? 'CONNECTED' : 'ERROR',
                last_sync: new Date().toISOString()
              }
              : int
          )
        );
      } else {
        // For other integrations, test via integration-manager Edge Function
        setIntegrations(prev =>
          prev.map(int =>
            int.id === integrationId
              ? { ...int, status: 'PENDING' }
              : int
          )
        );

        try {
          const integration = integrations.find(i => i.id === integrationId);
          const result = await supabase.functions.invoke('integration-manager', {
            body: {
              action: 'test',
              integration_type: integration?.name?.toLowerCase().replaceAll(' ', '-') || 'generic',
              config: { endpoint_url: integration?.endpoint_url || '' },
              integration_id: integrationId
            }
          });

          const isConnected = result.data?.success === true;
          setIntegrations(prev =>
            prev.map(int =>
              int.id === integrationId
                ? {
                  ...int,
                  status: isConnected ? 'CONNECTED' : 'ERROR',
                  last_sync: new Date().toISOString()
                }
                : int
            )
          );
        } catch {
          setIntegrations(prev =>
            prev.map(int =>
              int.id === integrationId
                ? { ...int, status: 'ERROR' }
                : int
            )
          );
        }
      }

      return { success: true };
    } catch (error: any) {
      return { error: error.message };
    }
  };

  useEffect(() => {
    const loadIntegrations = async () => {
      setLoading(true);

      // Initialize with integration templates
      setTemplates(integrationCatalog);

      // Check for real configured integrations (if user is available)
      if (user) {
        const realIntegrations = await checkConfiguredIntegrations();
        setIntegrations(realIntegrations);
      } else {
        // Awaiting authentication
        setIntegrations([]);
      }

      setLoading(false);
    };

    loadIntegrations();
  }, [user, isDemo]);

  return {
    integrations,
    templates,
    loading,
    error,
    addIntegration,
    removeIntegration,
    testConnection
  };
};