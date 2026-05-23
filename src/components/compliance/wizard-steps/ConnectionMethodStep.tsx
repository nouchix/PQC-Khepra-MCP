import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { 
  Terminal, 
  Key, 
  Wifi, 
  Cable, 
  Shield, 
  Zap,
  MonitorSpeaker,
  CheckCircle,
  Loader2,
  AlertCircle
} from 'lucide-react';
import { WizardData } from '../DataSourcesWizard';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

interface ConnectionMethod {
  id: string;
  name: string;
  type: string;
  protocols: any;
  capabilities: any;
  security_level: 'high' | 'medium' | 'low';
  supported_environments: string[];
}

interface ConnectionMethodStepProps {
  data: WizardData;
  onUpdate: (updates: Partial<WizardData>) => void;
}

export const ConnectionMethodStep: React.FC<ConnectionMethodStepProps> = ({
  data,
  onUpdate
}) => {
  const [adapters, setAdapters] = useState<Record<string, ConnectionMethod[]>>({});
  const [loading, setLoading] = useState<Record<string, boolean>>({});
  const [error, setError] = useState<string | null>(null);
  const { toast } = useToast();

  // Load adapters for each environment type
  useEffect(() => {
    const loadAdaptersForEnvironments = async () => {
      for (const environmentType of data.environments) {
        if (adapters[environmentType]) continue; // Skip if already loaded
        
        setLoading(prev => ({ ...prev, [environmentType]: true }));
        
        try {
          const { data: { user } } = await supabase.auth.getUser();
          if (!user) throw new Error('User not authenticated');

          // Get user's organizations
          const { data: userOrgs } = await supabase
            .from('user_organizations')
            .select('organization_id')
            .eq('user_id', user.id)
            .limit(1)
            .single();

          const organizationId = userOrgs?.organization_id || user.id; // Fallback to user ID

          // Call polymorphic engine to get adapters for this environment type  
          const response = await supabase.functions.invoke('polymorphic-schema-engine', {
            body: {
              action: 'get_adapters',
              organizationId: organizationId,
              environmentType: environmentType
            }
          });

          if (response.error) {
            throw new Error(response.error.message);
          }

          setAdapters(prev => ({
            ...prev,
            [environmentType]: response.data?.adapters || []
          }));

        } catch (err) {
          console.error(`Error loading adapters for ${environmentType}:`, err);
          setError(`Failed to load adapters for ${environmentType}`);
          toast({
            title: "Error Loading Adapters",
            description: `Failed to load connection methods for ${environmentType}`,
            variant: "destructive"
          });
        } finally {
          setLoading(prev => ({ ...prev, [environmentType]: false }));
        }
      }
    };

    if (data.environments.length > 0) {
      loadAdaptersForEnvironments();
    }
  }, [data.environments, adapters, toast]);

  const handleMethodChange = (environmentType: string, adapterId: string) => {
    const updatedMethods = {
      ...data.connectionMethods,
      [environmentType]: adapterId
    };
    onUpdate({ connectionMethods: updatedMethods });
  };

  const getSecurityColor = (security: string) => {
    switch (security) {
      case 'high': return 'bg-green-500/10 text-green-600 border-green-500/20';
      case 'medium': return 'bg-yellow-500/10 text-yellow-600 border-yellow-500/20';
      case 'low': return 'bg-red-500/10 text-red-600 border-red-500/20';
      default: return 'bg-gray-500/10 text-gray-600 border-gray-500/20';
    }
  };

  const getAdapterIcon = (type: string) => {
    switch (type) {
      case 'ssh': return Terminal;
      case 'api': return Key;
      case 'snmp': return MonitorSpeaker;
      case 'industrial': return Zap;
      case 'container': return Cable;
      case 'agentless': return Wifi;
      default: return Shield;
    }
  };

  const getEnvironmentTitle = (envId: string) => {
    const titles: Record<string, string> = {
      'cloud-aws': 'AWS Cloud Infrastructure',
      'cloud-azure': 'Microsoft Azure',
      'cloud-gcp': 'Google Cloud Platform',
      'servers-windows': 'Windows Servers',
      'servers-linux': 'Linux Servers',
      'servers-database': 'Database Servers',
      'web-api-rest': 'REST Web APIs',
      'web-applications': 'Web Applications',
      'containers-docker': 'Docker Containers',
      'containers-k8s': 'Kubernetes Clusters',
      'industrial-plc': 'PLCs and RTUs',
      'industrial-scada': 'SCADA Systems',
      'industrial-hmi': 'HMI Systems',
      'energy-solar': 'Solar Power Systems',
      'energy-wind': 'Wind Power Systems',
      'energy-battery': 'Battery Storage Systems',
      'energy-grid': 'Grid Infrastructure',
      'network-routers': 'Routers & Switches',
      'network-security': 'Network Security Devices',
      'network-wireless': 'Wireless Infrastructure',
      'mobile-devices': 'Mobile Devices',
      'iot-sensors': 'IoT Sensors & Devices'
    };
    return titles[envId] || envId;
  };

  return (
    <div className="space-y-6">
      <div className="text-center space-y-2">
        <h3 className="text-lg font-semibold">Configure Connection Methods</h3>
        <p className="text-muted-foreground">
          Choose how the STIG-Connector Polymorphic Engine should connect to each selected environment type.
        </p>
      </div>

      {error && (
        <Card className="border-destructive/50 bg-destructive/5">
          <CardContent className="pt-6">
            <div className="flex items-center space-x-2 text-destructive">
              <AlertCircle className="h-4 w-4" />
              <span className="text-sm">{error}</span>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="space-y-6">
        {data.environments.map((environmentType) => {
          const environmentAdapters = adapters[environmentType] || [];
          const isLoading = loading[environmentType];

          return (
            <Card key={environmentType}>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2 text-base">
                  <CheckCircle className="h-4 w-4 text-primary" />
                  <span>{getEnvironmentTitle(environmentType)}</span>
                  {isLoading && <Loader2 className="h-4 w-4 animate-spin" />}
                </CardTitle>
                <CardDescription>
                  Select the connection adapter for this environment type
                </CardDescription>
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <div className="flex items-center justify-center py-8">
                    <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                    <span className="ml-2 text-muted-foreground">Loading adapters...</span>
                  </div>
                ) : environmentAdapters.length === 0 ? (
                  <div className="text-center py-8 text-muted-foreground">
                    <AlertCircle className="h-6 w-6 mx-auto mb-2" />
                    <p>No adapters available for this environment type</p>
                  </div>
                ) : (
                  <RadioGroup
                    value={data.connectionMethods[environmentType] || ''}
                    onValueChange={(value) => handleMethodChange(environmentType, value)}
                    className="space-y-3"
                  >
                    {environmentAdapters.map((adapter) => {
                      const AdapterIcon = getAdapterIcon(adapter.type);
                      return (
                        <div key={adapter.id} className="flex items-start space-x-3">
                          <RadioGroupItem value={adapter.id} id={`${environmentType}-${adapter.id}`} className="mt-1" />
                          <div className="flex-1 space-y-2">
                            <Label htmlFor={`${environmentType}-${adapter.id}`} className="cursor-pointer">
                              <div className="flex items-center justify-between">
                                <div className="flex items-center space-x-2">
                                  <AdapterIcon className="h-4 w-4" />
                                  <span className="font-medium">{adapter.name}</span>
                                </div>
                                <Badge 
                                  variant="outline"
                                  className={`text-xs ${getSecurityColor(adapter.security_level)}`}
                                >
                                  {adapter.security_level.charAt(0).toUpperCase() + adapter.security_level.slice(1)} Security
                                </Badge>
                              </div>
                              <p className="text-sm text-muted-foreground mt-1">
                                Protocols: {adapter.protocols?.protocols?.join(', ') || 'Multiple protocols supported'}
                              </p>
                            </Label>
                            <div className="flex flex-wrap gap-1">
                              {(adapter.capabilities || []).slice(0, 3).map((capability: string, index: number) => (
                                <Badge key={index} variant="secondary" className="text-xs">
                                  {capability.replace(/_/g, ' ')}
                                </Badge>
                              ))}
                              {adapter.capabilities && adapter.capabilities.length > 3 && (
                                <Badge variant="secondary" className="text-xs">
                                  +{adapter.capabilities.length - 3} more
                                </Badge>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </RadioGroup>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>

      {Object.keys(data.connectionMethods).length > 0 && (
        <Card className="bg-primary/5 border-primary/20">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <Shield className="h-5 w-5 text-primary" />
                <div>
                  <h4 className="font-medium">
                    Connection adapters configured for {Object.keys(data.connectionMethods).length} environment types
                  </h4>
                  <p className="text-sm text-muted-foreground">
                    Polymorphic Engine will use these adapters to discover and connect to your infrastructure.
                  </p>
                </div>
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  // Refresh adapters
                  setAdapters({});
                  setError(null);
                }}
              >
                Refresh Adapters
              </Button>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};