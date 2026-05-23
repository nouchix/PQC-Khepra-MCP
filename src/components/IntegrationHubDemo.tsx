import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Plug, Plus, Settings, AlertCircle, CheckCircle, 
  Clock, Trash2, TestTube, Link, Zap, Shield,
  Cloud, Monitor, UserCheck, RefreshCw, ExternalLink
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { useToast } from '@/hooks/use-toast';

interface DemoIntegration {
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

interface DemoTemplate {
  id: string;
  name: string;
  type: 'SIEM' | 'FIREWALL' | 'ENDPOINT' | 'IDENTITY' | 'CLOUD' | 'CUSTOM';
  description: string;
  logo_url: string;
  documentation_url: string;
  required_fields: string[];
  supported_data_types: string[];
  is_popular: boolean;
}

export const IntegrationHubDemo = () => {
  const [integrations, setIntegrations] = useState<DemoIntegration[]>([]);
  const [templates] = useState<DemoTemplate[]>([
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
    }
  ]);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  useEffect(() => {
    // Simulate loading demo integrations
    const loadDemo = async () => {
      setLoading(true);
      
      // Simulate API delay
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      setIntegrations([
        {
          id: 'demo-splunk',
          name: 'Splunk Enterprise SIEM',
          type: 'SIEM',
          status: 'CONNECTED',
          description: 'Enterprise SIEM platform for security monitoring and analytics',
          api_key_configured: true,
          last_sync: new Date(Date.now() - 1000 * 60 * 5).toISOString(), // 5 minutes ago
          sync_frequency: 'REALTIME',
          data_types: ['logs', 'alerts', 'incidents', 'threats'],
          created_at: new Date(Date.now() - 1000 * 60 * 60 * 24 * 7).toISOString(), // 1 week ago
          updated_at: new Date().toISOString()
        },
        {
          id: 'demo-elastic',
          name: 'Elastic Stack SIEM',
          type: 'SIEM',
          status: 'CONNECTED',
          description: 'Elasticsearch-based SIEM with API key authentication',
          api_key_configured: true,
          last_sync: new Date(Date.now() - 1000 * 60 * 2).toISOString(), // 2 minutes ago
          sync_frequency: 'REALTIME',
          data_types: ['logs', 'alerts', 'incidents', 'metrics'],
          created_at: new Date(Date.now() - 1000 * 60 * 60 * 24 * 3).toISOString(), // 3 days ago
          updated_at: new Date().toISOString()
        },
        {
          id: 'demo-palo-alto',
          name: 'Palo Alto Firewall',
          type: 'FIREWALL',
          status: 'PENDING',
          description: 'Next-generation firewall and security platform',
          api_key_configured: true,
          sync_frequency: 'HOURLY',
          data_types: ['firewall_logs', 'threat_intel'],
          created_at: new Date(Date.now() - 1000 * 60 * 30).toISOString(), // 30 minutes ago
          updated_at: new Date().toISOString()
        }
      ]);
      
      setLoading(false);
    };

    loadDemo();
  }, []);

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'SIEM': return <Shield className="h-5 w-5" />;
      case 'FIREWALL': return <Zap className="h-5 w-5" />;
      case 'ENDPOINT': return <Monitor className="h-5 w-5" />;
      case 'IDENTITY': return <UserCheck className="h-5 w-5" />;
      case 'CLOUD': return <Cloud className="h-5 w-5" />;
      default: return <Plug className="h-5 w-5" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'CONNECTED': return 'bg-success text-success-foreground';
      case 'DISCONNECTED': return 'bg-muted text-muted-foreground';
      case 'ERROR': return 'bg-destructive text-destructive-foreground';
      case 'PENDING': return 'bg-warning text-warning-foreground';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'CONNECTED': return <CheckCircle className="h-4 w-4" />;
      case 'DISCONNECTED': return <AlertCircle className="h-4 w-4" />;
      case 'ERROR': return <AlertCircle className="h-4 w-4" />;
      case 'PENDING': return <Clock className="h-4 w-4" />;
      default: return <AlertCircle className="h-4 w-4" />;
    }
  };

  const handleTestConnection = (integrationId: string) => {
    toast({
      title: "Testing Connection",
      description: "Demo: Connection test successful!",
    });
  };

  const handleAddIntegration = (templateId: string) => {
    toast({
      title: "Demo Mode",
      description: "Integration would be configured in full version.",
    });
  };

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h2 className="text-2xl font-bold">Integration Hub</h2>
          <RefreshCw className="h-4 w-4 animate-spin" />
        </div>
        <div className="text-center py-12">
          <div className="text-lg">Loading integrations...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">Integration Hub</h2>
          <p className="text-muted-foreground">Connect and manage your security tools</p>
        </div>
        <Badge variant="outline" className="bg-blue-500/10 text-blue-400 border-blue-500/20">
          DEMO MODE
        </Badge>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-lg">Active Integrations</CardTitle>
              <CheckCircle className="h-5 w-5 text-success" />
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{integrations.filter(i => i.status === 'CONNECTED').length}</div>
            <p className="text-sm text-muted-foreground">Connected and operational</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-lg">Data Sources</CardTitle>
              <Plug className="h-5 w-5 text-primary" />
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{integrations.length}</div>
            <p className="text-sm text-muted-foreground">Total configured sources</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-lg">Real-time Feeds</CardTitle>
              <RefreshCw className="h-5 w-5 text-orange-500" />
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {integrations.filter(i => i.sync_frequency === 'REALTIME').length}
            </div>
            <p className="text-sm text-muted-foreground">Live data streaming</p>
          </CardContent>
        </Card>
      </div>

      {/* Main Content */}
      <Tabs defaultValue="active" className="space-y-6">
        <TabsList>
          <TabsTrigger value="active">Active Integrations</TabsTrigger>
          <TabsTrigger value="catalog">Integration Catalog</TabsTrigger>
        </TabsList>

        <TabsContent value="active" className="space-y-4">
          {integrations.map((integration) => (
            <Card key={integration.id}>
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex items-center space-x-3">
                    {getTypeIcon(integration.type)}
                    <div>
                      <CardTitle className="text-lg">{integration.name}</CardTitle>
                      <CardDescription>{integration.description}</CardDescription>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Badge className={getStatusColor(integration.status)}>
                      {getStatusIcon(integration.status)}
                      {integration.status}
                    </Badge>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                  <div>
                    <div className="text-sm font-medium text-muted-foreground">Sync Frequency</div>
                    <div className="text-sm">{integration.sync_frequency}</div>
                  </div>
                  <div>
                    <div className="text-sm font-medium text-muted-foreground">Last Sync</div>
                    <div className="text-sm">
                      {integration.last_sync 
                        ? formatDistanceToNow(new Date(integration.last_sync), { addSuffix: true })
                        : 'Never'
                      }
                    </div>
                  </div>
                  <div>
                    <div className="text-sm font-medium text-muted-foreground">Data Types</div>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {integration.data_types.slice(0, 3).map((type) => (
                        <Badge key={type} variant="outline" className="text-xs">
                          {type}
                        </Badge>
                      ))}
                      {integration.data_types.length > 3 && (
                        <Badge variant="outline" className="text-xs">
                          +{integration.data_types.length - 3}
                        </Badge>
                      )}
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center space-x-2 pt-4 border-t">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleTestConnection(integration.id)}
                  >
                    <TestTube className="h-4 w-4 mr-2" />
                    Test Connection
                  </Button>
                  <Button variant="outline" size="sm">
                    <Settings className="h-4 w-4 mr-2" />
                    Configure
                  </Button>
                  <Button variant="outline" size="sm">
                    <ExternalLink className="h-4 w-4 mr-2" />
                    View Logs
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </TabsContent>

        <TabsContent value="catalog" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {templates.map((template) => (
              <Card key={template.id} className="hover:shadow-lg transition-shadow">
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="flex items-center space-x-3">
                      {getTypeIcon(template.type)}
                      <div>
                        <CardTitle className="text-lg">{template.name}</CardTitle>
                        <CardDescription className="text-sm">{template.description}</CardDescription>
                      </div>
                    </div>
                    {template.is_popular && (
                      <Badge variant="secondary" className="text-xs">Popular</Badge>
                    )}
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div>
                      <div className="text-sm font-medium text-muted-foreground mb-1">Supported Data Types</div>
                      <div className="flex flex-wrap gap-1">
                        {template.supported_data_types.slice(0, 3).map((type) => (
                          <Badge key={type} variant="outline" className="text-xs">
                            {type}
                          </Badge>
                        ))}
                        {template.supported_data_types.length > 3 && (
                          <Badge variant="outline" className="text-xs">
                            +{template.supported_data_types.length - 3}
                          </Badge>
                        )}
                      </div>
                    </div>
                    
                    <div className="flex items-center space-x-2 pt-2">
                      <Button 
                        className="flex-1"
                        onClick={() => handleAddIntegration(template.id)}
                      >
                        <Plus className="h-4 w-4 mr-2" />
                        Connect
                      </Button>
                      <Button variant="outline" size="sm">
                        <Link className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};