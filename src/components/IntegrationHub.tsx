import { useState } from 'react';
import { useIntegrations, IntegrationTemplate } from '@/hooks/useIntegrations';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { ScrollArea } from '@/components/ui/scroll-area';
import { 
  Plug, Plus, Settings, AlertCircle, CheckCircle, 
  Clock, Trash2, TestTube, Link, Zap, Shield,
  Cloud, Monitor, UserCheck, RefreshCw, ExternalLink
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { useToast } from '@/hooks/use-toast';
import StrategicMarketplace from '@/components/marketplace/StrategicMarketplace';

export const IntegrationHub = () => {
  const { integrations, templates, loading, addIntegration, removeIntegration, testConnection } = useIntegrations();
  const [selectedTemplate, setSelectedTemplate] = useState<IntegrationTemplate | null>(null);
  const [configValues, setConfigValues] = useState<Record<string, string>>({});
  const [isAddingIntegration, setIsAddingIntegration] = useState(false);
  const [showAddDialog, setShowAddDialog] = useState(false);
  const { toast } = useToast();

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

  const handleAddIntegration = async () => {
    if (!selectedTemplate) return;

    console.log('🔌 Adding integration:', selectedTemplate.name);
    setIsAddingIntegration(true);
    
    const result = await addIntegration(selectedTemplate, configValues);
    
    if (result.success) {
      console.log('✅ Integration added successfully:', selectedTemplate.name);
      toast({
        title: "Integration Added",
        description: `${selectedTemplate.name} integration is being configured...`,
        variant: "default"
      });
      setShowAddDialog(false);
      setSelectedTemplate(null);
      setConfigValues({});
    } else {
      console.error('❌ Integration failed:', result.error);
      toast({
        title: "Integration Failed",
        description: result.error || "Failed to add integration",
        variant: "destructive"
      });
    }
    
    setIsAddingIntegration(false);
  };

  const handleRemoveIntegration = async (integrationId: string, name: string) => {
    const result = await removeIntegration(integrationId);
    
    if (result.success) {
      toast({
        title: "Integration Removed",
        description: `${name} integration has been disconnected`,
        variant: "default"
      });
    } else {
      toast({
        title: "Removal Failed",
        description: result.error || "Failed to remove integration",
        variant: "destructive"
      });
    }
  };

  const handleTestConnection = async (integrationId: string, name: string) => {
    const result = await testConnection(integrationId);
    
    if (result.success) {
      toast({
        title: "Testing Connection",
        description: `Testing connection to ${name}...`,
        variant: "default"
      });
    }
  };

  const connectedIntegrations = integrations.filter(int => int.status === 'CONNECTED');
  const popularTemplates = templates.filter(template => template.is_popular);

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="text-foreground">Loading integrations...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Integration Overview */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Active Integrations</p>
                <p className="text-2xl font-bold text-success">{connectedIntegrations.length}</p>
              </div>
              <Plug className="h-8 w-8 text-success" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Data Sources</p>
                <p className="text-2xl font-bold text-primary">
                  {connectedIntegrations.reduce((acc, int) => acc + int.data_types.length, 0)}
                </p>
              </div>
              <Link className="h-8 w-8 text-primary" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Real-time Feeds</p>
                <p className="text-2xl font-bold text-accent">
                  {integrations.filter(int => int.sync_frequency === 'REALTIME' && int.status === 'CONNECTED').length}
                </p>
              </div>
              <RefreshCw className="h-8 w-8 text-accent" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Integration Tabs */}
      <Tabs defaultValue="active" className="space-y-4">
        <div className="flex items-center justify-between">
          <TabsList className="bg-card border border-border">
            <TabsTrigger value="active" className="flex items-center space-x-2">
              <Plug className="h-4 w-4" />
              <span>Active Integrations</span>
            </TabsTrigger>
            <TabsTrigger value="catalog" className="flex items-center space-x-2">
              <Plus className="h-4 w-4" />
              <span>Integration Catalog</span>
            </TabsTrigger>
          </TabsList>
          
          <div className="flex items-center space-x-2">
            <Button 
              variant="outline"
              onClick={() => globalThis.open('/integration-guide/custom-api', '_blank')}
              className="flex items-center space-x-2"
            >
              <ExternalLink className="h-4 w-4" />
              <span>API Integration Guide</span>
            </Button>
          
            <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
            <DialogTrigger asChild>
              <Button variant="cyber" className="flex items-center space-x-2">
                <Plus className="h-4 w-4" />
                <span>Add Integration</span>
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-2xl card-cyber">
              <DialogHeader>
                <DialogTitle>Add New Integration</DialogTitle>
                <DialogDescription>
                  Connect IMOHTEP with your existing security infrastructure
                </DialogDescription>
              </DialogHeader>
              
              {!selectedTemplate ? (
                <div className="space-y-4">
                  <h3 className="font-semibold text-foreground">Popular Integrations</h3>
                  <div className="grid grid-cols-2 gap-3">
                    {popularTemplates.map((template) => (
                      <div
                        key={template.id}
                        className="p-4 border border-border rounded-lg cursor-pointer hover:bg-accent/50 transition-colors"
                        onClick={() => setSelectedTemplate(template)}
                      >
                        <div className="flex items-center space-x-3">
                          {getTypeIcon(template.type)}
                          <div>
                            <p className="font-medium text-foreground">{template.name}</p>
                            <p className="text-sm text-muted-foreground">{template.type}</p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="flex items-center space-x-3">
                    {getTypeIcon(selectedTemplate.type)}
                    <div>
                      <h3 className="font-semibold text-foreground">{selectedTemplate.name}</h3>
                      <p className="text-sm text-muted-foreground">{selectedTemplate.description}</p>
                    </div>
                  </div>
                  
                  <div className="space-y-3">
                    {selectedTemplate.required_fields.map((field) => (
                      <div key={field} className="space-y-2">
                        <Label htmlFor={field} className="text-foreground capitalize">
                          {field.replace(/_/g, ' ')}
                        </Label>
                        <Input
                          id={field}
                          type={field.includes('password') || field.includes('secret') || field.includes('key') ? 'password' : 'text'}
                          value={configValues[field] || ''}
                          onChange={(e) => setConfigValues(prev => ({ ...prev, [field]: e.target.value }))}
                          placeholder={`Enter ${field.replace(/_/g, ' ')}`}
                          className="bg-input/50 border-border"
                        />
                      </div>
                    ))}
                  </div>
                  
                  <div className="flex items-center justify-between pt-4">
                    <Button
                      variant="outline"
                      onClick={() => {
                        setSelectedTemplate(null);
                        setConfigValues({});
                      }}
                    >
                      Back
                    </Button>
                    <Button
                      variant="cyber"
                      onClick={handleAddIntegration}
                      disabled={isAddingIntegration}
                    >
                      {isAddingIntegration ? 'Connecting...' : 'Connect Integration'}
                    </Button>
                  </div>
                </div>
              )}
            </DialogContent>
          </Dialog>
          </div>
        </div>

        <TabsContent value="active" className="space-y-4">
          <Card className="card-cyber">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Plug className="h-5 w-5 text-primary" />
                <span>Active Integrations</span>
              </CardTitle>
        <CardDescription>
          Manage connections to DoD tactical systems, critical infrastructure, and enterprise AI platforms
        </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {integrations.length === 0 ? (
                  <div className="text-center text-muted-foreground py-8">
                    <Plug className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No strategic integrations configured</p>
                    <p className="text-sm">Connect DoD systems, critical infrastructure, or AI platforms to get started</p>
                  </div>
                ) : (
                  integrations.map((integration) => (
                    <div
                      key={integration.id}
                      className="p-4 border border-border rounded-lg bg-card hover:bg-accent/30 transition-colors"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-4">
                          {getTypeIcon(integration.type)}
                          <div className="flex-1">
                            <div className="flex items-center space-x-2 mb-1">
                              <h4 className="font-medium text-foreground">{integration.name}</h4>
                              <Badge className={getStatusColor(integration.status)}>
                                {getStatusIcon(integration.status)}
                                <span className="ml-1">{integration.status}</span>
                              </Badge>
                              <Badge variant="outline">{integration.type}</Badge>
                            </div>
                            <p className="text-sm text-muted-foreground mb-2">
                              {integration.description}
                            </p>
                            <div className="flex items-center space-x-4 text-xs text-muted-foreground">
                              <span>Sync: {integration.sync_frequency}</span>
                              {integration.last_sync && (
                                <span>
                                  Last sync: {formatDistanceToNow(new Date(integration.last_sync), { addSuffix: true })}
                                </span>
                              )}
                              <span>Data types: {integration.data_types.join(', ')}</span>
                            </div>
                          </div>
                        </div>
                        
                        <div className="flex items-center space-x-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleTestConnection(integration.id, integration.name)}
                          >
                            <TestTube className="h-3 w-3 mr-1" />
                            Test
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                          >
                            <Settings className="h-3 w-3 mr-1" />
                            Config
                          </Button>
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={() => handleRemoveIntegration(integration.id, integration.name)}
                          >
                            <Trash2 className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

            <TabsContent value="catalog" className="space-y-4">
              <StrategicMarketplace />
            </TabsContent>
      </Tabs>
    </div>
  );
};