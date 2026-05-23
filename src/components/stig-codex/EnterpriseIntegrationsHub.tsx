import { useState, useEffect } from 'react';
import { useOrganizationContext } from "@/components/OrganizationProvider";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { supabase } from "@/integrations/supabase/client";
import { Plus, Settings, Trash2, RefreshCw, CheckCircle, XCircle, AlertTriangle, Link, Zap, Shield, Users, MessageSquare } from 'lucide-react';
import { useToast } from "@/hooks/use-toast";

interface OrganizationIntegration {
  id: string;
  integration_type: string;
  integration_name: string;
  configuration: any;
  sync_status: string;
  last_sync?: string;
  error_message?: string;
  is_active: boolean;
}

interface APIIntegration {
  id: string;
  integration_name: string;
  api_type: string;
  endpoint_url: string;
  authentication_type: string;
  sync_status: string;
  total_requests: number;
  successful_requests: number;
  failed_requests: number;
  last_sync?: string;
  is_active: boolean;
}

interface CompliancePolicy {
  id: string;
  policy_name: string;
  policy_type: string;
  enforcement_level: string;
  compliance_threshold: number;
  is_active: boolean;
}

export const EnterpriseIntegrationsHub = () => {
  const [integrations, setIntegrations] = useState<OrganizationIntegration[]>([]);
  const [apiIntegrations, setApiIntegrations] = useState<APIIntegration[]>([]);
  const [policies, setPolicies] = useState<CompliancePolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [activeTab, setActiveTab] = useState('enterprise');
  const { currentOrganization } = useOrganizationContext();
  const { toast } = useToast();

  const [formData, setFormData] = useState({
    integration_type: 'servicenow',
    integration_name: '',
    configuration: {},
    authentication_data: {}
  });

  useEffect(() => {
    if (currentOrganization?.id) {
      fetchIntegrations();
      fetchAPIIntegrations();
      fetchPolicies();
    }
  }, [currentOrganization?.id]);

  const fetchIntegrations = async () => {
    try {
      const { data, error } = await supabase
        .from('organization_integrations')
        .select('*')
        .eq('organization_id', currentOrganization?.id)
        .order('created_at', { ascending: false });

      if (error) throw error;
      setIntegrations(data || []);
    } catch (error) {
      console.error('Error fetching integrations:', error);
    }
  };

  const fetchAPIIntegrations = async () => {
    try {
      const { data, error } = await supabase
        .from('api_integrations')
        .select('*')
        .eq('organization_id', currentOrganization?.id)
        .order('created_at', { ascending: false });

      if (error) throw error;
      setApiIntegrations(data || []);
    } catch (error) {
      console.error('Error fetching API integrations:', error);
    }
  };

  const fetchPolicies = async () => {
    try {
      const { data, error } = await supabase
        .from('stig_compliance_policies')
        .select('*')
        .eq('organization_id', currentOrganization?.id)
        .order('created_at', { ascending: false });

      if (error) throw error;
      setPolicies(data || []);
    } catch (error) {
      console.error('Error fetching policies:', error);
    } finally {
      setLoading(false);
    }
  };

  const syncIntegration = async (integrationId: string) => {
    try {
      const { data, error } = await supabase.functions.invoke('stig-intelligence-orchestrator', {
        body: {
          action: 'sync_integration',
          integration_id: integrationId,
          organization_id: currentOrganization?.id
        }
      });

      if (error) throw error;

      toast({
        title: "Sync Started",
        description: "Integration sync has been initiated."
      });

      // Refresh integrations
      fetchIntegrations();
    } catch (error) {
      console.error('Error syncing integration:', error);
      toast({
        title: "Error",
        description: "Failed to sync integration.",
        variant: "destructive"
      });
    }
  };

  const toggleIntegration = async (integrationId: string, isActive: boolean, type: 'enterprise' | 'api') => {
    try {
      const table = type === 'enterprise' ? 'organization_integrations' : 'api_integrations';
      
      const { error } = await supabase
        .from(table)
        .update({ is_active: !isActive })
        .eq('id', integrationId);

      if (error) throw error;

      if (type === 'enterprise') {
        setIntegrations(integrations.map(i => 
          i.id === integrationId ? { ...i, is_active: !isActive } : i
        ));
      } else {
        setApiIntegrations(apiIntegrations.map(i => 
          i.id === integrationId ? { ...i, is_active: !isActive } : i
        ));
      }

      toast({
        title: `Integration ${!isActive ? 'Activated' : 'Deactivated'}`,
        description: `Integration has been ${!isActive ? 'activated' : 'deactivated'} successfully.`
      });
    } catch (error) {
      console.error('Error toggling integration:', error);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'connected':
        return <CheckCircle className="h-4 w-4 text-green-400" />;
      case 'error':
        return <XCircle className="h-4 w-4 text-red-400" />;
      case 'pending':
        return <RefreshCw className="h-4 w-4 text-yellow-400" />;
      default:
        return <AlertTriangle className="h-4 w-4 text-gray-400" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'connected':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'error':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'pending':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      default:
        return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  const getIntegrationIcon = (type: string) => {
    switch (type) {
      case 'servicenow':
        return <Shield className="h-6 w-6 text-blue-400" />;
      case 'jira':
        return <Users className="h-6 w-6 text-blue-500" />;
      case 'slack':
        return <MessageSquare className="h-6 w-6 text-purple-400" />;
      case 'teams':
        return <MessageSquare className="h-6 w-6 text-blue-400" />;
      default:
        return <Link className="h-6 w-6 text-gray-400" />;
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="text-white">Loading enterprise integrations...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Enterprise Integrations</h2>
          <p className="text-gray-300">Connect with enterprise tools and systems</p>
        </div>
        <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
          <DialogTrigger asChild>
            <Button className="bg-gradient-to-r from-purple-500 to-blue-500">
              <Plus className="h-4 w-4 mr-2" />
              Add Integration
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Add Enterprise Integration</DialogTitle>
              <DialogDescription>
                Connect with your enterprise tools and systems
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="integration_type">Integration Type</Label>
                  <Select value={formData.integration_type} onValueChange={(value) => setFormData({...formData, integration_type: value})}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="servicenow">ServiceNow</SelectItem>
                      <SelectItem value="jira">Jira</SelectItem>
                      <SelectItem value="slack">Slack</SelectItem>
                      <SelectItem value="teams">Microsoft Teams</SelectItem>
                      <SelectItem value="email">Email</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label htmlFor="integration_name">Integration Name</Label>
                  <Input
                    id="integration_name"
                    value={formData.integration_name}
                    onChange={(e) => setFormData({...formData, integration_name: e.target.value})}
                    placeholder="Enter integration name"
                  />
                </div>
              </div>

              <div className="flex justify-end space-x-2">
                <Button variant="outline" onClick={() => setShowCreateDialog(false)}>
                  Cancel
                </Button>
                <Button>
                  Add Integration
                </Button>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium text-gray-300">Total Integrations</CardTitle>
              <Link className="h-4 w-4 text-purple-400" />
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">{integrations.length + apiIntegrations.length}</div>
            <p className="text-xs text-gray-400">
              {integrations.filter(i => i.is_active).length + apiIntegrations.filter(i => i.is_active).length} active
            </p>
          </CardContent>
        </Card>

        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium text-gray-300">Connected</CardTitle>
              <CheckCircle className="h-4 w-4 text-green-400" />
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">
              {integrations.filter(i => i.sync_status === 'connected').length + 
               apiIntegrations.filter(i => i.sync_status === 'connected').length}
            </div>
            <p className="text-xs text-gray-400">Healthy connections</p>
          </CardContent>
        </Card>

        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium text-gray-300">API Requests</CardTitle>
              <Zap className="h-4 w-4 text-blue-400" />
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">
              {apiIntegrations.reduce((sum, i) => sum + i.total_requests, 0)}
            </div>
            <p className="text-xs text-gray-400">Total requests made</p>
          </CardContent>
        </Card>

        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium text-gray-300">Success Rate</CardTitle>
              <CheckCircle className="h-4 w-4 text-green-400" />
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">
              {apiIntegrations.length > 0 ? 
                ((apiIntegrations.reduce((sum, i) => sum + i.successful_requests, 0) / 
                  apiIntegrations.reduce((sum, i) => sum + i.total_requests, 1)) * 100).toFixed(1) :
                0
              }%
            </div>
            <p className="text-xs text-gray-400">API success rate</p>
          </CardContent>
        </Card>
      </div>

      {/* Main Content */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="bg-slate-800/50 border border-slate-700">
          <TabsTrigger value="enterprise">Enterprise Tools</TabsTrigger>
          <TabsTrigger value="api">API Integrations</TabsTrigger>
          <TabsTrigger value="policies">Policies</TabsTrigger>
          <TabsTrigger value="marketplace">Marketplace</TabsTrigger>
        </TabsList>

        <TabsContent value="enterprise" className="space-y-4">
          <div className="grid gap-4">
            {integrations.map((integration) => (
              <Card key={integration.id} className="bg-slate-800/50 border-slate-700">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                      {getIntegrationIcon(integration.integration_type)}
                      <div>
                        <h3 className="font-semibold text-white">{integration.integration_name}</h3>
                        <div className="flex items-center space-x-2 mt-1">
                          <Badge variant="outline" className={getStatusColor(integration.sync_status)}>
                            {getStatusIcon(integration.sync_status)}
                            <span className="ml-1">{integration.sync_status}</span>
                          </Badge>
                          <span className="text-sm text-gray-400">
                            Type: {integration.integration_type}
                          </span>
                          {integration.last_sync && (
                            <span className="text-sm text-gray-400">
                              Last sync: {new Date(integration.last_sync).toLocaleString()}
                            </span>
                          )}
                        </div>
                        {integration.error_message && (
                          <p className="text-sm text-red-400 mt-1">{integration.error_message}</p>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => syncIntegration(integration.id)}
                      >
                        <RefreshCw className="h-4 w-4 mr-1" />
                        Sync
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => toggleIntegration(integration.id, integration.is_active, 'enterprise')}
                      >
                        {integration.is_active ? 'Disable' : 'Enable'}
                      </Button>
                      <Button size="sm" variant="outline">
                        <Settings className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="api" className="space-y-4">
          <div className="grid gap-4">
            {apiIntegrations.map((integration) => (
              <Card key={integration.id} className="bg-slate-800/50 border-slate-700">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                      <Zap className="h-6 w-6 text-blue-400" />
                      <div>
                        <h3 className="font-semibold text-white">{integration.integration_name}</h3>
                        <div className="flex items-center space-x-4 mt-1 text-sm text-gray-400">
                          <Badge variant="outline" className={getStatusColor(integration.sync_status)}>
                            {getStatusIcon(integration.sync_status)}
                            <span className="ml-1">{integration.sync_status}</span>
                          </Badge>
                          <span>Type: {integration.api_type.toUpperCase()}</span>
                          <span>Requests: {integration.total_requests}</span>
                          <span>Success: {integration.successful_requests}</span>
                          <span>Failed: {integration.failed_requests}</span>
                        </div>
                        <p className="text-sm text-gray-500 mt-1">{integration.endpoint_url}</p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => toggleIntegration(integration.id, integration.is_active, 'api')}
                      >
                        {integration.is_active ? 'Disable' : 'Enable'}
                      </Button>
                      <Button size="sm" variant="outline">
                        <Settings className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="policies" className="space-y-4">
          <div className="grid gap-4">
            {policies.map((policy) => (
              <Card key={policy.id} className="bg-slate-800/50 border-slate-700">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="font-semibold text-white">{policy.policy_name}</h3>
                      <div className="flex items-center space-x-4 mt-1 text-sm text-gray-400">
                        <span>Type: {policy.policy_type}</span>
                        <span>Enforcement: {policy.enforcement_level}</span>
                        <span>Threshold: {policy.compliance_threshold}%</span>
                        <Badge variant={policy.is_active ? "default" : "secondary"}>
                          {policy.is_active ? "Active" : "Inactive"}
                        </Badge>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Button size="sm" variant="outline">
                        <Settings className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="marketplace" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <Card className="bg-slate-800/50 border-slate-700 cursor-pointer hover:bg-slate-700/50 transition-colors">
              <CardHeader>
                <div className="flex items-center space-x-3">
                  <Shield className="h-8 w-8 text-blue-400" />
                  <div>
                    <CardTitle className="text-white">ServiceNow</CardTitle>
                    <CardDescription>IT Service Management integration</CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between">
                  <Badge variant="outline" className="bg-blue-500/20 text-blue-400 border-blue-500/30">
                    Available
                  </Badge>
                  <Button size="sm">Install</Button>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-slate-800/50 border-slate-700 cursor-pointer hover:bg-slate-700/50 transition-colors">
              <CardHeader>
                <div className="flex items-center space-x-3">
                  <Users className="h-8 w-8 text-blue-500" />
                  <div>
                    <CardTitle className="text-white">Jira</CardTitle>
                    <CardDescription>Issue tracking and project management</CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between">
                  <Badge variant="outline" className="bg-blue-500/20 text-blue-400 border-blue-500/30">
                    Available
                  </Badge>
                  <Button size="sm">Install</Button>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-slate-800/50 border-slate-700 cursor-pointer hover:bg-slate-700/50 transition-colors">
              <CardHeader>
                <div className="flex items-center space-x-3">
                  <MessageSquare className="h-8 w-8 text-purple-400" />
                  <div>
                    <CardTitle className="text-white">Slack</CardTitle>
                    <CardDescription>Team communication and notifications</CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between">
                  <Badge variant="outline" className="bg-purple-500/20 text-purple-400 border-purple-500/30">
                    Available
                  </Badge>
                  <Button size="sm">Install</Button>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};