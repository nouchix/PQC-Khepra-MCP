import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Switch } from '@/components/ui/switch';
import { Progress } from '@/components/ui/progress';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { AlertCircle, CheckCircle, Shield, Key, Users, Settings, Globe, Lock } from 'lucide-react';

interface AuthProvider {
  id: string;
  name: string;
  type: 'oauth2' | 'saml' | 'oidc' | 'scim';
  status: 'active' | 'inactive' | 'configuring';
  compliance: number;
  users: number;
  features: string[];
  config: Record<string, any>;
}

export const EnterpriseAuthManager = () => {
  const [providers, setProviders] = useState<AuthProvider[]>([
    {
      id: 'oauth2-1',
      name: 'OAuth 2.1 Provider',
      type: 'oauth2',
      status: 'active',
      compliance: 98,
      users: 1250,
      features: ['PKCE', 'Refresh Rotation', 'Custom Scopes', 'Rate Limiting'],
      config: { client_id: 'xxx-xxx', pkce_enabled: true }
    },
    {
      id: 'saml-1',
      name: 'SAML 2.0 IdP',
      type: 'saml',
      status: 'active',
      compliance: 95,
      users: 850,
      features: ['SP-Initiated', 'IdP-Initiated', 'Attribute Mapping', 'Metadata'],
      config: { entity_id: 'https://khepra.enterprise', sso_url: 'https://sso.khepra.com' }
    },
    {
      id: 'oidc-1',
      name: 'OpenID Connect',
      type: 'oidc',
      status: 'configuring',
      compliance: 85,
      users: 500,
      features: ['Discovery', 'JWT Validation', 'Userinfo Endpoint', 'Logout'],
      config: { issuer: 'https://auth.khepra.com', discovery_enabled: true }
    },
    {
      id: 'scim-1',
      name: 'SCIM 2.0 Provisioning',
      type: 'scim',
      status: 'active',
      compliance: 92,
      users: 2100,
      features: ['User Sync', 'Group Management', 'Real-time Updates', 'Bulk Operations'],
      config: { endpoint: '/scim/v2', auth_method: 'bearer' }
    }
  ]);

  const [selectedProvider, setSelectedProvider] = useState<AuthProvider | null>(null);

  const toggleProvider = (id: string) => {
    setProviders(prev => prev.map(provider => 
      provider.id === id 
        ? { ...provider, status: provider.status === 'active' ? 'inactive' : 'active' }
        : provider
    ));
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'configuring': return <AlertCircle className="h-4 w-4 text-yellow-500" />;
      default: return <AlertCircle className="h-4 w-4 text-red-500" />;
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'oauth2': return <Key className="h-4 w-4" />;
      case 'saml': return <Shield className="h-4 w-4" />;
      case 'oidc': return <Globe className="h-4 w-4" />;
      case 'scim': return <Users className="h-4 w-4" />;
      default: return <Lock className="h-4 w-4" />;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-foreground">Enterprise Authentication</h2>
          <p className="text-muted-foreground">OAuth 2.1, SAML, OIDC, and SCIM integration management</p>
        </div>
        <Badge variant="secondary" className="bg-primary/10 text-primary">
          Phase 2 Implementation
        </Badge>
      </div>

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="oauth2">OAuth 2.1</TabsTrigger>
          <TabsTrigger value="saml">SAML 2.0</TabsTrigger>
          <TabsTrigger value="oidc">OIDC</TabsTrigger>
          <TabsTrigger value="scim">SCIM 2.0</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            {providers.map((provider) => (
              <Card key={provider.id} className="relative">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      {getTypeIcon(provider.type)}
                      <CardTitle className="text-sm">{provider.name}</CardTitle>
                    </div>
                    {getStatusIcon(provider.status)}
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-muted-foreground">Compliance</span>
                      <span className="font-medium">{provider.compliance}%</span>
                    </div>
                    <Progress value={provider.compliance} className="h-1" />
                  </div>
                  
                  <div className="space-y-1">
                    <p className="text-xs text-muted-foreground">Active Users</p>
                    <p className="text-lg font-bold">{provider.users.toLocaleString()}</p>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="text-xs text-muted-foreground">Active</span>
                    <Switch
                      checked={provider.status === 'active'}
                      onCheckedChange={() => toggleProvider(provider.id)}
                    />
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Authentication Flow Status</CardTitle>
                <CardDescription>Real-time authentication metrics</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Successful Logins (24h)</span>
                    <span className="font-mono text-green-600">2,847</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Failed Attempts (24h)</span>
                    <span className="font-mono text-red-600">23</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">MFA Challenges</span>
                    <span className="font-mono text-blue-600">1,205</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">SSO Sessions</span>
                    <span className="font-mono text-purple-600">892</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Security Compliance</CardTitle>
                <CardDescription>Industry standard compliance status</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm">SOC 2 Type II</span>
                    <Badge variant="default">Compliant</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">FIDO2/WebAuthn</span>
                    <Badge variant="default">Enabled</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Zero Trust</span>
                    <Badge variant="default">Active</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">NIST 800-63B</span>
                    <Badge variant="secondary">In Progress</Badge>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="oauth2">
          <Card>
            <CardHeader>
              <CardTitle>OAuth 2.1 Configuration</CardTitle>
              <CardDescription>Enhanced OAuth implementation with PKCE and security best practices</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="client-id">Client ID</Label>
                    <Input id="client-id" placeholder="khepra-oauth-client" />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="redirect-uri">Redirect URI</Label>
                    <Input id="redirect-uri" placeholder="https://app.khepra.com/auth/callback" />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="scope">Default Scopes</Label>
                    <Input id="scope" placeholder="openid profile email" />
                  </div>
                </div>
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label>Security Features</Label>
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-sm">PKCE Enabled</span>
                        <Switch defaultChecked />
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm">Refresh Token Rotation</span>
                        <Switch defaultChecked />
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm">State Parameter</span>
                        <Switch defaultChecked />
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm">Custom Claims</span>
                        <Switch />
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <div className="flex space-x-2">
                <Button>Save Configuration</Button>
                <Button variant="outline">Test Flow</Button>
                <Button variant="outline">View Logs</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="saml">
          <Card>
            <CardHeader>
              <CardTitle>SAML 2.0 Identity Provider</CardTitle>
              <CardDescription>Enterprise SSO with SAML identity provider configuration</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="entity-id">Entity ID</Label>
                    <Input id="entity-id" placeholder="https://khepra.enterprise/saml" />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="sso-url">SSO URL</Label>
                    <Input id="sso-url" placeholder="https://sso.khepra.com/saml/login" />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="slo-url">SLO URL</Label>
                    <Input id="slo-url" placeholder="https://sso.khepra.com/saml/logout" />
                  </div>
                </div>
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label>SAML Features</Label>
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-sm">SP-Initiated Flow</span>
                        <Switch defaultChecked />
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm">IdP-Initiated Flow</span>
                        <Switch defaultChecked />
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm">Attribute Mapping</span>
                        <Switch defaultChecked />
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm">Encrypted Assertions</span>
                        <Switch />
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <div className="flex space-x-2">
                <Button>Update SAML Config</Button>
                <Button variant="outline">Download Metadata</Button>
                <Button variant="outline">Test SSO</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="oidc">
          <Card>
            <CardHeader>
              <CardTitle>OpenID Connect Provider</CardTitle>
              <CardDescription>Modern identity layer on top of OAuth 2.0</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="issuer">Issuer URL</Label>
                    <Input id="issuer" placeholder="https://auth.khepra.com" />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="userinfo">UserInfo Endpoint</Label>
                    <Input id="userinfo" placeholder="https://auth.khepra.com/userinfo" />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="jwks">JWKS URI</Label>
                    <Input id="jwks" placeholder="https://auth.khepra.com/.well-known/jwks.json" />
                  </div>
                </div>
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label>OIDC Features</Label>
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-sm">Discovery Enabled</span>
                        <Switch defaultChecked />
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm">JWT Validation</span>
                        <Switch defaultChecked />
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm">Session Management</span>
                        <Switch defaultChecked />
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm">Back-Channel Logout</span>
                        <Switch />
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <div className="flex space-x-2">
                <Button>Configure OIDC</Button>
                <Button variant="outline">Validate Discovery</Button>
                <Button variant="outline">Test Tokens</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="scim">
          <Card>
            <CardHeader>
              <CardTitle>SCIM 2.0 User Provisioning</CardTitle>
              <CardDescription>Automated user and group management with SCIM protocol</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="scim-endpoint">SCIM Endpoint</Label>
                    <Input id="scim-endpoint" placeholder="/scim/v2" />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="auth-method">Authentication Method</Label>
                    <Select defaultValue="bearer">
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="bearer">Bearer Token</SelectItem>
                        <SelectItem value="basic">Basic Auth</SelectItem>
                        <SelectItem value="oauth2">OAuth 2.0</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="sync-frequency">Sync Frequency</Label>
                    <Select defaultValue="realtime">
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="realtime">Real-time</SelectItem>
                        <SelectItem value="hourly">Hourly</SelectItem>
                        <SelectItem value="daily">Daily</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label>SCIM Features</Label>
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-sm">User Provisioning</span>
                        <Switch defaultChecked />
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm">Group Management</span>
                        <Switch defaultChecked />
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm">Real-time Updates</span>
                        <Switch defaultChecked />
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm">Bulk Operations</span>
                        <Switch />
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <div className="flex space-x-2">
                <Button>Enable SCIM</Button>
                <Button variant="outline">Test Sync</Button>
                <Button variant="outline">View Activity</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};