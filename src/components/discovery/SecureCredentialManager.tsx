import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Progress } from '@/components/ui/progress';
import { 
  Shield, 
  Key, 
  Plus, 
  Eye, 
  EyeOff, 
  TestTube, 
  RotateCcw, 
  Trash2,
  Clock,
  AlertTriangle,
  CheckCircle,
  Lock,
  Unlock
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { SecureCredentialVault, type SecureCredential } from '@/services/SecureCredentialVault';

interface SecureCredentialManagerProps {
  organizationId: string;
  onCredentialSelected?: (credentialId: string) => void;
}

export const SecureCredentialManager: React.FC<SecureCredentialManagerProps> = ({
  organizationId,
  onCredentialSelected
}) => {
  const [credentials, setCredentials] = useState<SecureCredential[]>([]);
  const [loading, setLoading] = useState(false);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [testingCredential, setTestingCredential] = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState<{ [key: string]: boolean }>({});
  const { toast } = useToast();

  const [newCredential, setNewCredential] = useState({
    credential_name: '',
    credential_type: 'username_password' as const,
    target_systems: [] as string[],
    credentials: {} as any,
    mfa_required: true,
    max_concurrent_uses: 5,
    expires_at: '',
    target_input: ''
  });

  useEffect(() => {
    fetchCredentials();
  }, [organizationId]);

  const fetchCredentials = async () => {
    try {
      setLoading(true);
      const data = await SecureCredentialVault.listCredentials(organizationId);
      setCredentials(data);
    } catch (error: any) {
      toast({
        title: "Error",
        description: "Failed to fetch credentials: " + error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const handleCreateCredential = async () => {
    try {
      setLoading(true);
      
      // Prepare credential data
      const credentialData = {
        ...newCredential,
        target_systems: newCredential.target_input.split(',').map(s => s.trim()).filter(Boolean)
      };

      await SecureCredentialVault.storeCredential(organizationId, credentialData);
      
      toast({
        title: "Success",
        description: "Secure credential created successfully with AES-256 encryption",
      });

      setShowCreateDialog(false);
      resetNewCredential();
      await fetchCredentials();
    } catch (error: any) {
      toast({
        title: "Error",
        description: "Failed to create credential: " + error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const handleTestCredential = async (credentialId: string) => {
    try {
      setTestingCredential(credentialId);
      
      const credential = credentials.find(c => c.id === credentialId);
      if (!credential) return;

      const testTarget = credential.target_systems[0] || 'localhost';
      const result = await SecureCredentialVault.testCredential(credentialId, testTarget);
      
      toast({
        title: result.success ? "Test Successful" : "Test Failed",
        description: result.details,
        variant: result.success ? "default" : "destructive"
      });
    } catch (error: any) {
      toast({
        title: "Test Error",
        description: "Failed to test credential: " + error.message,
        variant: "destructive"
      });
    } finally {
      setTestingCredential(null);
    }
  };

  const handleRevokeCredential = async (credentialId: string) => {
    try {
      await SecureCredentialVault.revokeCredential(credentialId, 'User requested revocation');
      
      toast({
        title: "Credential Revoked",
        description: "Credential has been securely revoked and audit logged",
      });

      await fetchCredentials();
    } catch (error: any) {
      toast({
        title: "Error",
        description: "Failed to revoke credential: " + error.message,
        variant: "destructive"
      });
    }
  };

  const resetNewCredential = () => {
    setNewCredential({
      credential_name: '',
      credential_type: 'username_password',
      target_systems: [],
      credentials: {},
      mfa_required: true,
      max_concurrent_uses: 5,
      expires_at: '',
      target_input: ''
    });
  };

  const renderCredentialFields = () => {
    const credType = newCredential.credential_type;
    
    if (credType === 'username_password') {
        return (
          <>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label htmlFor="username">Username</Label>
                <Input
                  id="username"
                  value={newCredential.credentials.username || ''}
                  onChange={(e) => setNewCredential({
                    ...newCredential,
                    credentials: { ...newCredential.credentials, username: e.target.value }
                  })}
                  placeholder="Enter username"
                />
              </div>
              <div>
                <Label htmlFor="password">Password</Label>
                <div className="relative">
                  <Input
                    id="password"
                    type={showPassword.new ? 'text' : 'password'}
                    value={newCredential.credentials.password || ''}
                    onChange={(e) => setNewCredential({
                      ...newCredential,
                      credentials: { ...newCredential.credentials, password: e.target.value }
                    })}
                    placeholder="Enter password (min 12 chars)"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="absolute right-0 top-0 h-full px-3"
                    onClick={() => setShowPassword({...showPassword, new: !showPassword.new})}
                  >
                    {showPassword.new ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </Button>
                </div>
              </div>
            </div>
          </>
        );
    }
    
    if (credType === 'ssh_key') {
        return (
          <>
            <div>
              <Label htmlFor="private_key">Private Key</Label>
              <Textarea
                id="private_key"
                value={newCredential.credentials.private_key || ''}
                onChange={(e) => setNewCredential({
                  ...newCredential,
                  credentials: { ...newCredential.credentials, private_key: e.target.value }
                })}
                placeholder="-----BEGIN PRIVATE KEY-----"
                rows={8}
              />
            </div>
            <div>
              <Label htmlFor="public_key">Public Key</Label>
              <Textarea
                id="public_key"
                value={newCredential.credentials.public_key || ''}
                onChange={(e) => setNewCredential({
                  ...newCredential,
                  credentials: { ...newCredential.credentials, public_key: e.target.value }
                })}
                placeholder="ssh-rsa AAAAB3..."
                rows={3}
              />
            </div>
          </>
        );
    }
    
    if (credType === 'api_token') {
        return (
          <div>
            <Label htmlFor="token">API Token</Label>
            <div className="relative">
              <Input
                id="token"
                type={showPassword.new ? 'text' : 'password'}
                value={newCredential.credentials.token || ''}
                onChange={(e) => setNewCredential({
                  ...newCredential,
                  credentials: { ...newCredential.credentials, token: e.target.value }
                })}
                placeholder="Enter API token (min 32 chars)"
              />
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="absolute right-0 top-0 h-full px-3"
                onClick={() => setShowPassword({...showPassword, new: !showPassword.new})}
              >
                {showPassword.new ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </Button>
            </div>
          </div>
        );
    }

    if (credType === 'certificate') {
        return (
          <>
            <div>
              <Label htmlFor="certificate">Certificate</Label>
              <Textarea
                id="certificate"
                value={newCredential.credentials.certificate || ''}
                onChange={(e) => setNewCredential({
                  ...newCredential,
                  credentials: { ...newCredential.credentials, certificate: e.target.value }
                })}
                placeholder="-----BEGIN CERTIFICATE-----"
                rows={6}
              />
            </div>
            <div>
              <Label htmlFor="private_key">Private Key</Label>
              <Textarea
                id="private_key"
                value={newCredential.credentials.private_key || ''}
                onChange={(e) => setNewCredential({
                  ...newCredential,
                  credentials: { ...newCredential.credentials, private_key: e.target.value }
                })}
                placeholder="-----BEGIN PRIVATE KEY-----"
                rows={6}
              />
            </div>
          </>
        );
    }

    if (credType === 'cloud_service_account') {
        return (
          <div>
            <Label htmlFor="service_account_json">Service Account JSON</Label>
            <Textarea
              id="service_account_json"
              value={newCredential.credentials.service_account_json || ''}
              onChange={(e) => setNewCredential({
                ...newCredential,
                credentials: { ...newCredential.credentials, service_account_json: e.target.value }
              })}
              placeholder='{"type": "service_account", ...}'
              rows={8}
            />
          </div>
        );
    }
    
    return null;
  };

  const getStatusColor = (credential: SecureCredential) => {
    if (!credential.is_active) return 'hsl(var(--destructive))';
    if (credential.expires_at && new Date(credential.expires_at) < new Date()) return 'hsl(var(--warning))';
    if (credential.usage_count >= credential.max_concurrent_uses) return 'hsl(var(--warning))';
    return 'hsl(var(--success))';
  };

  const getStatusIcon = (credential: SecureCredential) => {
    if (!credential.is_active) return <Lock className="h-4 w-4" />;
    if (credential.expires_at && new Date(credential.expires_at) < new Date()) return <AlertTriangle className="h-4 w-4" />;
    if (credential.usage_count >= credential.max_concurrent_uses) return <AlertTriangle className="h-4 w-4" />;
    return <CheckCircle className="h-4 w-4" />;
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              <CardTitle>TRL 10 Secure Credential Vault</CardTitle>
            </div>
            <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
              <DialogTrigger asChild>
                <Button className="bg-hsl(var(--primary)) hover:bg-hsl(var(--primary))/90">
                  <Plus className="h-4 w-4 mr-2" />
                  Add Credential
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl">
                <DialogHeader>
                  <DialogTitle>Create Secure Credential</DialogTitle>
                  <DialogDescription>
                    Store credentials with AES-256 encryption, MFA, and audit logging
                  </DialogDescription>
                </DialogHeader>
                
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <Label htmlFor="credential_name">Credential Name</Label>
                      <Input
                        id="credential_name"
                        value={newCredential.credential_name}
                        onChange={(e) => setNewCredential({...newCredential, credential_name: e.target.value})}
                        placeholder="Production SSH Key"
                      />
                    </div>
                    <div>
                      <Label htmlFor="credential_type">Credential Type</Label>
                      <Select 
                        value={newCredential.credential_type} 
                        onValueChange={(value: any) => setNewCredential({...newCredential, credential_type: value})}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="username_password">Username/Password</SelectItem>
                          <SelectItem value="ssh_key">SSH Key Pair</SelectItem>
                          <SelectItem value="api_token">API Token</SelectItem>
                          <SelectItem value="certificate">Certificate</SelectItem>
                          <SelectItem value="cloud_service_account">Cloud Service Account</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <div>
                    <Label htmlFor="target_systems">Target Systems</Label>
                    <Input
                      id="target_systems"
                      value={newCredential.target_input}
                      onChange={(e) => setNewCredential({...newCredential, target_input: e.target.value})}
                      placeholder="192.168.1.0/24, server.example.com (comma-separated)"
                    />
                  </div>

                  {renderCredentialFields()}

                  <div className="grid grid-cols-2 gap-4">
                    <div className="flex items-center space-x-2">
                      <Switch
                        id="mfa_required"
                        checked={newCredential.mfa_required}
                        onCheckedChange={(checked) => setNewCredential({...newCredential, mfa_required: checked})}
                      />
                      <Label htmlFor="mfa_required">Require MFA</Label>
                    </div>
                    <div>
                      <Label htmlFor="max_uses">Max Concurrent Uses</Label>
                      <Input
                        id="max_uses"
                        type="number"
                        value={newCredential.max_concurrent_uses}
                        onChange={(e) => setNewCredential({...newCredential, max_concurrent_uses: Number.parseInt(e.target.value)})}
                        min="1"
                        max="10"
                      />
                    </div>
                  </div>

                  <div>
                    <Label htmlFor="expires_at">Expiration Date (Optional)</Label>
                    <Input
                      id="expires_at"
                      type="datetime-local"
                      value={newCredential.expires_at}
                      onChange={(e) => setNewCredential({...newCredential, expires_at: e.target.value})}
                    />
                  </div>

                  <Alert>
                    <Shield className="h-4 w-4" />
                    <AlertDescription>
                      Credentials will be encrypted with AES-256-GCM and stored securely. All access is logged for audit compliance.
                    </AlertDescription>
                  </Alert>

                  <div className="flex justify-end space-x-2">
                    <Button variant="outline" onClick={() => setShowCreateDialog(false)}>
                      Cancel
                    </Button>
                    <Button onClick={handleCreateCredential} disabled={loading}>
                      {loading ? 'Creating...' : 'Create Secure Credential'}
                    </Button>
                  </div>
                </div>
              </DialogContent>
            </Dialog>
          </div>
          <CardDescription>
            Enterprise-grade credential management with encryption, MFA, and comprehensive audit logging
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {credentials.map((credential) => (
              <div key={credential.id} className="flex items-center justify-between p-4 border rounded-lg">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <Key className="h-4 w-4 text-gray-500" />
                    <span className="font-medium">{credential.credential_name}</span>
                    <Badge variant="outline">{credential.credential_type}</Badge>
                    <div className="flex items-center gap-1" style={{ color: getStatusColor(credential) }}>
                      {getStatusIcon(credential)}
                      <span className="text-sm">
                        {credential.is_active ? 'Active' : 'Revoked'}
                      </span>
                    </div>
                  </div>
                  
                  <div className="text-sm text-gray-600 grid grid-cols-3 gap-4">
                    <div>
                      <p>Target Systems: {credential.target_systems.length}</p>
                      <p>Usage: {credential.usage_count}/{credential.max_concurrent_uses}</p>
                    </div>
                    <div>
                      <p>MFA Required: {credential.mfa_required ? 'Yes' : 'No'}</p>
                      <p>Created: {new Date(credential.created_at).toLocaleDateString()}</p>
                    </div>
                    <div>
                      <p>Last Used: {credential.last_used_at ? new Date(credential.last_used_at).toLocaleDateString() : 'Never'}</p>
                      {credential.expires_at && (
                        <p>Expires: {new Date(credential.expires_at).toLocaleDateString()}</p>
                      )}
                    </div>
                  </div>

                  {credential.usage_count > 0 && (
                    <div className="mt-2">
                      <div className="flex items-center justify-between text-xs mb-1">
                        <span>Usage</span>
                        <span>{credential.usage_count}/{credential.max_concurrent_uses}</span>
                      </div>
                      <Progress 
                        value={(credential.usage_count / credential.max_concurrent_uses) * 100} 
                        className="h-1" 
                      />
                    </div>
                  )}
                </div>
                
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => handleTestCredential(credential.id)}
                    disabled={testingCredential === credential.id || !credential.is_active}
                  >
                    {testingCredential === credential.id ? (
                      <RotateCcw className="h-4 w-4 animate-spin mr-1" />
                    ) : (
                      <TestTube className="h-4 w-4 mr-1" />
                    )}
                    Test
                  </Button>
                  
                  {onCredentialSelected && (
                    <Button
                      size="sm"
                      onClick={() => onCredentialSelected(credential.id)}
                      disabled={!credential.is_active}
                      className="bg-hsl(var(--primary)) hover:bg-hsl(var(--primary))/90"
                    >
                      Select
                    </Button>
                  )}
                  
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => handleRevokeCredential(credential.id)}
                    disabled={!credential.is_active}
                    className="text-red-600 hover:text-red-700"
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            ))}
            
            {credentials.length === 0 && !loading && (
              <Alert>
                <Key className="h-4 w-4" />
                <AlertDescription>
                  No secure credentials found. Create your first credential to start using the TRL 10 discovery engine.
                </AlertDescription>
              </Alert>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};