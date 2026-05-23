import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Eye, 
  EyeOff, 
  Upload, 
  Key, 
  Server, 
  FileText,
  AlertTriangle,
  Plus,
  X
} from 'lucide-react';
import { WizardData } from '../DataSourcesWizard';

interface ConnectionDetailsStepProps {
  data: WizardData;
  onUpdate: (updates: Partial<WizardData>) => void;
}

export const ConnectionDetailsStep: React.FC<ConnectionDetailsStepProps> = ({
  data,
  onUpdate
}) => {
  const [showPasswords, setShowPasswords] = useState<Record<string, boolean>>({});
  const [bulkImportText, setBulkImportText] = useState('');

  const togglePasswordVisibility = (field: string) => {
    setShowPasswords(prev => ({
      ...prev,
      [field]: !prev[field]
    }));
  };

  const updateConnectionDetail = (environmentType: string, field: string, value: any) => {
    const currentDetails = data.connectionDetails[environmentType] || {};
    const updatedDetails = {
      ...data.connectionDetails,
      [environmentType]: {
        ...currentDetails,
        [field]: value
      }
    };
    onUpdate({ connectionDetails: updatedDetails });
  };

  const addHostToList = (environmentType: string) => {
    const currentDetails = data.connectionDetails[environmentType] || {};
    const hosts = currentDetails.hosts || [];
    const updatedDetails = {
      ...data.connectionDetails,
      [environmentType]: {
        ...currentDetails,
        hosts: [...hosts, { hostname: '', ip: '', port: '' }]
      }
    };
    onUpdate({ connectionDetails: updatedDetails });
  };

  const updateHost = (environmentType: string, index: number, field: string, value: string) => {
    const currentDetails = data.connectionDetails[environmentType] || {};
    const hosts = [...(currentDetails.hosts || [])];
    hosts[index] = { ...hosts[index], [field]: value };
    
    const updatedDetails = {
      ...data.connectionDetails,
      [environmentType]: {
        ...currentDetails,
        hosts
      }
    };
    onUpdate({ connectionDetails: updatedDetails });
  };

  const removeHost = (environmentType: string, index: number) => {
    const currentDetails = data.connectionDetails[environmentType] || {};
    const hosts = [...(currentDetails.hosts || [])];
    hosts.splice(index, 1);
    
    const updatedDetails = {
      ...data.connectionDetails,
      [environmentType]: {
        ...currentDetails,
        hosts
      }
    };
    onUpdate({ connectionDetails: updatedDetails });
  };

  const processBulkImport = (environmentType: string) => {
    const lines = bulkImportText.trim().split('\n');
    const hosts = lines.map(line => {
      const parts = line.split(',').map(p => p.trim());
      return {
        hostname: parts[0] || '',
        ip: parts[1] || '',
        port: parts[2] || ''
      };
    }).filter(host => host.hostname || host.ip);

    const currentDetails = data.connectionDetails[environmentType] || {};
    const updatedDetails = {
      ...data.connectionDetails,
      [environmentType]: {
        ...currentDetails,
        hosts: [...(currentDetails.hosts || []), ...hosts]
      }
    };
    onUpdate({ connectionDetails: updatedDetails });
    setBulkImportText('');
  };

  const getConnectionMethod = (environmentType: string) => {
    return data.connectionMethods[environmentType];
  };

  const renderConnectionForm = (environmentType: string) => {
    const method = getConnectionMethod(environmentType);
    const details = data.connectionDetails[environmentType] || {};

    switch (method) {
      case 'ssh-winrm':
        return (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label htmlFor={`${environmentType}-username`}>Username</Label>
                <Input
                  id={`${environmentType}-username`}
                  value={details.username || ''}
                  onChange={(e) => updateConnectionDetail(environmentType, 'username', e.target.value)}
                  placeholder="admin or domain\\username"
                />
              </div>
              <div>
                <Label htmlFor={`${environmentType}-password`}>Password</Label>
                <div className="relative">
                  <Input
                    id={`${environmentType}-password`}
                    type={showPasswords[`${environmentType}-password`] ? 'text' : 'password'}
                    value={details.password || ''}
                    onChange={(e) => updateConnectionDetail(environmentType, 'password', e.target.value)}
                    placeholder="Enter password"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="absolute right-0 top-0 h-full px-3"
                    onClick={() => togglePasswordVisibility(`${environmentType}-password`)}
                  >
                    {showPasswords[`${environmentType}-password`] ? 
                      <EyeOff className="h-4 w-4" /> : 
                      <Eye className="h-4 w-4" />
                    }
                  </Button>
                </div>
              </div>
            </div>
            <div>
              <Label>SSH Private Key (Optional)</Label>
              <Textarea
                value={details.privateKey || ''}
                onChange={(e) => updateConnectionDetail(environmentType, 'privateKey', e.target.value)}
                placeholder="-----BEGIN PRIVATE KEY-----"
                rows={4}
              />
            </div>
          </div>
        );

      case 'api-credentials':
        return (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label htmlFor={`${environmentType}-access-key`}>Access Key ID</Label>
                <Input
                  id={`${environmentType}-access-key`}
                  value={details.accessKeyId || ''}
                  onChange={(e) => updateConnectionDetail(environmentType, 'accessKeyId', e.target.value)}
                  placeholder="AKIA..."
                />
              </div>
              <div>
                <Label htmlFor={`${environmentType}-secret-key`}>Secret Access Key</Label>
                <div className="relative">
                  <Input
                    id={`${environmentType}-secret-key`}
                    type={showPasswords[`${environmentType}-secret`] ? 'text' : 'password'}
                    value={details.secretAccessKey || ''}
                    onChange={(e) => updateConnectionDetail(environmentType, 'secretAccessKey', e.target.value)}
                    placeholder="Enter secret key"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="absolute right-0 top-0 h-full px-3"
                    onClick={() => togglePasswordVisibility(`${environmentType}-secret`)}
                  >
                    {showPasswords[`${environmentType}-secret`] ? 
                      <EyeOff className="h-4 w-4" /> : 
                      <Eye className="h-4 w-4" />
                    }
                  </Button>
                </div>
              </div>
            </div>
            <div>
              <Label htmlFor={`${environmentType}-region`}>Default Region</Label>
              <Input
                id={`${environmentType}-region`}
                value={details.region || ''}
                onChange={(e) => updateConnectionDetail(environmentType, 'region', e.target.value)}
                placeholder="us-east-1, eastus, us-central1"
              />
            </div>
          </div>
        );

      case 'snmp':
        return (
          <div className="space-y-4">
            <div className="grid grid-cols-3 gap-4">
              <div>
                <Label htmlFor={`${environmentType}-community`}>Community String</Label>
                <Input
                  id={`${environmentType}-community`}
                  value={details.community || ''}
                  onChange={(e) => updateConnectionDetail(environmentType, 'community', e.target.value)}
                  placeholder="public, private"
                />
              </div>
              <div>
                <Label htmlFor={`${environmentType}-snmp-version`}>SNMP Version</Label>
                <select
                  className="w-full h-10 px-3 rounded-md border border-border bg-background"
                  value={details.version || 'v2c'}
                  onChange={(e) => updateConnectionDetail(environmentType, 'version', e.target.value)}
                >
                  <option value="v1">SNMPv1</option>
                  <option value="v2c">SNMPv2c</option>
                  <option value="v3">SNMPv3 (Secure)</option>
                </select>
              </div>
              <div>
                <Label htmlFor={`${environmentType}-port`}>SNMP Port</Label>
                <Input
                  id={`${environmentType}-port`}
                  value={details.port || '161'}
                  onChange={(e) => updateConnectionDetail(environmentType, 'port', e.target.value)}
                  placeholder="161"
                />
              </div>
            </div>
          </div>
        );

      default:
        return (
          <div className="text-center py-8 text-muted-foreground">
            Configuration form for {method} will be implemented here.
          </div>
        );
    }
  };

  const renderHostsList = (environmentType: string) => {
    const details = data.connectionDetails[environmentType] || {};
    const hosts = details.hosts || [];

    return (
      <div className="space-y-4">
        {hosts.map((host: any, index: number) => (
          <div key={index} className="flex items-center space-x-2 p-3 border rounded-lg">
            <Input
              placeholder="Hostname or FQDN"
              value={host.hostname || ''}
              onChange={(e) => updateHost(environmentType, index, 'hostname', e.target.value)}
              className="flex-1"
            />
            <Input
              placeholder="IP Address"
              value={host.ip || ''}
              onChange={(e) => updateHost(environmentType, index, 'ip', e.target.value)}
              className="w-32"
            />
            <Input
              placeholder="Port"
              value={host.port || ''}
              onChange={(e) => updateHost(environmentType, index, 'port', e.target.value)}
              className="w-20"
            />
            <Button
              variant="ghost"
              size="sm"
              onClick={() => removeHost(environmentType, index)}
              className="text-red-500 hover:text-red-600"
            >
              <X className="h-4 w-4" />
            </Button>
          </div>
        ))}
        
        <div className="flex space-x-2">
          <Button
            variant="outline"
            onClick={() => addHostToList(environmentType)}
            className="flex-1"
          >
            <Plus className="h-4 w-4 mr-2" />
            Add Host
          </Button>
        </div>
      </div>
    );
  };

  const getEnvironmentTitle = (envId: string) => {
    const titles: Record<string, string> = {
      'cloud-aws': 'AWS Cloud Infrastructure',
      'cloud-azure': 'Microsoft Azure',
      'cloud-gcp': 'Google Cloud Platform',
      'servers-windows': 'Windows Servers',
      'servers-linux': 'Linux Servers',
      'containers-docker': 'Docker Containers',
      'containers-k8s': 'Kubernetes Clusters',
      'industrial-plc': 'PLCs and RTUs',
      'industrial-scada': 'SCADA Systems',
      'energy-solar': 'Solar Power Systems',
      'energy-wind': 'Wind Power Systems',
      'energy-battery': 'Battery Storage Systems',
      'network-infrastructure': 'Network Infrastructure'
    };
    return titles[envId] || envId;
  };

  return (
    <div className="space-y-6">
      <div className="text-center space-y-2">
        <h3 className="text-lg font-semibold">Connection Details & Credentials</h3>
        <p className="text-muted-foreground">
          Provide authentication credentials and target hosts for each environment type.
        </p>
      </div>

      <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-4">
        <div className="flex items-center space-x-2">
          <AlertTriangle className="h-4 w-4 text-yellow-600" />
          <p className="text-sm text-yellow-700">
            All credentials are securely encrypted and stored using industry-standard security practices.
          </p>
        </div>
      </div>

      <div className="space-y-6">
        {Object.keys(data.connectionMethods).map((environmentType) => (
          <Card key={environmentType}>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2 text-base">
                <Key className="h-4 w-4 text-primary" />
                <span>{getEnvironmentTitle(environmentType)}</span>
              </CardTitle>
              <CardDescription>
                Connection method: {data.connectionMethods[environmentType]}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="credentials" className="w-full">
                <TabsList className="grid w-full grid-cols-3">
                  <TabsTrigger value="credentials">Credentials</TabsTrigger>
                  <TabsTrigger value="hosts">Target Hosts</TabsTrigger>
                  <TabsTrigger value="bulk">Bulk Import</TabsTrigger>
                </TabsList>
                
                <TabsContent value="credentials" className="space-y-4">
                  {renderConnectionForm(environmentType)}
                </TabsContent>
                
                <TabsContent value="hosts" className="space-y-4">
                  {renderHostsList(environmentType)}
                </TabsContent>
                
                <TabsContent value="bulk" className="space-y-4">
                  <div>
                    <Label htmlFor="bulk-import">Bulk Import Hosts</Label>
                    <p className="text-xs text-muted-foreground mb-2">
                      Enter one host per line in format: hostname,ip,port
                    </p>
                    <Textarea
                      id="bulk-import"
                      value={bulkImportText}
                      onChange={(e) => setBulkImportText(e.target.value)}
                      placeholder="server1.domain.com,192.168.1.10,22&#10;server2.domain.com,192.168.1.11,22"
                      rows={6}
                    />
                    <Button
                      onClick={() => processBulkImport(environmentType)}
                      disabled={!bulkImportText.trim()}
                      className="mt-2"
                    >
                      <Upload className="h-4 w-4 mr-2" />
                      Import Hosts
                    </Button>
                  </div>
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
};