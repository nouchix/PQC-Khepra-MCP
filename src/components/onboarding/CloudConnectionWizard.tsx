import { useState } from 'react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Cloud, Server, Network, CheckCircle2 } from 'lucide-react';
import AWSConnector from './connectors/AWSConnector';
import AzureConnector from './connectors/AzureConnector';
import GCPConnector from './connectors/GCPConnector';
import OnPremisesConnector from './connectors/OnPremisesConnector';

interface CloudConnectionWizardProps {
  organizationId: string;
  onConnectionComplete: (connectionId: string) => void;
  onSkip?: () => void;
}

export default function CloudConnectionWizard({
  organizationId,
  onConnectionComplete,
  onSkip
}: CloudConnectionWizardProps) {
  const [selectedProvider, setSelectedProvider] = useState<string>('aws');
  const [connectionStatus, setConnectionStatus] = useState<{
    [key: string]: 'idle' | 'connecting' | 'connected' | 'failed';
  }>({});

  const providers = [
    {
      id: 'aws',
      name: 'Amazon Web Services',
      icon: Cloud,
      description: 'Connect via CloudFormation or IAM Role',
      popular: true
    },
    {
      id: 'azure',
      name: 'Microsoft Azure',
      icon: Cloud,
      description: 'Connect via Service Principal',
      popular: true
    },
    {
      id: 'gcp',
      name: 'Google Cloud Platform',
      icon: Cloud,
      description: 'Connect via Service Account',
      popular: true
    },
    {
      id: 'on-premises',
      name: 'On-Premises / Network',
      icon: Network,
      description: 'Network scanning or agent deployment',
      popular: false
    }
  ];

  const handleConnectionSuccess = (connectionId: string, provider: string) => {
    setConnectionStatus({ ...connectionStatus, [provider]: 'connected' });
    onConnectionComplete(connectionId);
  };

  const handleConnectionError = (provider: string) => {
    setConnectionStatus({ ...connectionStatus, [provider]: 'failed' });
  };

  return (
    <div className="space-y-8">
      <div className="text-center space-y-3">
        <h2 className="text-4xl font-bold bg-gradient-to-r from-primary to-primary/60 bg-clip-text text-transparent">
          Connect Your Infrastructure
        </h2>
        <p className="text-lg text-muted-foreground max-w-3xl mx-auto">
          One-click connection to AWS, Azure, GCP, or secure on-premises networks for comprehensive STIG discovery
        </p>
      </div>

      {/* Provider Selection Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {providers.map((provider) => {
          const Icon = provider.icon;
          const status = connectionStatus[provider.id] || 'idle';
          
          return (
            <Card
              key={provider.id}
              className={`group p-8 cursor-pointer transition-all duration-200 hover:shadow-xl border-2 ${
                selectedProvider === provider.id 
                  ? 'border-primary shadow-lg shadow-primary/20 scale-[1.02]' 
                  : 'border-border hover:border-primary/50'
              } ${
                status === 'connected' ? 'bg-gradient-to-br from-green-500/5 to-green-500/10 border-green-500/30' : ''
              }`}
              onClick={() => setSelectedProvider(provider.id)}
            >
              <div className="flex items-start gap-4">
                <div className={`p-4 rounded-xl transition-all ${
                  status === 'connected' 
                    ? 'bg-green-500/10 shadow-lg shadow-green-500/20' 
                    : selectedProvider === provider.id
                      ? 'bg-primary/10 shadow-lg shadow-primary/20'
                      : 'bg-muted group-hover:bg-primary/10'
                }`}>
                  {status === 'connected' ? (
                    <CheckCircle2 className="h-8 w-8 text-green-600" />
                  ) : (
                    <Icon className="h-8 w-8 text-primary transition-transform group-hover:scale-110" />
                  )}
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <h3 className="font-bold text-lg">{provider.name}</h3>
                    {provider.popular && (
                      <span className="text-xs bg-primary/10 text-primary px-2 py-1 rounded-full font-medium">
                        Most Popular
                      </span>
                    )}
                  </div>
                  <p className="text-sm text-muted-foreground">{provider.description}</p>
                  {status === 'connected' && (
                    <p className="text-sm text-green-600 mt-3 font-semibold flex items-center gap-1">
                      <CheckCircle2 className="h-4 w-4" />
                      Successfully Connected
                    </p>
                  )}
                  {status === 'failed' && (
                    <p className="text-sm text-destructive mt-3 font-semibold">⚠ Connection failed - Please retry</p>
                  )}
                </div>
              </div>
            </Card>
          );
        })}
      </div>

      {/* Connection Form */}
      <Card className="p-8 border-2 shadow-lg">
        <Tabs value={selectedProvider} onValueChange={setSelectedProvider}>
          <TabsList className="grid w-full grid-cols-4 h-12 bg-muted/50">
            <TabsTrigger value="aws" className="font-medium data-[state=active]:bg-background data-[state=active]:shadow-md">AWS</TabsTrigger>
            <TabsTrigger value="azure" className="font-medium data-[state=active]:bg-background data-[state=active]:shadow-md">Azure</TabsTrigger>
            <TabsTrigger value="gcp" className="font-medium data-[state=active]:bg-background data-[state=active]:shadow-md">GCP</TabsTrigger>
            <TabsTrigger value="on-premises" className="font-medium data-[state=active]:bg-background data-[state=active]:shadow-md">On-Premises</TabsTrigger>
          </TabsList>

          <TabsContent value="aws" className="space-y-4 mt-8">
            <AWSConnector
              organizationId={organizationId}
              onSuccess={(id) => handleConnectionSuccess(id, 'aws')}
              onError={() => handleConnectionError('aws')}
            />
          </TabsContent>

          <TabsContent value="azure" className="space-y-4 mt-8">
            <AzureConnector
              organizationId={organizationId}
              onSuccess={(id) => handleConnectionSuccess(id, 'azure')}
              onError={() => handleConnectionError('azure')}
            />
          </TabsContent>

          <TabsContent value="gcp" className="space-y-4 mt-8">
            <GCPConnector
              organizationId={organizationId}
              onSuccess={(id) => handleConnectionSuccess(id, 'gcp')}
              onError={() => handleConnectionError('gcp')}
            />
          </TabsContent>

          <TabsContent value="on-premises" className="space-y-4 mt-8">
            <OnPremisesConnector
              organizationId={organizationId}
              onSuccess={(id) => handleConnectionSuccess(id, 'on-premises')}
              onError={() => handleConnectionError('on-premises')}
            />
          </TabsContent>
        </Tabs>
      </Card>

      {onSkip && (
        <div className="text-center pt-4">
          <Button variant="ghost" onClick={onSkip} size="lg" className="text-muted-foreground hover:text-foreground">
            Skip for now - I'll connect later →
          </Button>
        </div>
      )}
    </div>
  );
}
