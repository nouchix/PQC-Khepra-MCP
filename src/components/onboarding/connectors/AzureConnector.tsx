import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { ExternalLink, CheckCircle, Download, Copy } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

interface AzureConnectorProps {
  organizationId: string;
  onSuccess: (connectionId: string) => void;
  onError: () => void;
}

export default function AzureConnector({ organizationId, onSuccess, onError }: AzureConnectorProps) {
  const [loading, setLoading] = useState(false);
  const [tenantId, setTenantId] = useState('');
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [subscriptionId, setSubscriptionId] = useState('');
  const { toast } = useToast();

  const generateARMTemplate = () => {
    const template = {
      "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
      "contentVersion": "1.0.0.0",
      "parameters": {
        "applicationName": {
          "type": "string",
          "defaultValue": "NouchiX-STIGs-Discovery",
          "metadata": {
            "description": "Name of the service principal application"
          }
        }
      },
      "variables": {
        "readerRoleDefinitionId": "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.Authorization/roleDefinitions/', 'acdd72a7-3385-48ef-bd42-f606fba81ae7')]"
      },
      "resources": [
        {
          "type": "Microsoft.Authorization/roleAssignments",
          "apiVersion": "2022-04-01",
          "name": "[guid(subscription().id, parameters('applicationName'))]",
          "properties": {
            "roleDefinitionId": "[variables('readerRoleDefinitionId')]",
            "principalId": "[parameters('applicationName')]",
            "principalType": "ServicePrincipal"
          }
        }
      ],
      "outputs": {
        "subscriptionId": {
          "type": "string",
          "value": "[subscription().subscriptionId]"
        },
        "tenantId": {
          "type": "string",
          "value": "[subscription().tenantId]"
        }
      }
    };
    return JSON.stringify(template, null, 2);
  };

  const downloadARMTemplate = () => {
    const template = generateARMTemplate();
    const blob = new Blob([template], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'nouchix-stigs-discovery-azure-arm.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast({ title: 'ARM Template Downloaded', description: 'Azure Resource Manager template saved' });
  };

  const downloadPowerShellScript = () => {
    const script = `# NouchiX STIGs Discovery - Azure Service Principal Setup
$appName = "NouchiX-STIGs-Discovery"
$subscriptionId = "${subscriptionId || '<your-subscription-id>'}"

# Login to Azure
Connect-AzAccount

# Select subscription
Select-AzSubscription -SubscriptionId $subscriptionId

# Create service principal with Reader role
$sp = New-AzADServicePrincipal -DisplayName $appName -Role "Reader"

# Output credentials (SAVE THESE SECURELY)
Write-Host "Tenant ID: $((Get-AzContext).Tenant.Id)"
Write-Host "Subscription ID: $subscriptionId"
Write-Host "Client ID (Application ID): $($sp.ApplicationId)"
Write-Host "Client Secret: $($sp.PasswordCredentials.SecretText)"

Write-Host ""
Write-Host "⚠️  IMPORTANT: Save the Client Secret now - it cannot be retrieved later!"
`;
    const blob = new Blob([script], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'setup-nouchix-azure.ps1';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast({ title: 'PowerShell Script Downloaded', description: 'Run this script in Azure Cloud Shell or PowerShell' });
  };

  const handleConnect = async () => {
    if (!tenantId || !clientId || !clientSecret || !subscriptionId) {
      toast({ title: 'Error', description: 'Please fill in all fields', variant: 'destructive' });
      return;
    }

    setLoading(true);
    try {
      const { data: connection, error: dbError } = await supabase
        .from('cloud_connections' as any)
        .insert({
          organization_id: organizationId,
          cloud_provider: 'azure',
          connection_type: 'service_principal',
          connection_name: 'Azure Subscription',
          tenant_id: tenantId,
          client_id: clientId,
          subscription_id: subscriptionId,
          status: 'pending'
        })
        .select()
        .single() as any;

      if (dbError) throw dbError;

      const { data: discoveryData, error: discoveryError } = await supabase.functions.invoke(
        'cloud-asset-discovery',
        {
          body: {
            connectionId: connection?.id,
            provider: 'azure',
            tenantId,
            clientId,
            clientSecret,
            subscriptionId
          }
        }
      );

      if (discoveryError) throw discoveryError;

      toast({
        title: 'Azure Connected Successfully',
        description: `Discovered ${discoveryData.assetsFound || 0} assets. Discovery running...`
      });

      onSuccess(connection?.id);
    } catch (error: any) {
      console.error('Azure connection error:', error);
      toast({
        title: 'Connection Failed',
        description: error.message || 'Failed to connect to Azure',
        variant: 'destructive'
      });
      onError();
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <Alert>
        <AlertDescription>
          <strong>Azure Service Principal Setup:</strong> Create a service principal with Reader role
          on your subscription for read-only STIG discovery access.
        </AlertDescription>
      </Alert>

      <div className="grid grid-cols-2 gap-3 mb-4">
        <Button onClick={downloadARMTemplate} variant="outline">
          <Download className="mr-2 h-4 w-4" />
          Download ARM Template
        </Button>
        <Button onClick={downloadPowerShellScript} variant="outline">
          <Download className="mr-2 h-4 w-4" />
          Download Setup Script
        </Button>
      </div>

      <div className="space-y-4">
        <div>
          <Label>Tenant ID</Label>
          <Input
            placeholder="00000000-0000-0000-0000-000000000000"
            value={tenantId}
            onChange={(e) => setTenantId(e.target.value)}
            className="mt-2"
          />
        </div>

        <div>
          <Label>Client ID (Application ID)</Label>
          <Input
            placeholder="00000000-0000-0000-0000-000000000000"
            value={clientId}
            onChange={(e) => setClientId(e.target.value)}
            className="mt-2"
          />
        </div>

        <div>
          <Label>Client Secret</Label>
          <Input
            type="password"
            placeholder="Your service principal secret"
            value={clientSecret}
            onChange={(e) => setClientSecret(e.target.value)}
            className="mt-2"
          />
        </div>

        <div>
          <Label>Subscription ID</Label>
          <Input
            placeholder="00000000-0000-0000-0000-000000000000"
            value={subscriptionId}
            onChange={(e) => setSubscriptionId(e.target.value)}
            className="mt-2"
          />
        </div>

        <Button onClick={handleConnect} disabled={loading} className="w-full">
          {loading ? 'Connecting...' : 'Connect Azure Subscription'}
        </Button>
      </div>

      <Alert>
        <CheckCircle className="h-4 w-4" />
        <AlertDescription>
          <strong>Security:</strong> Credentials are encrypted at rest. NouchiX only requires Reader role
          and never modifies your Azure resources.
        </AlertDescription>
      </Alert>

      <Button
        variant="link"
        onClick={() => globalThis.open('https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal', '_blank')}
      >
        <ExternalLink className="mr-2 h-4 w-4" />
        How to create a Service Principal
      </Button>
    </div>
  );
}
