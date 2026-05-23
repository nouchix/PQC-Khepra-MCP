import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { ExternalLink, Copy, CheckCircle, Download } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

interface AWSConnectorProps {
  organizationId: string;
  onSuccess: (connectionId: string) => void;
  onError: () => void;
}

export default function AWSConnector({ organizationId, onSuccess, onError }: AWSConnectorProps) {
  const [method, setMethod] = useState<'cloudformation' | 'manual'>('cloudformation');
  const [loading, setLoading] = useState(false);
  const [externalId] = useState(() => `nouchix-${crypto.randomUUID().substring(0, 8)}`);
  const [roleArn, setRoleArn] = useState('');
  const { toast } = useToast();

  const generateCloudFormationTemplate = () => {
    const template = {
      AWSTemplateFormatVersion: '2010-09-09',
      Description: 'NouchiX STIGs Discovery - AWS Read-Only Access Role',
      Parameters: {
        ExternalId: {
          Type: 'String',
          Default: externalId,
          Description: 'External ID for secure cross-account access'
        }
      },
      Resources: {
        NouchiXDiscoveryRole: {
          Type: 'AWS::IAM::Role',
          Properties: {
            RoleName: 'NouchiX-STIGs-Discovery-Role',
            AssumeRolePolicyDocument: {
              Version: '2012-10-17',
              Statement: [{
                Effect: 'Allow',
                Principal: {
                  AWS: 'arn:aws:iam::YOUR_NOUCHIX_ACCOUNT:root'
                },
                Action: 'sts:AssumeRole',
                Condition: {
                  StringEquals: {
                    'sts:ExternalId': { Ref: 'ExternalId' }
                  }
                }
              }]
            },
            ManagedPolicyArns: [
              'arn:aws:iam::aws:policy/SecurityAudit',
              'arn:aws:iam::aws:policy/ReadOnlyAccess'
            ],
            Tags: [
              { Key: 'Purpose', Value: 'NouchiX-STIGs-Discovery' },
              { Key: 'ManagedBy', Value: 'NouchiX' }
            ]
          }
        }
      },
      Outputs: {
        RoleArn: {
          Description: 'ARN of the created IAM role',
          Value: { 'Fn::GetAtt': ['NouchiXDiscoveryRole', 'Arn'] }
        },
        ExternalId: {
          Description: 'External ID for role assumption',
          Value: { Ref: 'ExternalId' }
        }
      }
    };
    return JSON.stringify(template, null, 2);
  };

  const cloudFormationUrl = () => {
    const template = generateCloudFormationTemplate();
    const encodedTemplate = encodeURIComponent(template);
    return `https://console.aws.amazon.com/cloudformation/home#/stacks/create/review?templateURL=data:text/plain,${encodedTemplate}&stackName=NouchiX-STIGs-Discovery`;
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({ title: 'Copied to clipboard' });
  };

  const downloadCloudFormationTemplate = () => {
    const template = generateCloudFormationTemplate();
    const blob = new Blob([template], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'nouchix-stigs-discovery-cloudformation.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast({ title: 'Template Downloaded', description: 'CloudFormation template saved to your downloads' });
  };

  const handleConnect = async () => {
    if (!roleArn) {
      toast({ title: 'Error', description: 'Please enter the Role ARN', variant: 'destructive' });
      return;
    }

    setLoading(true);
    try {
      // Store connection in database
      const { data: connection, error: dbError } = await supabase
        .from('cloud_connections' as any)
        .insert({
          organization_id: organizationId,
          cloud_provider: 'aws',
          connection_type: method,
          connection_name: 'AWS Account',
          role_arn: roleArn,
          external_id: externalId,
          status: 'pending'
        })
        .select()
        .single() as any;

      if (dbError) throw dbError;

      // Trigger discovery
      const { data: discoveryData, error: discoveryError } = await supabase.functions.invoke(
        'cloud-asset-discovery',
        {
          body: {
            connectionId: connection?.id,
            provider: 'aws',
            roleArn,
            externalId
          }
        }
      );

      if (discoveryError) throw discoveryError;

      toast({
        title: 'AWS Connected Successfully',
        description: `Discovered ${discoveryData.assetsFound || 0} assets. Discovery running...`
      });

      onSuccess(connection?.id);
    } catch (error: any) {
      console.error('AWS connection error:', error);
      toast({
        title: 'Connection Failed',
        description: error.message || 'Failed to connect to AWS',
        variant: 'destructive'
      });
      onError();
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <Tabs value={method} onValueChange={(v) => setMethod(v as any)}>
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="cloudformation">CloudFormation (Recommended)</TabsTrigger>
          <TabsTrigger value="manual">Manual IAM Role</TabsTrigger>
        </TabsList>

        <TabsContent value="cloudformation" className="space-y-4">
          <Alert>
            <AlertDescription>
              <strong>One-Click Setup:</strong> Launch our CloudFormation stack to automatically create a secure,
              read-only IAM role with the necessary permissions for STIG discovery.
            </AlertDescription>
          </Alert>

          <div className="space-y-4">
            <div>
              <Label>External ID (for security)</Label>
              <div className="flex gap-2 mt-2">
                <Input value={externalId} readOnly className="font-mono text-sm" />
                <Button
                  variant="outline"
                  size="icon"
                  onClick={() => copyToClipboard(externalId)}
                >
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                This unique ID ensures only NouchiX can assume the role
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <Button
                onClick={downloadCloudFormationTemplate}
                variant="outline"
                size="lg"
              >
                <Download className="mr-2 h-4 w-4" />
                Download Template
              </Button>
              <Button
                onClick={() => globalThis.open(cloudFormationUrl(), '_blank')}
                size="lg"
              >
                <ExternalLink className="mr-2 h-4 w-4" />
                Launch in AWS
              </Button>
            </div>

            <div className="border-t pt-4">
              <Label>After stack creation, paste the Role ARN here:</Label>
              <div className="flex gap-2 mt-2">
                <Input
                  placeholder="arn:aws:iam::123456789012:role/NouchiX-STIGs-Discovery-Role"
                  value={roleArn}
                  onChange={(e) => setRoleArn(e.target.value)}
                />
                <Button onClick={handleConnect} disabled={loading}>
                  {loading ? 'Connecting...' : 'Connect'}
                </Button>
              </div>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="manual" className="space-y-4">
          <Alert>
            <AlertDescription>
              Manually create an IAM role with SecurityAudit and ReadOnlyAccess policies.
              The role must trust NouchiX's AWS account and use the External ID below.
            </AlertDescription>
          </Alert>

          <div className="space-y-4">
            <div>
              <Label>External ID</Label>
              <div className="flex gap-2 mt-2">
                <Input value={externalId} readOnly className="font-mono text-sm" />
                <Button
                  variant="outline"
                  size="icon"
                  onClick={() => copyToClipboard(externalId)}
                >
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
            </div>

            <div>
              <Label>Role ARN</Label>
              <Input
                placeholder="arn:aws:iam::123456789012:role/YourRoleName"
                value={roleArn}
                onChange={(e) => setRoleArn(e.target.value)}
                className="mt-2"
              />
            </div>

            <Button onClick={handleConnect} disabled={loading} className="w-full">
              {loading ? 'Connecting...' : 'Connect AWS Account'}
            </Button>
          </div>
        </TabsContent>
      </Tabs>

      <Alert>
        <CheckCircle className="h-4 w-4" />
        <AlertDescription>
          <strong>Security:</strong> NouchiX uses read-only access and never modifies your AWS resources.
          All data is encrypted in transit and at rest.
        </AlertDescription>
      </Alert>
    </div>
  );
}
