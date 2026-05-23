import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { AlertCircle, Cloud, Database, Shield, Activity } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { toast } from 'sonner';

interface CloudTrailConfig {
  channelArn: string;
  externalId: string;
  region: string;
  accountId: string;
  enabled: boolean;
}

interface AuditEvent {
  timestamp: string;
  eventSource: string;
  eventName: string;
  userIdentity: string;
  resources: string[];
  eventId: string;
}

export const AWSCloudTrailIntegration: React.FC = () => {
  const [config, setConfig] = useState<CloudTrailConfig>({
    channelArn: 'arn:aws:cloudtrail:us-east-1:445971788114:channel/de77d6a3-e98c-46f3-abbd-8925101cb20f',
    externalId: 'souhimbou-ai',
    region: 'us-east-1',
    accountId: '445971788114',
    enabled: true
  });

  const [recentEvents, setRecentEvents] = useState<AuditEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<'checking' | 'connected' | 'disconnected' | 'error'>('checking');

  useEffect(() => {
    checkConnection();
  }, [config.enabled]);

  const checkConnection = async () => {
    if (!config.enabled) {
      setConnectionStatus('disconnected');
      return;
    }

    setConnectionStatus('checking');
    try {
      // Simulate connection check
      await new Promise(resolve => setTimeout(resolve, 2000));
      setConnectionStatus('connected');
      setIsConnected(true);
      toast.success('AWS CloudTrail connection established');
    } catch (error) {
      setConnectionStatus('error');
      setIsConnected(false);
      toast.error('Failed to connect to AWS CloudTrail');
    }
  };

  const sendTestAuditEvent = async () => {
    if (!isConnected) {
      toast.error('Not connected to CloudTrail');
      return;
    }

    try {
      const testEvent = {
        eventVersion: '1.08',
        userIdentity: {
          type: 'IAMUser',
          principalId: 'KHEPRA-PROTOCOL-AGENT',
          arn: `arn:aws:iam::${config.accountId}:user/khepra-agent`,
          accountId: config.accountId,
          userName: 'khepra-agent'
        },
        eventTime: new Date().toISOString(),
        eventSource: 'khepra-protocol.ai',
        eventName: 'SecurityEventGenerated',
        awsRegion: config.region,
        sourceIPAddress: '127.0.0.1',
        userAgent: 'KHEPRA-Protocol/1.0',
        resources: [
          {
            accountId: config.accountId,
            type: 'AWS::CloudTrail::Channel',
            ARN: config.channelArn
          }
        ],
        eventType: 'AwsApiCall',
        managementEvent: false,
        recipientAccountId: config.accountId,
        serviceEventDetails: {
          connectivityType: 'Test',
          sessionCreationDateTime: new Date().toISOString()
        }
      };

      // In a real implementation, this would use AWS SDK to call cloudtrail-data:PutAuditEvents
      console.log('Sending audit event to CloudTrail:', testEvent);
      
      toast.success('Test audit event sent successfully');
      
      // Add to recent events display
      const displayEvent: AuditEvent = {
        timestamp: new Date().toISOString(),
        eventSource: 'khepra-protocol.ai',
        eventName: 'SecurityEventGenerated',
        userIdentity: 'khepra-agent',
        resources: [config.channelArn],
        eventId: `test-${Date.now()}`
      };
      
      setRecentEvents(prev => [displayEvent, ...prev.slice(0, 9)]);
    } catch (error) {
      toast.error('Failed to send test audit event');
      console.error('Error sending audit event:', error);
    }
  };

  const getStatusBadge = () => {
    switch (connectionStatus) {
      case 'connected':
        return <Badge variant="secondary" className="bg-emerald-500/10 text-emerald-700 border-emerald-200">Connected</Badge>;
      case 'disconnected':
        return <Badge variant="outline" className="text-muted-foreground">Disconnected</Badge>;
      case 'error':
        return <Badge variant="destructive">Error</Badge>;
      case 'checking':
        return <Badge variant="outline" className="text-blue-600">Checking...</Badge>;
      default:
        return <Badge variant="outline">Unknown</Badge>;
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Cloud className="h-5 w-5 text-blue-600" />
            AWS CloudTrail Integration
            {getStatusBadge()}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <Alert>
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>
              Integration with AWS CloudTrail Data Store: aws-nouchix-data-store
            </AlertDescription>
          </Alert>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="channelArn">Channel ARN</Label>
              <Input
                id="channelArn"
                value={config.channelArn}
                onChange={(e) => setConfig(prev => ({ ...prev, channelArn: e.target.value }))}
                className="font-mono text-sm"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="externalId">External ID</Label>
              <Input
                id="externalId"
                value={config.externalId}
                onChange={(e) => setConfig(prev => ({ ...prev, externalId: e.target.value }))}
                className="font-mono text-sm"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="region">AWS Region</Label>
              <Input
                id="region"
                value={config.region}
                onChange={(e) => setConfig(prev => ({ ...prev, region: e.target.value }))}
                className="font-mono text-sm"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="accountId">Account ID</Label>
              <Input
                id="accountId"
                value={config.accountId}
                onChange={(e) => setConfig(prev => ({ ...prev, accountId: e.target.value }))}
                className="font-mono text-sm"
              />
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <Switch
              id="enabled"
              checked={config.enabled}
              onCheckedChange={(checked) => setConfig(prev => ({ ...prev, enabled: checked }))}
            />
            <Label htmlFor="enabled">Enable CloudTrail Integration</Label>
          </div>

          <div className="flex gap-2">
            <Button onClick={checkConnection} variant="outline">
              <Activity className="h-4 w-4 mr-2" />
              Test Connection
            </Button>
            <Button onClick={sendTestAuditEvent} disabled={!isConnected}>
              <Shield className="h-4 w-4 mr-2" />
              Send Test Event
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="h-5 w-5 text-purple-600" />
            Recent Audit Events
          </CardTitle>
        </CardHeader>
        <CardContent>
          {recentEvents.length === 0 ? (
            <p className="text-muted-foreground text-center py-4">
              No recent events. Send a test event to see activity.
            </p>
          ) : (
            <div className="space-y-2">
              {recentEvents.map((event) => (
                <div key={event.eventId} className="border rounded-lg p-3 space-y-1">
                  <div className="flex justify-between items-start">
                    <div className="space-y-1">
                      <p className="font-semibold text-sm">{event.eventName}</p>
                      <p className="text-xs text-muted-foreground">{event.eventSource}</p>
                    </div>
                    <Badge variant="outline" className="text-xs">
                      {new Date(event.timestamp).toLocaleTimeString()}
                    </Badge>
                  </div>
                  <div className="text-xs space-y-1">
                    <p><span className="font-medium">User:</span> {event.userIdentity}</p>
                    <p><span className="font-medium">Resources:</span> {event.resources.length} resource(s)</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>CloudTrail Policy Configuration</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <Label htmlFor="policy">Current Channel Policy</Label>
            <Textarea
              id="policy"
              value={JSON.stringify({
                "Version": "2012-10-17",
                "Statement": [
                  {
                    "Sid": "ChannelPolicy",
                    "Effect": "Allow",
                    "Principal": {
                      "AWS": `arn:aws:iam::${config.accountId}:root`
                    },
                    "Action": "cloudtrail-data:PutAuditEvents",
                    "Resource": config.channelArn,
                    "Condition": {
                      "StringEquals": {
                        "cloudtrail:ExternalId": config.externalId
                      }
                    }
                  }
                ]
              }, null, 2)}
              rows={15}
              className="font-mono text-xs"
              readOnly
            />
          </div>
        </CardContent>
      </Card>
    </div>
  );
};