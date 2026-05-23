import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { Settings, Globe, Key, Shield, Webhook, CheckCircle, AlertCircle } from 'lucide-react';

interface KipSettings {
  kipUrl: string;
  platformId: string;
  culturalContext: string;
  webhookSecret: string;
  enableWebhooks: boolean;
  enableCulturalAuth: boolean;
  adinkraSymbols: string[];
  trustScoreThreshold: number;
}

const AVAILABLE_SYMBOLS = [
  { value: 'GYE_NYAME', label: 'Gye Nyame', meaning: 'Supremacy of divine power' },
  { value: 'SANKOFA', label: 'Sankofa', meaning: 'Learning from the past' },
  { value: 'DWENNIMMEN', label: 'Dwennimmen', meaning: 'Humility and wisdom' },
  { value: 'ADWO', label: 'Adwo', meaning: 'Tranquility and peace' },
  { value: 'MPATAPO', label: 'Mpatapo', meaning: 'Knot of reconciliation' },
  { value: 'FAWOHODIE', label: 'Fawohodie', meaning: 'Independence and freedom' },
  { value: 'NKYINKYIM', label: 'Nkyinkyim', meaning: 'Initiative and dynamism' }
];

export const KipIntegrationSettings = () => {
  const { toast } = useToast();
  const [settings, setSettings] = useState<KipSettings>({
    kipUrl: 'https://kip-project.lovable.app/khepra/v1',
    platformId: 'souhimbou-ai',
    culturalContext: 'souhimbou:integration:bridge',
    webhookSecret: '',
    enableWebhooks: true,
    enableCulturalAuth: true,
    adinkraSymbols: ['GYE_NYAME', 'SANKOFA', 'DWENNIMMEN'],
    trustScoreThreshold: 75
  });
  const [isLoading, setIsLoading] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<'testing' | 'connected' | 'disconnected'>('disconnected');

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) return;

      // Load existing settings from ai_agent_chats table
      const { data } = await supabase
        .from('ai_agent_chats')
        .select('*')
        .eq('user_id', user.id)
        .eq('message_type', 'kip_integration_settings')
        .order('created_at', { ascending: false })
        .limit(1);

      if (data && data.length > 0 && (data[0] as any).context) {
        const savedSettings = (data[0] as any).context as Record<string, any>;
        setSettings(prev => ({
          ...prev,
          ...Object.fromEntries(
            Object.entries(savedSettings).filter(([key]) => key in prev)
          )
        }));
      }
    } catch (error) {
      console.error('Error loading settings:', error);
    }
  };

  const saveSettings = async () => {
    setIsLoading(true);
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) throw new Error('User not authenticated');

      // Save settings to ai_agent_chats table
      const { error } = await supabase.from('ai_agent_chats').insert({
        user_id: user.id,
        organization_id: user.user_metadata?.organization_id || user.id,
        message_type: 'kip_integration_settings',
        message: 'KIP Integration Settings Updated',
        response: JSON.stringify(settings),
        context: settings as Record<string, any>,
        metadata: {
          source: 'kip_integration_settings',
          updated_at: new Date().toISOString()
        } as Record<string, any>
      });

      if (error) throw error;

      toast({
        title: "Settings Saved",
        description: "KIP integration settings have been updated successfully."
      });
    } catch (error) {
      console.error('Error saving settings:', error);
      toast({
        title: "Error",
        description: "Failed to save settings. Please try again.",
        variant: "destructive"
      });
    } finally {
      setIsLoading(false);
    }
  };

  const testConnection = async () => {
    setConnectionStatus('testing');
    try {
      const response = await fetch(`${settings.kipUrl}/healthz`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'KHEPRA-Platform-ID': settings.platformId
        }
      });

      if (response.ok) {
        setConnectionStatus('connected');
        toast({
          title: "Connection Successful",
          description: "Successfully connected to KIP platform."
        });
      } else {
        throw new Error('Connection failed');
      }
    } catch (error) {
      setConnectionStatus('disconnected');
      toast({
        title: "Connection Failed",
        description: "Unable to connect to KIP platform. Check your settings.",
        variant: "destructive"
      });
    }
  };

  const generateWebhookSecret = () => {
    const secret = crypto.randomUUID();
    setSettings(prev => ({ ...prev, webhookSecret: secret }));
  };

  const handleSymbolToggle = (symbol: string) => {
    setSettings(prev => ({
      ...prev,
      adinkraSymbols: prev.adinkraSymbols.includes(symbol)
        ? prev.adinkraSymbols.filter(s => s !== symbol)
        : [...prev.adinkraSymbols, symbol]
    }));
  };

  const getConnectionStatusIcon = () => {
    switch (connectionStatus) {
      case 'connected': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'testing': return <div className="h-4 w-4 animate-spin border-2 border-primary border-t-transparent rounded-full" />;
      default: return <AlertCircle className="h-4 w-4 text-red-500" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Connection Settings */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <div>
            <CardTitle className="text-lg font-medium flex items-center gap-2">
              <Globe className="h-5 w-5" />
              Connection Settings
            </CardTitle>
            <CardDescription>
              Configure the connection to your KIP project
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            {getConnectionStatusIcon()}
            <Button variant="outline" size="sm" onClick={testConnection}>
              Test Connection
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="kipUrl">KIP Project URL</Label>
              <Input
                id="kipUrl"
                value={settings.kipUrl}
                onChange={(e) => setSettings(prev => ({ ...prev, kipUrl: e.target.value }))}
                placeholder="https://your-kip-project.lovable.app/khepra/v1"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="platformId">Platform ID</Label>
              <Input
                id="platformId"
                value={settings.platformId}
                onChange={(e) => setSettings(prev => ({ ...prev, platformId: e.target.value }))}
                placeholder="souhimbou-ai"
              />
            </div>
          </div>
          <div className="space-y-2">
            <Label htmlFor="culturalContext">Cultural Context</Label>
            <Input
              id="culturalContext"
              value={settings.culturalContext}
              onChange={(e) => setSettings(prev => ({ ...prev, culturalContext: e.target.value }))}
              placeholder="souhimbou:integration:bridge"
            />
          </div>
        </CardContent>
      </Card>

      {/* Webhook Configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg font-medium flex items-center gap-2">
            <Webhook className="h-5 w-5" />
            Webhook Configuration
          </CardTitle>
          <CardDescription>
            Configure webhook endpoints and authentication
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>Enable Webhooks</Label>
              <p className="text-sm text-muted-foreground">
                Receive real-time events from KIP platform
              </p>
            </div>
            <Switch
              checked={settings.enableWebhooks}
              onCheckedChange={(checked) => setSettings(prev => ({ ...prev, enableWebhooks: checked }))}
            />
          </div>

          {settings.enableWebhooks && (
            <>
              <div className="space-y-2">
                <Label htmlFor="webhookSecret">Webhook Secret</Label>
                <div className="flex gap-2">
                  <Input
                    id="webhookSecret"
                    type="password"
                    value={settings.webhookSecret}
                    onChange={(e) => setSettings(prev => ({ ...prev, webhookSecret: e.target.value }))}
                    placeholder="Enter webhook secret for verification"
                  />
                  <Button variant="outline" onClick={generateWebhookSecret}>
                    Generate
                  </Button>
                </div>
              </div>

              <div className="space-y-2">
                <Label>Webhook Endpoints</Label>
                <div className="bg-muted p-3 rounded-lg text-sm font-mono space-y-1">
                  <div>Handler: https://{globalThis.location.hostname}/functions/v1/kip-webhook-handler</div>
                  <div>Matcher: https://{globalThis.location.hostname}/functions/v1/cultural-fingerprint-matcher</div>
                </div>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* Cultural Authentication */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg font-medium flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Cultural Authentication
          </CardTitle>
          <CardDescription>
            Configure Adinkra symbol-based authentication and trust scoring
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>Enable Cultural Authentication</Label>
              <p className="text-sm text-muted-foreground">
                Use Adinkra symbols for cultural context validation
              </p>
            </div>
            <Switch
              checked={settings.enableCulturalAuth}
              onCheckedChange={(checked) => setSettings(prev => ({ ...prev, enableCulturalAuth: checked }))}
            />
          </div>

          {settings.enableCulturalAuth && (
            <>
              <div className="space-y-2">
                <Label>Selected Adinkra Symbols</Label>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {AVAILABLE_SYMBOLS.map((symbol) => (
                    <div
                      key={symbol.value}
                      className={`p-3 border rounded-lg cursor-pointer transition-colors ${settings.adinkraSymbols.includes(symbol.value)
                          ? 'border-primary bg-primary/5'
                          : 'border-border'
                        }`}
                      onClick={() => handleSymbolToggle(symbol.value)}
                    >
                      <div className="flex items-center justify-between">
                        <div>
                          <div className="font-medium">{symbol.label}</div>
                          <div className="text-xs text-muted-foreground">{symbol.meaning}</div>
                        </div>
                        {settings.adinkraSymbols.includes(symbol.value) && (
                          <Badge variant="default">Selected</Badge>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="trustThreshold">Trust Score Threshold</Label>
                <div className="flex items-center gap-2">
                  <Input
                    id="trustThreshold"
                    type="number"
                    min="0"
                    max="100"
                    value={settings.trustScoreThreshold}
                    onChange={(e) => setSettings(prev => ({ ...prev, trustScoreThreshold: Number.parseInt(e.target.value) }))}
                    className="w-20"
                  />
                  <span className="text-sm text-muted-foreground">
                    Minimum trust score required for authentication
                  </span>
                </div>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* Save Button */}
      <div className="flex justify-end">
        <Button onClick={saveSettings} disabled={isLoading}>
          {isLoading ? 'Saving...' : 'Save Settings'}
        </Button>
      </div>
    </div>
  );
};