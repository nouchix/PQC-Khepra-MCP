"use client";
import { useState, useEffect } from 'react';
import { useParams } from '@/lib/router-compat';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import { supabase } from '@/integrations/supabase/client';
import { KhepraScansWidget } from '@/components/khepra/KhepraScansWidget';
import { KhepraLicenseWidget } from '@/components/khepra/KhepraLicenseWidget';
import { KhepraDAGVisualization } from '@/components/khepra/KhepraDAGVisualization';
import { useToast } from '@/hooks/use-toast';
import {
  Shield,
  Network,
  Key,
  Settings,
  Activity,
  BarChart3,
  Server,
  ExternalLink,
} from 'lucide-react';

interface DeploymentConfig {
  deploymentUrl: string;
  apiKey: string;
  organizationName: string;
}

/**
 * Validates a deployment URL and returns it only if it uses http/https.
 * Returns an empty string for any other scheme (javascript:, data:, etc.)
 * to prevent URL injection via user-supplied configuration. (CWE-601, alert #1)
 */
function sanitizeDeploymentUrl(url: string): string {
  if (!url || typeof url !== 'string') return '';
  try {
    const parsed = new URL(url);
    // Only allow http/https protocols. Any other scheme (javascript:, data:, etc.)
    // returns empty string, preventing protocol injection (CWE-601 / #539).
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return '';
    // Reconstruct a clean URL from parsed components (never pass raw user input).
    // encodeURI ensures any residual special chars are percent-encoded.
    const safe = parsed.origin + parsed.pathname + (parsed.search || '');
    return encodeURI(decodeURI(safe)); // normalize then encode
  } catch {
    // Unparseable URL — reject it
  }
  return '';
}

// Fetch deployment config from Supabase.
// NOTE: Both URL and API key are stored in sessionStorage (not localStorage) to avoid
// persisting connection config across browser sessions. (CWE-312 / alert #540)
async function getDeploymentConfig(orgId: string): Promise<DeploymentConfig | null> {
  const { data, error } = await supabase
    .from('deployments')
    .select('vps_url, api_key, organization_name')
    .eq('organization_id', orgId)
    .single();

  if (error || !data) {
    // Fall back to a locally cached (session-only) override if the org has no
    // registered deployment row yet, otherwise honestly report "not found" so the
    // UI shows the real "Deployment Not Found" state instead of fabricated defaults.
    const cachedUrl = sessionStorage.getItem(`khepra_url_${orgId}`);
    const cachedKey = sessionStorage.getItem(`khepra_key_${orgId}`);
    if (!cachedUrl) return null;
    return {
      deploymentUrl: cachedUrl,
      apiKey: cachedKey || '',
      organizationName: 'Organization',
    };
  }

  const deploymentUrl = data.vps_url || sessionStorage.getItem(`khepra_url_${orgId}`);
  if (!deploymentUrl) {
    // Row exists but has no usable URL yet — honestly report "not configured"
    // rather than fabricating a localhost placeholder.
    return null;
  }

  return {
    deploymentUrl,
    apiKey: data.api_key || sessionStorage.getItem(`khepra_key_${orgId}`) || '',
    organizationName: data.organization_name || 'Organization',
  };
}

export default function ClientPortal() {
  const { org_id } = useParams<{ org_id: string }>();
  const { toast } = useToast();

  const [config, setConfig] = useState<DeploymentConfig | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isConfigOpen, setIsConfigOpen] = useState(false);
  const [tempUrl, setTempUrl] = useState('');
  const [tempKey, setTempKey] = useState('');

  useEffect(() => {
    async function loadConfig() {
      if (!org_id) return;

      setIsLoading(true);
      try {
        const deploymentConfig = await getDeploymentConfig(org_id);
        setConfig(deploymentConfig);
        if (deploymentConfig) {
          setTempUrl(deploymentConfig.deploymentUrl);
          setTempKey(deploymentConfig.apiKey);
        }
      } catch (error) {
        console.error('Failed to load deployment config:', error);
        toast({
          title: 'Configuration Error',
          description: 'Failed to load deployment configuration.',
          variant: 'destructive',
        });
      } finally {
        setIsLoading(false);
      }
    }

    loadConfig();
  }, [org_id, toast]);

  const handleSaveConfig = () => {
    if (!org_id) return;

    // Security: Store only the non-sensitive deployment URL in sessionStorage.
    // API key is kept in memory (React state) only — not persisted to storage
    // to prevent CWE-312 clear-text storage of sensitive credentials. (#540)
    sessionStorage.setItem(`khepra_url_${org_id}`, tempUrl);

    setConfig({
      ...config!,
      deploymentUrl: tempUrl,
      apiKey: tempKey,
    });

    setIsConfigOpen(false);

    toast({
      title: 'Configuration Saved',
      description: 'Your Khepra deployment settings have been updated.',
    });
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <Shield className="h-12 w-12 animate-pulse mx-auto mb-4 text-primary" />
          <p className="text-muted-foreground">Loading Client Portal...</p>
        </div>
      </div>
    );
  }

  if (!config) {
    return (
      <div className="container mx-auto py-8">
        <Card>
          <CardHeader>
            <CardTitle>Deployment Not Found</CardTitle>
            <CardDescription>
              No Khepra deployment is configured for this organization.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button onClick={() => setIsConfigOpen(true)}>
              Configure Deployment
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="container mx-auto py-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Shield className="h-8 w-8 text-primary" />
            Khepra Client Portal
          </h1>
          <p className="text-muted-foreground mt-1">
            {config.organizationName} - Real-time security monitoring
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="flex items-center gap-1">
            <Server className="h-3 w-3" />
            {new URL(config.deploymentUrl).host}
          </Badge>

          <Dialog open={isConfigOpen} onOpenChange={setIsConfigOpen}>
            <DialogTrigger asChild>
              <Button variant="outline" size="sm">
                <Settings className="h-4 w-4 mr-2" />
                Configure
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Deployment Configuration</DialogTitle>
                <DialogDescription>
                  Configure the connection to your Khepra VPS deployment.
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 py-4">
                <div className="space-y-2">
                  <Label htmlFor="url">Deployment URL</Label>
                  <Input
                    id="url"
                    placeholder="https://khepra.example.com:8080"
                    value={tempUrl}
                    onChange={(e) => setTempUrl(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="key">API Key</Label>
                  <Input
                    id="key"
                    type="password"
                    placeholder="Your machine ID or API key"
                    value={tempKey}
                    onChange={(e) => setTempKey(e.target.value)}
                  />
                </div>
                <Button onClick={handleSaveConfig} className="w-full">
                  Save Configuration
                </Button>
              </div>
            </DialogContent>
          </Dialog>

          <Button variant="outline" size="sm" asChild>
            {/* sanitizeDeploymentUrl enforces http/https only, preventing
                javascript: or data: URL injection. (alert #1) */}
            <a
              href={sanitizeDeploymentUrl(config.deploymentUrl)}
              target="_blank"
              rel="noopener noreferrer"
            >
              <ExternalLink className="h-4 w-4 mr-2" />
              Open API
            </a>
          </Button>
        </div>
      </div>

      {/* Main Content */}
      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="overview" className="flex items-center gap-2">
            <Activity className="h-4 w-4" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="scans" className="flex items-center gap-2">
            <Shield className="h-4 w-4" />
            Security Scans
          </TabsTrigger>
          <TabsTrigger value="dag" className="flex items-center gap-2">
            <Network className="h-4 w-4" />
            DAG Constellation
          </TabsTrigger>
          <TabsTrigger value="license" className="flex items-center gap-2">
            <Key className="h-4 w-4" />
            License
          </TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <KhepraScansWidget
              deploymentUrl={config.deploymentUrl}
              apiKey={config.apiKey}
            />
            <KhepraLicenseWidget
              deploymentUrl={config.deploymentUrl}
              apiKey={config.apiKey}
            />
          </div>
          <KhepraDAGVisualization
            deploymentUrl={config.deploymentUrl}
            apiKey={config.apiKey}
            height={400}
          />
        </TabsContent>

        {/* Scans Tab */}
        <TabsContent value="scans">
          <KhepraScansWidget
            deploymentUrl={config.deploymentUrl}
            apiKey={config.apiKey}
          />
        </TabsContent>

        {/* DAG Tab */}
        <TabsContent value="dag">
          <KhepraDAGVisualization
            deploymentUrl={config.deploymentUrl}
            apiKey={config.apiKey}
            height={600}
          />
        </TabsContent>

        {/* License Tab */}
        <TabsContent value="license">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <KhepraLicenseWidget
              deploymentUrl={config.deploymentUrl}
              apiKey={config.apiKey}
            />
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <BarChart3 className="h-5 w-5" />
                  Usage Statistics
                </CardTitle>
                <CardDescription>
                  License usage and API call metrics
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-4 text-center">
                  <div className="bg-muted rounded-lg p-4">
                    <div className="text-3xl font-bold text-primary">--</div>
                    <div className="text-sm text-muted-foreground">API Calls Today</div>
                  </div>
                  <div className="bg-muted rounded-lg p-4">
                    <div className="text-3xl font-bold text-primary">--</div>
                    <div className="text-sm text-muted-foreground">Scans This Month</div>
                  </div>
                  <div className="bg-muted rounded-lg p-4">
                    <div className="text-3xl font-bold text-green-600">--</div>
                    <div className="text-sm text-muted-foreground">Issues Resolved</div>
                  </div>
                  <div className="bg-muted rounded-lg p-4">
                    <div className="text-3xl font-bold text-orange-600">--</div>
                    <div className="text-sm text-muted-foreground">Open Findings</div>
                  </div>
                </div>
                <p className="text-xs text-muted-foreground mt-4 text-center">
                  Usage data will populate as you use the Khepra deployment.
                </p>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
