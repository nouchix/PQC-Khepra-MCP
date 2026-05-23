import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Download, Network, AlertCircle } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

interface OnPremisesConnectorProps {
  organizationId: string;
  onSuccess: (connectionId: string) => void;
  onError: () => void;
}

export default function OnPremisesConnector({ organizationId, onSuccess, onError }: OnPremisesConnectorProps) {
  const [loading, setLoading] = useState(false);
  const [method, setMethod] = useState<'network' | 'agent'>('network');
  const [networkRanges, setNetworkRanges] = useState('');
  const { toast } = useToast();

  const handleNetworkScan = async () => {
    if (!networkRanges) {
      toast({ title: 'Error', description: 'Please enter network ranges', variant: 'destructive' });
      return;
    }

    const ranges = networkRanges.split('\n').filter(r => r.trim());
    
    setLoading(true);
    try {
      const { data: connection, error: dbError } = await supabase
        .from('cloud_connections' as any)
        .insert({
          organization_id: organizationId,
          cloud_provider: 'on-premises',
          connection_type: 'network_scan',
          connection_name: 'On-Premises Network',
          network_ranges: ranges,
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
            provider: 'on-premises',
            method: 'network_scan',
            networkRanges: ranges
          }
        }
      );

      if (discoveryError) throw discoveryError;

      toast({
        title: 'Network Scan Started',
        description: `Scanning ${ranges.length} network range(s). This may take several minutes...`
      });

      onSuccess(connection?.id);
    } catch (error: any) {
      console.error('Network scan error:', error);
      toast({
        title: 'Scan Failed',
        description: error.message || 'Failed to start network scan',
        variant: 'destructive'
      });
      onError();
    } finally {
      setLoading(false);
    }
  };

  const downloadNetworkScanScript = () => {
    const script = `#!/bin/bash
# NouchiX STIGs Discovery - Network Scanning Script
# Requires: nmap, jq

SCAN_RANGES="${networkRanges.replace(/\n/g, ' ') || '192.168.1.0/24'}"
OUTPUT_FILE="nouchix-network-scan-$(date +%Y%m%d-%H%M%S).json"
ORGANIZATION_ID="${organizationId}"

echo "🔍 NouchiX STIGs Network Discovery"
echo "=================================="
echo "Scanning ranges: \${SCAN_RANGES}"
echo ""

# Create results array
echo "[" > \${OUTPUT_FILE}

for RANGE in \${SCAN_RANGES}; do
  echo "📡 Scanning \${RANGE}..."
  
  # Run nmap scan with service/version detection
  nmap -sV -sC -O --script vulners -oX - \${RANGE} | \\
    python3 -c "
import sys, json, xmltodict
data = xmltodict.parse(sys.stdin.read())
print(json.dumps(data, indent=2))
" >> \${OUTPUT_FILE}
done

echo "]" >> \${OUTPUT_FILE}

echo ""
echo "✅ Scan complete!"
echo "📄 Results saved to: \${OUTPUT_FILE}"
echo "📤 Upload this file to NouchiX dashboard"
`;
    const blob = new Blob([script], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'nouchix-network-scan.sh';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast({ title: 'Scan Script Downloaded', description: 'Run on a system inside your network' });
  };

  const handleAgentDownload = (platform: string) => {
    toast({
      title: 'Agent Download',
      description: `${platform} agent installer coming soon in v2.0`
    });
  };

  return (
    <div className="space-y-6">
      <Tabs value={method} onValueChange={(v) => setMethod(v as any)}>
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="network">Network Scan</TabsTrigger>
          <TabsTrigger value="agent">Agent Deployment</TabsTrigger>
        </TabsList>

        <TabsContent value="network" className="space-y-4">
          <Alert>
            <Network className="h-4 w-4" />
            <AlertDescription>
              <strong>Agentless Network Scanning:</strong> Uses nmap and OpenVAS to discover hosts,
              services, and vulnerabilities across your network ranges.
            </AlertDescription>
          </Alert>

          <div className="space-y-4">
            <div>
              <Label>Network Ranges</Label>
              <Textarea
                placeholder={`192.168.1.0/24\n10.0.0.0/16\n172.16.0.0/12`}
                value={networkRanges}
                onChange={(e) => setNetworkRanges(e.target.value)}
                className="mt-2 font-mono text-sm"
                rows={6}
              />
              <p className="text-xs text-muted-foreground mt-1">
                Enter one network range per line (CIDR notation)
              </p>
            </div>

            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>
                <strong>Important:</strong> Network scanning may trigger IDS/IPS alerts. Ensure you have
                authorization to scan these networks and coordinate with your security team.
              </AlertDescription>
            </Alert>

            <div className="grid grid-cols-2 gap-3">
              <Button onClick={downloadNetworkScanScript} variant="outline">
                <Download className="mr-2 h-4 w-4" />
                Download Scan Script
              </Button>
              <Button onClick={handleNetworkScan} disabled={loading}>
                {loading ? 'Starting...' : 'Start Scan'}
              </Button>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="agent" className="space-y-4">
          <Alert>
            <AlertDescription>
              <strong>Agent-Based Discovery:</strong> Deploy lightweight agents on your systems for
              deep configuration analysis and continuous STIG compliance monitoring.
            </AlertDescription>
          </Alert>

          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <Button variant="outline" onClick={() => handleAgentDownload('Linux')}>
                <Download className="mr-2 h-4 w-4" />
                Linux Agent
              </Button>
              <Button variant="outline" onClick={() => handleAgentDownload('Windows')}>
                <Download className="mr-2 h-4 w-4" />
                Windows Agent
              </Button>
              <Button variant="outline" onClick={() => handleAgentDownload('Container')}>
                <Download className="mr-2 h-4 w-4" />
                Container Agent
              </Button>
            </div>

            <Alert>
              <AlertDescription>
                Agent deployment provides the most comprehensive discovery and enables real-time
                configuration drift detection and automated remediation.
              </AlertDescription>
            </Alert>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
