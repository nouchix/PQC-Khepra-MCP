import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { 
  Cloud, 
  Network, 
  Monitor, 
  CheckCircle, 
  Loader2,
  AlertCircle 
} from 'lucide-react';
import { EnvironmentAutoDiscovery, type DiscoveryResults } from '@/services/EnvironmentAutoDiscovery';
import { useToast } from '@/hooks/use-toast';

interface AutoDiscoveryPanelProps {
  organizationId: string;
  onDiscoveryComplete?: (results: DiscoveryResults) => void;
}

export const AutoDiscoveryPanel = ({ 
  organizationId, 
  onDiscoveryComplete 
}: AutoDiscoveryPanelProps) => {
  const [isDiscovering, setIsDiscovering] = useState(false);
  const [results, setResults] = useState<DiscoveryResults | null>(null);
  const { toast } = useToast();

  useEffect(() => {
    // Auto-start discovery on mount
    startDiscovery();
  }, [organizationId]);

  const startDiscovery = async () => {
    setIsDiscovering(true);
    
    try {
      const discovery = new EnvironmentAutoDiscovery(organizationId);
      const discoveryResults = await discovery.discover();
      
      setResults(discoveryResults);
      onDiscoveryComplete?.(discoveryResults);
      
      toast({
        title: "Environment Detected",
        description: `Found ${discoveryResults.cloud.provider} infrastructure with ${discoveryResults.overallConfidence}% confidence`,
      });
    } catch (error) {
      console.error('Discovery failed:', error);
      toast({
        title: "Discovery Failed",
        description: "Could not auto-detect environment. Manual setup available.",
        variant: "destructive",
      });
    } finally {
      setIsDiscovering(false);
    }
  };

  if (isDiscovering) {
    return (
      <div className="flex flex-col items-center justify-center py-16">
        <Loader2 className="h-12 w-12 animate-spin text-primary mb-4" />
        <p className="text-lg font-medium">NouchiX STIGs Discovery Engine</p>
        <p className="text-sm text-muted-foreground">Multi-layered scanning: nmap • OpenVAS • OpenSCAP</p>
      </div>
    );
  }

  if (!results) {
    return (
      <div className="flex flex-col items-center justify-center py-16">
        <AlertCircle className="h-12 w-12 text-muted-foreground mb-4" />
        <p className="text-lg font-medium mb-4">No environment detected</p>
        <Button onClick={startDiscovery} variant="outline">
          Retry
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <CheckCircle className="h-6 w-6 text-green-600" />
        <h2 className="text-2xl font-semibold">Environment Detected</h2>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        {/* Cloud */}
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Cloud className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm font-medium text-muted-foreground">Cloud</span>
          </div>
          <div className="space-y-2">
            <div className="text-2xl font-semibold uppercase">{results.cloud.provider}</div>
            {results.cloud.region && (
              <p className="text-sm text-muted-foreground">{results.cloud.region}</p>
            )}
            <p className="text-xs text-muted-foreground">{results.cloud.confidence}% confidence</p>
          </div>
        </div>

        {/* Network */}
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Network className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm font-medium text-muted-foreground">Network</span>
          </div>
          <div className="space-y-2">
            <div className="text-2xl font-semibold">{results.network.detectedServices.length}</div>
            <p className="text-sm text-muted-foreground">Services discovered</p>
            <div className="flex gap-1 mt-2">
              <Badge variant="outline" className="text-xs">nmap</Badge>
              <Badge variant="outline" className="text-xs">OpenVAS</Badge>
            </div>
            <p className="text-xs text-muted-foreground">{results.network.confidence}% confidence</p>
          </div>
        </div>

        {/* Platform */}
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Monitor className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm font-medium text-muted-foreground">Platform</span>
          </div>
          <div className="space-y-2">
            <div className="text-2xl font-semibold uppercase">{results.platform.operatingSystem}</div>
            {results.platform.browser && (
              <p className="text-sm text-muted-foreground capitalize">{results.platform.browser}</p>
            )}
          </div>
        </div>
      </div>

      <div className="pt-4 border-t">
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Overall Confidence</span>
          <Badge variant={results.overallConfidence > 70 ? 'default' : 'secondary'} className="text-base px-3 py-1">
            {results.overallConfidence}%
          </Badge>
        </div>
      </div>
    </div>
  );
};
