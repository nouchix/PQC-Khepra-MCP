import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { CheckCircle, Cloud, Zap } from 'lucide-react';
import type { DiscoveryResults } from '@/services/EnvironmentAutoDiscovery';

interface ConnectionPhaseProps {
  discoveryResults: DiscoveryResults;
  onComplete: (connectionData: any) => void;
}

export function ConnectionPhase({ discoveryResults, onComplete }: ConnectionPhaseProps) {
  const [connecting, setConnecting] = useState(false);
  const [connected, setConnected] = useState(false);

  const provider = discoveryResults.cloud.provider;
  const isKnownProvider = ['aws', 'azure', 'gcp'].includes(provider);

  const handleOneClickConnect = async () => {
    setConnecting(true);
    
    // Simulate connection process
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    setConnected(true);
    setConnecting(false);
    
    setTimeout(() => {
      onComplete({
        provider,
        region: discoveryResults.cloud.region,
        connectedAt: new Date().toISOString(),
      });
    }, 1000);
  };

  if (connected) {
    return (
      <div className="flex flex-col items-center justify-center py-16">
        <CheckCircle className="h-16 w-16 text-green-600 mb-4" />
        <h2 className="text-2xl font-semibold mb-2">Connected!</h2>
        <p className="text-muted-foreground">Proceeding to agent deployment...</p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-3xl font-semibold mb-3">One-Click Connection</h2>
        <p className="text-lg text-muted-foreground">
          We detected your environment. Connect with one click.
        </p>
      </div>

      {/* Detected Provider */}
      <div className="bg-card border border-border rounded-xl p-8">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-4">
            <div className="h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center">
              <Cloud className="h-6 w-6 text-primary" />
            </div>
            <div>
              <div className="text-sm text-muted-foreground mb-1">Detected Provider</div>
              <div className="text-2xl font-semibold uppercase">{provider}</div>
            </div>
          </div>
          {isKnownProvider && (
            <Badge className="bg-green-500/10 text-green-600 border-green-500/20">
              Supported
            </Badge>
          )}
        </div>

        {discoveryResults.cloud.region && (
          <div className="flex items-center gap-2 mb-6">
            <span className="text-sm text-muted-foreground">Region:</span>
            <Badge variant="outline">{discoveryResults.cloud.region}</Badge>
          </div>
        )}

        {isKnownProvider ? (
          <Button 
            onClick={handleOneClickConnect} 
            disabled={connecting}
            size="lg" 
            className="w-full"
          >
            {connecting ? (
              <>Connecting...</>
            ) : (
              <>
                <Zap className="mr-2 h-5 w-5" />
                Connect to {provider.toUpperCase()}
              </>
            )}
          </Button>
        ) : (
          <div className="text-center py-4">
            <p className="text-sm text-muted-foreground mb-4">
              Manual configuration required for {provider}
            </p>
            <Button variant="outline" onClick={() => onComplete({ provider, manual: true })}>
              Configure Manually
            </Button>
          </div>
        )}
      </div>

      <div className="text-center">
        <p className="text-sm text-muted-foreground">
          Auto-detected from your environment • Zero manual entry
        </p>
      </div>
    </div>
  );
}
