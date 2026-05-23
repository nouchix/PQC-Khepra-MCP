import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { CheckCircle, Download, Terminal, Copy } from 'lucide-react';
import type { DiscoveryResults } from '@/services/EnvironmentAutoDiscovery';
import { useToast } from '@/hooks/use-toast';

interface AgentDeploymentPhaseProps {
  discoveryResults: DiscoveryResults;
  onComplete: () => void;
}

export function AgentDeploymentPhase({ discoveryResults, onComplete }: AgentDeploymentPhaseProps) {
  const [deployed, setDeployed] = useState(false);
  const { toast } = useToast();
  const platform = discoveryResults.platform.operatingSystem;

  const getInstallCommand = () => {
    switch (platform) {
      case 'windows':
        return 'powershell -Command "iwr -useb https://install.khepra.io/windows | iex"';
      case 'linux':
        return 'curl -fsSL https://install.khepra.io/linux | bash';
      case 'macos':
        return 'curl -fsSL https://install.khepra.io/macos | bash';
      default:
        return 'curl -fsSL https://install.khepra.io/install | bash';
    }
  };

  const copyCommand = () => {
    navigator.clipboard.writeText(getInstallCommand());
    toast({
      title: "Copied!",
      description: "Installation command copied to clipboard",
    });
  };

  const handleDeployed = () => {
    setDeployed(true);
    setTimeout(() => {
      onComplete();
    }, 1500);
  };

  if (deployed) {
    return (
      <div className="flex flex-col items-center justify-center py-16">
        <CheckCircle className="h-16 w-16 text-green-600 mb-4" />
        <h2 className="text-2xl font-semibold mb-2">Agent Deployed!</h2>
        <p className="text-muted-foreground">Starting asset scan...</p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-3xl font-semibold mb-3">Deploy Agent</h2>
        <p className="text-lg text-muted-foreground">
          Platform-specific installer generated for {platform}
        </p>
      </div>

      {/* Platform Info */}
      <div className="bg-card border border-border rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <div className="text-sm text-muted-foreground mb-1">Detected Platform</div>
            <div className="text-xl font-semibold uppercase">{platform}</div>
          </div>
          <Badge variant="outline" className="bg-green-500/10 text-green-600 border-green-500/20">
            Installer Ready
          </Badge>
        </div>
      </div>

      {/* Installation Command */}
      <div className="bg-card border border-border rounded-xl p-6">
        <div className="flex items-center gap-2 mb-4">
          <Terminal className="h-5 w-5 text-muted-foreground" />
          <span className="font-medium">One-Line Install</span>
        </div>
        
        <div className="bg-muted rounded-lg p-4 font-mono text-sm mb-4 flex items-center justify-between">
          <code className="flex-1">{getInstallCommand()}</code>
          <Button variant="ghost" size="sm" onClick={copyCommand}>
            <Copy className="h-4 w-4" />
          </Button>
        </div>

        <div className="flex gap-3">
          <Button onClick={handleDeployed} size="lg" className="flex-1">
            <Download className="mr-2 h-5 w-5" />
            Download Installer
          </Button>
          <Button variant="outline" onClick={handleDeployed} size="lg">
            I've Deployed It
          </Button>
        </div>
      </div>

      <div className="text-center">
        <p className="text-sm text-muted-foreground">
          Auto-generated for your platform • No configuration needed
        </p>
      </div>
    </div>
  );
}
