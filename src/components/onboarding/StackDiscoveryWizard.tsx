import { useState, useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import DiscoveryPhase from './phases/DiscoveryPhase';
import { ConnectionPhase } from './phases/ConnectionPhase';
import { AgentDeploymentPhase } from './phases/AgentDeploymentPhase';
import { ScanningPhase } from './phases/ScanningPhase';
import { ArrowRight, CheckCircle } from 'lucide-react';
import type { DiscoveryResults } from '@/services/EnvironmentAutoDiscovery';
import type { DeepScanResults } from '@/services/DeepAssetScanService';

interface StackDiscoveryWizardProps {
  onComplete: () => void;
}

type Phase = 'discovery' | 'connection' | 'deployment' | 'scanning' | 'complete';

const StackDiscoveryWizard: React.FC<StackDiscoveryWizardProps> = ({ onComplete }) => {
  const [organizationId, setOrganizationId] = useState<string>('');

  useEffect(() => {
    supabase.auth.getUser().then(({ data }) => {
      const id = data?.user?.user_metadata?.organization_id || data?.user?.id;
      if (!id) throw new Error('User must be authenticated to run stack discovery');
      setOrganizationId(id);
    });
  }, []);
  const [currentPhase, setCurrentPhase] = useState<Phase>('discovery');
  const [discoveryResults, setDiscoveryResults] = useState<DiscoveryResults | null>(null);
  const [scanResults, setScanResults] = useState<DeepScanResults | null>(null);

  const phases = [
    { id: 'discovery', label: 'Auto-Discovery', complete: currentPhase !== 'discovery' },
    { id: 'connection', label: 'One-Click Connect', complete: ['deployment', 'scanning', 'complete'].includes(currentPhase) },
    { id: 'deployment', label: 'Agent Deploy', complete: ['scanning', 'complete'].includes(currentPhase) },
    { id: 'scanning', label: 'Instant Scan', complete: currentPhase === 'complete' },
  ];

  const handleDiscoveryComplete = (results?: DiscoveryResults) => {
    if (results) {
      setDiscoveryResults(results);
    }
    setCurrentPhase('connection');
  };

  const handleConnectionComplete = () => {
    setCurrentPhase('deployment');
  };

  const handleDeploymentComplete = () => {
    setCurrentPhase('scanning');
  };

  const handleScanningComplete = (results: DeepScanResults) => {
    setScanResults(results);
    setCurrentPhase('complete');
  };

  if (currentPhase === 'complete' && scanResults) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-background via-background to-primary/5">
        <div className="max-w-6xl mx-auto px-4 py-16">
          <div className="text-center mb-16 space-y-6">
            <div className="relative inline-block">
              <div className="absolute inset-0 bg-green-500/20 blur-3xl rounded-full animate-pulse" />
              <CheckCircle className="h-24 w-24 text-green-600 mx-auto relative" />
            </div>
            <h1 className="text-5xl font-bold bg-gradient-to-r from-foreground to-foreground/70 bg-clip-text text-transparent">
              Setup Complete!
            </h1>
            <p className="text-xl text-muted-foreground">
              Onboarding reduced from <span className="line-through">30 minutes</span> to <span className="font-bold text-green-600">3 minutes</span>
            </p>
          </div>

          {/* Results Summary */}
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4 mb-16">
            <Card className="p-8 bg-gradient-to-br from-primary/5 to-primary/10 border-primary/20">
              <div className="text-sm text-muted-foreground mb-3 font-medium">Assets Discovered</div>
              <div className="text-4xl font-bold text-primary">{scanResults.assets_discovered}</div>
            </Card>
            <Card className="p-8 bg-gradient-to-br from-green-500/5 to-green-500/10 border-green-500/20">
              <div className="text-sm text-muted-foreground mb-3 font-medium">Baseline Compliance</div>
              <div className="text-4xl font-bold text-green-600">{scanResults.baseline_compliance}%</div>
            </Card>
            <Card className="p-8 bg-gradient-to-br from-blue-500/5 to-blue-500/10 border-blue-500/20">
              <div className="text-sm text-muted-foreground mb-3 font-medium">CMMC Controls</div>
              <div className="text-4xl font-bold text-blue-600">{scanResults.cmmc_controls_mapped}</div>
            </Card>
            <Card className="p-8 bg-gradient-to-br from-purple-500/5 to-purple-500/10 border-purple-500/20">
              <div className="text-sm text-muted-foreground mb-3 font-medium">Automation Ready</div>
              <div className="text-4xl font-bold text-purple-600">{scanResults.automation_ready}%</div>
            </Card>
          </div>

          <div className="flex justify-center">
            <Button onClick={onComplete} size="lg" className="min-w-[400px] h-14 text-lg font-semibold shadow-lg shadow-primary/20 hover:shadow-xl hover:shadow-primary/30 transition-all">
              Go to Dashboard
              <ArrowRight className="h-5 w-5 ml-2" />
            </Button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted/20">
      <div className="max-w-6xl mx-auto px-4 py-12">
        {/* Progress Indicator */}
        <div className="mb-16">
          <div className="flex items-center justify-between max-w-4xl mx-auto">
            {phases.map((phase, index) => (
              <div key={phase.id} className="flex items-center flex-1">
                <div className="flex flex-col items-center flex-1">
                  <div className={`
                    h-14 w-14 rounded-full flex items-center justify-center font-semibold mb-3 transition-all duration-300 shadow-lg
                    ${phase.complete 
                      ? 'bg-gradient-to-br from-green-600 to-green-500 text-white shadow-green-500/50' 
                      : currentPhase === phase.id 
                        ? 'bg-gradient-to-br from-primary to-primary/80 text-primary-foreground shadow-primary/50 scale-110' 
                        : 'bg-muted text-muted-foreground shadow-none'
                    }
                  `}>
                    {phase.complete ? <CheckCircle className="h-6 w-6" /> : <span className="text-lg">{index + 1}</span>}
                  </div>
                  <span className={`text-sm text-center font-medium ${
                    currentPhase === phase.id ? 'text-foreground' : 'text-muted-foreground'
                  }`}>
                    {phase.label}
                  </span>
                </div>
                {index < phases.length - 1 && (
                  <div className={`
                    h-1 flex-1 mx-4 mb-8 rounded-full transition-all duration-300
                    ${phase.complete 
                      ? 'bg-gradient-to-r from-green-600 to-green-500' 
                      : 'bg-muted'
                    }
                  `} />
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Current Phase */}
        {currentPhase === 'discovery' && (
          <DiscoveryPhase 
            organizationId={organizationId}
            onboardingId="onboarding-session"
            onComplete={handleDiscoveryComplete}
          />
        )}

        {currentPhase === 'connection' && discoveryResults && (
          <ConnectionPhase 
            discoveryResults={discoveryResults}
            onComplete={handleConnectionComplete}
          />
        )}

        {currentPhase === 'deployment' && discoveryResults && (
          <AgentDeploymentPhase 
            discoveryResults={discoveryResults}
            onComplete={handleDeploymentComplete}
          />
        )}

        {currentPhase === 'scanning' && (
          <ScanningPhase onComplete={handleScanningComplete} />
        )}
      </div>
    </div>
  );
};

export default StackDiscoveryWizard;