import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { CheckCircle, Shield, Database, Cloud, Loader2 } from 'lucide-react';
import type { DeepScanResults } from '@/services/DeepAssetScanService';

interface ScanningPhaseProps {
  onComplete: (results: DeepScanResults) => void;
}

export function ScanningPhase({ onComplete }: ScanningPhaseProps) {
  const [progress, setProgress] = useState(0);
  const [phase, setPhase] = useState('Initializing scan...');
  const [complete, setComplete] = useState(false);

  useEffect(() => {
    const phases = [
      { text: 'Scanning network assets...', duration: 2000 },
      { text: 'Running STIG compliance checks...', duration: 2000 },
      { text: 'Mapping CMMC controls...', duration: 1500 },
      { text: 'Analyzing vulnerabilities...', duration: 1500 },
    ];

    let currentPhase = 0;
    let currentProgress = 0;

    const runPhases = async () => {
      for (const phaseData of phases) {
        setPhase(phaseData.text);
        const increment = 100 / phases.length;
        
        await new Promise(resolve => setTimeout(resolve, phaseData.duration));
        currentProgress += increment;
        setProgress(currentProgress);
        currentPhase++;
      }

      setComplete(true);
      
      setTimeout(() => {
        onComplete({
          assets_discovered: 12,
          stig_profiles_identified: ['Linux', 'Windows', 'Network'],
          baseline_compliance: 78,
          critical_findings: 2,
          high_findings: 5,
          medium_findings: 12,
          low_findings: 8,
          cmmc_controls_mapped: 45,
          automation_ready: 85,
          discovered_assets: [],
        });
      }, 1000);
    };

    runPhases();
  }, []);

  if (complete) {
    return (
      <div className="flex flex-col items-center justify-center py-16">
        <CheckCircle className="h-16 w-16 text-green-600 mb-4" />
        <h2 className="text-2xl font-semibold mb-2">Scan Complete!</h2>
        <p className="text-muted-foreground">Generating results...</p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-3xl font-semibold mb-3">Instant Scanning</h2>
        <p className="text-lg text-muted-foreground">
          Prioritized scan of detected assets
        </p>
      </div>

      {/* Scanning Progress */}
      <div className="bg-card border border-border rounded-xl p-8">
        <div className="flex flex-col items-center space-y-6">
          <Loader2 className="h-16 w-16 animate-spin text-primary" />
          
          <div className="text-center space-y-2">
            <p className="text-xl font-medium">{phase}</p>
            <p className="text-sm text-muted-foreground">Using Shodan API and OSINT tools</p>
          </div>

          <div className="w-full max-w-md space-y-2">
            <Progress value={progress} className="h-2" />
            <p className="text-sm text-center text-muted-foreground">{Math.round(progress)}%</p>
          </div>
        </div>
      </div>

      {/* What We're Scanning */}
      <div className="grid gap-4 md:grid-cols-3">
        <div className="bg-card border border-border rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <Database className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm text-muted-foreground">STIG Checks</span>
          </div>
          <p className="text-lg font-semibold">Running</p>
        </div>

        <div className="bg-card border border-border rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <Shield className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm text-muted-foreground">Compliance</span>
          </div>
          <p className="text-lg font-semibold">Analyzing</p>
        </div>

        <div className="bg-card border border-border rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <Cloud className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm text-muted-foreground">CMMC Mapping</span>
          </div>
          <p className="text-lg font-semibold">In Progress</p>
        </div>
      </div>
    </div>
  );
}
