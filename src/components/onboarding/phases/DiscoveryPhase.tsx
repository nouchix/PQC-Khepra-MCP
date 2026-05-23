import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { useToast } from '@/hooks/use-toast';
import { Loader2, Shield, CheckCircle } from 'lucide-react';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { AutoDiscoveryPanel } from '../AutoDiscoveryPanel';
import CloudConnectionWizard from '../CloudConnectionWizard';
import { DiscoveryResults } from '@/services/EnvironmentAutoDiscovery';
import { DeepScanResults } from '@/services/DeepAssetScanService';

interface ScanProgress {
  phase: string;
  percentage: number;
}
import { supabase } from '@/integrations/supabase/client';

interface DiscoveryPhaseProps {
  organizationId: string;
  onboardingId: string;
  onComplete?: (results?: DiscoveryResults) => void;
}

export default function DiscoveryPhase({
  organizationId,
  onboardingId,
  onComplete
}: DiscoveryPhaseProps) {
  const { toast } = useToast();
  const [autoDiscoveryComplete, setAutoDiscoveryComplete] = useState(false);
  const [autoDiscoveryResults, setAutoDiscoveryResults] = useState<DiscoveryResults | null>(null);
  const [connectionPhase, setConnectionPhase] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState<ScanProgress>({
    phase: 'Initializing',
    percentage: 0
  });
  const [deepScanResults, setDeepScanResults] = useState<DeepScanResults | null>(null);
  const [connectedAccounts, setConnectedAccounts] = useState<string[]>([]);

  const handleAutoDiscoveryComplete = (results: DiscoveryResults) => {
    console.log('Auto-discovery complete:', results);
    setAutoDiscoveryResults(results);
    setAutoDiscoveryComplete(true);
    setConnectionPhase(true);
  };

  const handleConnectionComplete = async (connectionId: string) => {
    console.log('Cloud connection complete:', connectionId);
    setConnectedAccounts([...connectedAccounts, connectionId]);
    await startRealDiscovery(connectionId);
  };

  const handleSkipConnection = () => {
    setConnectionPhase(false);
    if (onComplete) onComplete(autoDiscoveryResults || undefined);
  };

  const startRealDiscovery = async (connectionId: string) => {
    setIsScanning(true);
    setConnectionPhase(false);
    
    try {
      setScanProgress({ phase: 'Discovering Infrastructure', percentage: 20 });
      
      const pollInterval = setInterval(async () => {
        const { data: assets, error } = await supabase
          .from('discovered_assets' as any)
          .select('*')
          .eq('connection_id', connectionId);
        
        if (error) {
          console.error('Error fetching assets:', error);
          return;
        }
        
        if (assets && assets.length > 0) {
          clearInterval(pollInterval);
          
          const scanResults: DeepScanResults = {
            assets_discovered: assets.length,
            stig_profiles_identified: Array.from(new Set(
              assets.flatMap((a: any) => a.applicable_stigs?.map((s: any) => s.stig_id) || [])
            )),
            baseline_compliance: calculateComplianceScore(assets),
            critical_findings: 0,
            high_findings: 0,
            medium_findings: 0,
            low_findings: 0,
            cmmc_controls_mapped: assets.reduce((sum: number, a: any) => sum + (a.applicable_stigs?.length || 0), 0),
            automation_ready: Math.round(
              assets.filter((a: any) => a.applicable_stigs?.some((s: any) => s.automation_possible)).length / 
              assets.length * 100
            ),
            discovered_assets: assets.map((a: any) => ({
              hostname: a.asset_name || a.asset_id,
              ip: a.ip_addresses?.[0] || '',
              type: a.asset_type,
              os: a.platform,
              services: (a.configuration?.services || []).map((s: any) => s.name || s)
            }))
          };
          
          setScanProgress({ phase: 'Discovery Complete', percentage: 100 });
          setDeepScanResults(scanResults);
          setIsScanning(false);
          
            toast({
            title: 'Discovery Complete',
            description: `Found ${scanResults.assets_discovered} assets with ${scanResults.stig_profiles_identified.length} STIG profiles`
          });
        }
      }, 3000);
      
      setTimeout(() => clearInterval(pollInterval), 120000);
      
    } catch (error) {
      console.error('Real discovery error:', error);
      setIsScanning(false);
    }
  };

  const calculateComplianceScore = (assets: any[]): number => {
    if (assets.length === 0) return 0;
    const scores = assets
      .filter((a: any) => a.compliance_score != null)
      .map((a: any) => a.compliance_score);
    return scores.length > 0 
      ? Math.round(scores.reduce((a: number, b: number) => a + b, 0) / scores.length)
      : 0;
  };

  return (
    <div className="space-y-6">
      {!autoDiscoveryComplete ? (
        <div className="space-y-8">
          <div className="text-center space-y-3">
            <h2 className="text-4xl font-bold bg-gradient-to-r from-primary to-primary/60 bg-clip-text text-transparent">
              NouchiX STIGs Discovery
            </h2>
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
              Enterprise-grade asset discovery and STIG compliance mapping in minutes
            </p>
          </div>
          <AutoDiscoveryPanel
            organizationId={organizationId}
            onDiscoveryComplete={handleAutoDiscoveryComplete}
          />
        </div>
      ) : connectionPhase ? (
        <div className="space-y-8">
          <div className="text-center space-y-3">
            <h2 className="text-4xl font-bold">Connect Your Infrastructure</h2>
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
              One-click connection to AWS, Azure, GCP, or on-premises networks
            </p>
          </div>
          <CloudConnectionWizard
            organizationId={organizationId}
            onConnectionComplete={handleConnectionComplete}
            onSkip={handleSkipConnection}
          />
        </div>
      ) : isScanning ? (
        <Card className="p-12 bg-gradient-to-br from-background to-muted/20">
          <div className="flex flex-col items-center space-y-8">
            <div className="relative">
              <div className="absolute inset-0 bg-primary/20 blur-3xl rounded-full animate-pulse" />
              <Loader2 className="h-20 w-20 animate-spin text-primary relative" />
              <Shield className="h-10 w-10 absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-primary" />
            </div>
            
            <div className="text-center space-y-3">
              <p className="text-2xl font-semibold">{scanProgress.phase}</p>
              <p className="text-muted-foreground text-lg">Analyzing infrastructure and mapping STIG controls</p>
            </div>

            <div className="w-full max-w-2xl space-y-4">
              <Progress value={scanProgress.percentage} className="h-3" />
              <p className="text-sm text-center text-muted-foreground font-medium">{scanProgress.percentage}%</p>
            </div>
          </div>
        </Card>
      ) : deepScanResults ? (
        <div className="space-y-8">
          <Card className="p-8 bg-gradient-to-br from-green-500/5 to-green-500/10 border-green-500/20">
            <div className="flex items-start gap-4">
              <div className="p-3 bg-green-500/10 rounded-xl">
                <CheckCircle className="h-8 w-8 text-green-600" />
              </div>
              <div className="flex-1">
                <h3 className="text-2xl font-bold mb-2">Discovery Complete</h3>
                <p className="text-muted-foreground text-lg">
                  Successfully discovered <span className="font-semibold text-foreground">{deepScanResults.assets_discovered} assets</span> with{' '}
                  <span className="font-semibold text-foreground">{deepScanResults.stig_profiles_identified.length} STIG profiles</span> identified
                </p>
              </div>
            </div>
          </Card>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Card className="p-6">
              <div className="text-sm text-muted-foreground mb-2">Assets Found</div>
              <div className="text-3xl font-bold text-primary">{deepScanResults.assets_discovered}</div>
            </Card>
            <Card className="p-6">
              <div className="text-sm text-muted-foreground mb-2">STIG Profiles</div>
              <div className="text-3xl font-bold text-primary">{deepScanResults.stig_profiles_identified.length}</div>
            </Card>
            <Card className="p-6">
              <div className="text-sm text-muted-foreground mb-2">Compliance</div>
              <div className="text-3xl font-bold text-primary">{deepScanResults.baseline_compliance}%</div>
            </Card>
            <Card className="p-6">
              <div className="text-sm text-muted-foreground mb-2">Auto-Ready</div>
              <div className="text-3xl font-bold text-primary">{deepScanResults.automation_ready}%</div>
            </Card>
          </div>

          <div className="flex justify-center">
            <Button onClick={() => onComplete?.(autoDiscoveryResults || undefined)} size="lg" className="min-w-[300px]">
              Continue to Dashboard
            </Button>
          </div>
        </div>
      ) : null}
    </div>
  );
}
