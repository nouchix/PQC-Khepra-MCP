import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Lock, Shield, Crown, AlertCircle } from 'lucide-react';
import { useKhepraAPI } from '@/hooks/useKhepraAPI';

interface KhepraPremiumGuardProps {
  children: React.ReactNode;
  feature?: string;
  requiredTier?: 'khepri' | 'ra' | 'atum' | 'osiris';
  deploymentUrl: string;
  apiKey: string;
}

export const KhepraPremiumGuard: React.FC<KhepraPremiumGuardProps> = ({
  children,
  feature = 'khepra-protocol',
  requiredTier = 'ra',
  deploymentUrl,
  apiKey
}) => {
  const { license } = useKhepraAPI(deploymentUrl, apiKey);

  const data = license.data;
  const isLoading = license.isLoading;
  const isError = license.isError;

  // Tier Hierarchy (weights)
  const tierWeights: Record<string, number> = {
    'community': 0,
    'khepri': 1,
    'ra': 2,
    'atum': 3,
    'osiris': 4
  };

  const currentTier = data?.tier || 'community';
  const hasAccess = data?.is_valid && (tierWeights[currentTier] >= tierWeights[requiredTier]);

  if (isLoading) {
    return (
      <div className="p-8 text-center animate-pulse">
        <Shield className="h-12 w-12 mx-auto mb-4 text-muted-foreground/30" />
        <p className="text-muted-foreground">Validating Khepra Authorization...</p>
      </div>
    );
  }

  if (isError || !data) {
    return (
      <Card className="border-red-200 bg-red-50/50">
        <CardContent className="p-6 flex items-center gap-4">
          <AlertCircle className="h-8 w-8 text-red-600" />
          <div>
            <h4 className="font-bold text-red-900">Connection Failed</h4>
            <p className="text-sm text-red-700">Unable to verify license status with the Khepra deployment.</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (hasAccess) {
    return <>{children}</>;
  }

  const handleUpgrade = () => {
    // Redirect to billing or show enrollment dialog
    globalThis.location.href = `https://souhimbou.ai/billing?tier=${requiredTier}`;
  };

  return (
    <div className="py-12 bg-gradient-to-br from-background via-background to-muted/20 rounded-xl border border-border shadow-soft">
      <div className="container mx-auto px-4">
        <div className="max-w-2xl mx-auto text-center space-y-8">
          {/* Header */}
          <div className="space-y-4">
            <div className="flex items-center justify-center space-x-3">
              <Shield className="h-10 w-10 text-primary" />
              <h2 className="text-3xl font-bold bg-gradient-to-r from-primary to-primary/60 bg-clip-text text-transparent">
                Tier Restricted: {requiredTier.toUpperCase()}
              </h2>
            </div>
            <p className="text-muted-foreground">
              Feature: <span className="font-mono text-foreground">{feature}</span> requires {requiredTier} tier clearance.
            </p>
          </div>

          {/* Locked Card */}
          <Card className="border-primary/20 bg-card/50 backdrop-blur-sm shadow-xl">
            <CardHeader>
              <div className="flex items-center justify-center mb-2">
                <div className="p-3 rounded-full bg-primary/10 border border-primary/20">
                  <Lock className="h-6 w-6 text-primary" />
                </div>
              </div>
              <CardTitle className="text-xl">Authorization Required</CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <p className="text-sm text-muted-foreground">
                The current license ({currentTier}) does not have sufficient deity authority for this operation.
                Upgrade to the {requiredTier} (Solar Ascendant) tier to unlock full PQC and STIG-NIST capabilities.
              </p>

              <Button
                onClick={handleUpgrade}
                size="lg"
                className="w-full bg-gradient-to-r from-primary to-primary/80 hover:from-primary/90 hover:to-primary/70"
              >
                <Crown className="h-5 w-5 mr-2" />
                Unlock {requiredTier.toUpperCase()} Capabilities
              </Button>

              <p className="text-xs text-muted-foreground/70">
                Machine ID: {data.machine_id} | Mode: Premium Hardened
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};