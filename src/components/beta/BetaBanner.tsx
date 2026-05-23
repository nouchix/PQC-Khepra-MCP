import { AlertTriangle } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { useBetaAccess } from '@/hooks/useBetaAccess';

export const BetaBanner = () => {
  const { hasBetaAccess, enrollment } = useBetaAccess();

  if (!hasBetaAccess || !enrollment) return null;

  const tierLabels = {
    trailblazer_beta: 'Trailblazer Beta',
    mvp_1_beta: 'MVP 1.0 Beta',
    mvp_2_pilot: 'MVP 2.0 Pilot'
  };

  return (
    <Alert variant="destructive" className="border-yellow-500 bg-yellow-500/10 mb-4">
      <AlertTriangle className="h-4 w-4" />
      <AlertDescription className="flex items-center justify-between">
        <span>
          <strong>{tierLabels[enrollment.tier]}</strong> - BETA ENVIRONMENT • Not for production CUI workloads • 
          Production GovCloud deployment: Q2 2025
        </span>
      </AlertDescription>
    </Alert>
  );
};