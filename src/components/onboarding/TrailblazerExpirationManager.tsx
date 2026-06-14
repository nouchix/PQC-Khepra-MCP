import { useState } from 'react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Crown, ArrowRight, Rocket, CheckCircle } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useTrialStatus } from '@/hooks/useTrialStatus';
import { useSubscription } from '@/hooks/useSubscription';
import { useToast } from '@/hooks/use-toast';

const TrailblazerExpirationManager = () => {
  const { trialStatus, loading } = useTrialStatus();
  const { subscribed } = useSubscription();
  const navigate = useNavigate();
  const { toast } = useToast();
  const [dismissed, setDismissed] = useState(false);

  if (subscribed || dismissed || loading) {
    return null;
  }

  const getBetaStatus = () => {
    if (trialStatus.planType === 'trailblazer_plus') {
      return {
        color: 'bg-green-900/20 border-green-500/30',
        icon: CheckCircle,
        title: 'Trailblazer Plus Active',
        description: 'You have access to all enhanced features',
        action: null
      };
    }

    return {
      color: 'bg-blue-900/20 border-blue-500/30',
      icon: Rocket,
      title: 'Welcome to Trailblazer Beta',
      description: 'You have free access to basic security features',
      action: {
        text: 'Upgrade to Plus',
        onClick: () => navigate('/billing')
      }
    };
  };

  const status = getBetaStatus();
  const Icon = status.icon;

  const handleDismiss = () => {
    setDismissed(true);
    toast({
      title: "Reminder dismissed",
      description: "You can always upgrade from the billing page.",
    });
  };

  return (
    <Alert className={status.color}>
      <Icon className="h-4 w-4" />
      <AlertDescription className="flex items-center justify-between">
        <div className="space-y-1">
          <div className="flex items-center space-x-2">
            <span className="font-medium">{status.title}</span>
            <Badge variant="outline" className="text-xs">
              {trialStatus.planType?.replaceAll('_', ' ').toUpperCase()}
            </Badge>
          </div>
          <p className="text-sm text-muted-foreground">
            {status.description}
          </p>
        </div>
        
        <div className="flex items-center space-x-2 ml-4">
          {status.action && (
            <Button
              size="sm"
              onClick={status.action.onClick}
              className="bg-blue-600 hover:bg-blue-700"
            >
              <Crown className="h-3 w-3 mr-1" />
              {status.action.text}
              <ArrowRight className="h-3 w-3 ml-1" />
            </Button>
          )}
          <Button
            size="sm"
            variant="ghost"
            onClick={handleDismiss}
            className="text-xs"
          >
            Dismiss
          </Button>
        </div>
      </AlertDescription>
    </Alert>
  );
};

export default TrailblazerExpirationManager;