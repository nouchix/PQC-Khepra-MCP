import { ReactNode } from 'react';
import { Lock, Crown, Zap } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { useNavigate } from '@/lib/router-compat';
import { useTrialStatus } from '@/hooks/useTrialStatus';

interface FeatureGateProps {
  children: ReactNode;
  featureType: 'basic' | 'customization' | 'reminders' | 'grace_mode' | 'premium' | 'enterprise';
  featureName: string;
  description?: string;
  className?: string;
}

const FeatureGate = ({ children, featureType, featureName, description, className }: FeatureGateProps) => {
  const { canAccessFeature, trialStatus } = useTrialStatus();
  const navigate = useNavigate();

  // Allow access if user can access this feature
  if (canAccessFeature(featureType)) {
    return <>{children}</>;
  }

  const getFeatureIcon = () => {
    switch (featureType) {
      case 'customization':
      case 'reminders':
      case 'grace_mode':
        return <Crown className="h-8 w-8 text-blue-500" />;
      case 'premium':
        return <Crown className="h-8 w-8 text-yellow-500" />;
      case 'enterprise':
        return <Zap className="h-8 w-8 text-purple-500" />;
      default:
        return <Lock className="h-8 w-8 text-gray-500" />;
    }
  };

  const getFeatureBadge = () => {
    switch (featureType) {
      case 'customization':
      case 'reminders':
      case 'grace_mode':
        return (
          <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-500/20 text-blue-400 border border-blue-500/30">
            <Crown className="h-3 w-3 mr-1" />
            Trailblazer Plus
          </span>
        );
      case 'premium':
        return (
          <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">
            <Crown className="h-3 w-3 mr-1" />
            Premium
          </span>
        );
      case 'enterprise':
        return (
          <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-purple-500/20 text-purple-400 border border-purple-500/30">
            <Zap className="h-3 w-3 mr-1" />
            Enterprise
          </span>
        );
      default:
        return null;
    }
  };

  const getUpgradeMessage = () => {
    if (trialStatus.isBetaActive && trialStatus.planType === 'trailblazer_beta') {
      if (['customization', 'reminders', 'grace_mode'].includes(featureType)) {
        return "Upgrade to Trailblazer Plus ($19/month) to unlock this feature.";
      }
      return `This ${featureType} feature requires a subscription.`;
    }
    return `This ${featureType} feature requires an active subscription.`;
  };

  return (
    <div className={className}>
      <Card className="bg-slate-800/50 border-slate-700 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-slate-800/80 to-slate-900/80 backdrop-blur-sm" />
        <CardHeader className="relative z-10 text-center">
          <div className="flex flex-col items-center space-y-3">
            {getFeatureIcon()}
            <div className="space-y-1">
              <CardTitle className="text-white flex items-center justify-center space-x-2">
                <span>{featureName}</span>
                {getFeatureBadge()}
              </CardTitle>
              {description && (
                <p className="text-sm text-gray-400">{description}</p>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent className="relative z-10 text-center space-y-4">
          <p className="text-gray-300 text-sm">
            {getUpgradeMessage()}
          </p>
          
          <div className="flex flex-col sm:flex-row gap-2 justify-center">
            <Button
              onClick={() => navigate('/billing')}
              className="bg-gradient-to-r from-blue-500 to-purple-500 hover:from-blue-600 hover:to-purple-600"
            >
              <Crown className="h-4 w-4 mr-2" />
              {trialStatus.isBetaActive ? 'Upgrade Now' : 'Get Access'}
            </Button>
            
            {!trialStatus.isBetaActive && (
              <Button
                variant="outline"
                onClick={() => navigate('/billing')}
                className="border-gray-600 text-gray-300 hover:bg-gray-800"
              >
                Learn More
              </Button>
            )}
          </div>
          
          {trialStatus.isBetaActive && trialStatus.planType === 'trailblazer_beta' && (
            <p className="text-xs text-blue-400">
              Trailblazer Beta • Upgrade for enhanced features
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default FeatureGate;