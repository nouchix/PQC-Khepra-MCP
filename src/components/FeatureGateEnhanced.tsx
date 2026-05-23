import { ReactNode } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { useTrialStatus } from '@/hooks/useTrialStatus';
import { useUsageTracker } from '@/components/UsageTracker';
import { useNavigate } from '@/lib/router-compat';
import { 
  Lock, 
  Crown, 
  Zap, 
  Shield,
  Star,
  ArrowRight,
  Sparkles
} from 'lucide-react';

interface FeatureGateEnhancedProps {
  children: ReactNode;
  featureType: 'basic' | 'customization' | 'reminders' | 'grace_mode' | 'premium' | 'enterprise';
  featureName: string;
  description?: string;
  valueProposition?: string;
  upgradeMessage?: string;
  showPreview?: boolean;
  className?: string;
}

export const FeatureGateEnhanced = ({
  children,
  featureType,
  featureName,
  description,
  valueProposition,
  upgradeMessage,
  showPreview = false,
  className = ""
}: FeatureGateEnhancedProps) => {
  const { trialStatus, canAccessFeature } = useTrialStatus();
  const { trackUpgradePrompt } = useUsageTracker();
  const navigate = useNavigate();

  if (canAccessFeature(featureType)) {
    return <div className={className}>{children}</div>;
  }

  const getFeatureIcon = () => {
    switch (featureType) {
      case 'premium':
        return <Crown className="h-6 w-6 text-yellow-500" />;
      case 'enterprise':
        return <Sparkles className="h-6 w-6 text-purple-500" />;
      default:
        return <Lock className="h-6 w-6 text-muted-foreground" />;
    }
  };

  const getFeatureBadge = () => {
    const variants = {
      basic: { variant: "secondary" as const, label: "Pro" },
      premium: { variant: "default" as const, label: "Premium" },
      enterprise: { variant: "default" as const, label: "Enterprise" }
    };
    
    const config = variants[featureType];
    return (
      <Badge variant={config.variant} className="ml-2">
        {config.label}
      </Badge>
    );
  };

  const getDefaultMessages = () => {
    switch (featureType) {
      case 'premium':
        return {
          value: "Advanced security analytics and automated threat response",
          upgrade: "Upgrade to Premium for advanced security features and CMMC compliance tools"
        };
      case 'enterprise':
        return {
          value: "Enterprise-grade compliance automation and dedicated support",
          upgrade: "Contact us for Enterprise features including custom integrations and dedicated support"
        };
      default:
        return {
          value: "Enhanced features for better security management",
          upgrade: "Upgrade your plan to access this feature"
        };
    }
  };

  const messages = getDefaultMessages();
  const finalValueProp = valueProposition || messages.value;
  const finalUpgradeMessage = upgradeMessage || messages.upgrade;

  const handleUpgradeClick = () => {
    trackUpgradePrompt(featureName, 'clicked');
    if (featureType === 'enterprise') {
      // Could open contact form or external link
      globalThis.open('mailto:sales@example.com?subject=Enterprise Inquiry', '_blank');
    } else {
      navigate('/billing');
    }
  };

  const handleDismiss = () => {
    trackUpgradePrompt(featureName, 'dismissed');
  };

  return (
    <div className={`relative ${className}`}>
      {/* Preview with overlay if showPreview is true */}
      {showPreview && (
        <div className="relative">
          <div className="opacity-30 pointer-events-none">
            {children}
          </div>
          <div className="absolute inset-0 bg-gradient-to-t from-background/90 to-transparent" />
        </div>
      )}

      {/* Feature gate card */}
      <Card className={`border-2 border-dashed ${
        featureType === 'premium' ? 'border-yellow-200 bg-yellow-50/50' :
        featureType === 'enterprise' ? 'border-purple-200 bg-purple-50/50' :
        'border-border bg-muted/30'
      } ${showPreview ? 'absolute inset-0 flex items-center justify-center' : ''}`}>
        <CardHeader className="text-center pb-4">
          <div className="flex items-center justify-center mb-3">
            {getFeatureIcon()}
          </div>
          <CardTitle className="flex items-center justify-center text-xl">
            {featureName}
            {getFeatureBadge()}
          </CardTitle>
          {description && (
            <p className="text-sm text-muted-foreground mt-2">
              {description}
            </p>
          )}
        </CardHeader>
        
        <CardContent className="text-center space-y-4">
          {/* Value Proposition */}
          <div className="p-4 rounded-lg bg-background/50 border">
            <div className="flex items-start space-x-3">
              <Shield className="h-5 w-5 text-primary mt-0.5" />
              <div className="text-left">
                <p className="text-sm font-medium">Premium Feature</p>
                <p className="text-sm text-muted-foreground">{finalValueProp}</p>
              </div>
            </div>
          </div>

          {/* Beta info if active */}
          {trialStatus.isBetaActive && (
            <div className="p-3 rounded-lg bg-primary/10 border border-primary/20">
              <div className="flex items-center justify-center space-x-2 text-sm">
                <Star className="h-4 w-4 text-primary" />
                <span className="font-medium">
                  Trailblazer Beta Access
                </span>
              </div>
            </div>
          )}

          {/* Action buttons */}
          <div className="space-y-3">
            <Button 
              onClick={handleUpgradeClick}
              className="w-full"
              size="lg"
            >
              {trialStatus.isBetaActive ? (
                <>
                  <Zap className="h-4 w-4 mr-2" />
                  Upgrade to Plus
                </>
              ) : featureType === 'enterprise' ? (
                <>
                  Contact Sales
                  <ArrowRight className="h-4 w-4 ml-2" />
                </>
              ) : (
                <>
                  Upgrade Now
                  <ArrowRight className="h-4 w-4 ml-2" />
                </>
              )}
            </Button>

            {!showPreview && (
              <Button 
                variant="ghost" 
                size="sm" 
                onClick={handleDismiss}
                className="w-full text-muted-foreground hover:text-foreground"
              >
                Maybe later
              </Button>
            )}
          </div>

          <p className="text-xs text-muted-foreground">
            {finalUpgradeMessage}
          </p>
        </CardContent>
      </Card>
    </div>
  );
};