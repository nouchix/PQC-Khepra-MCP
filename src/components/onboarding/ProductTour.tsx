import { useState, useEffect } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { 
  X, 
  ArrowRight, 
  ArrowLeft,
  Target,
  CheckCircle2,
  Lightbulb
} from 'lucide-react';

interface TourStep {
  id: string;
  title: string;
  description: string;
  position: 'top' | 'bottom' | 'left' | 'right';
  highlight?: string;
  action?: string;
}

interface ProductTourProps {
  active: boolean;
  onComplete: () => void;
  onSkip: () => void;
}

export const ProductTour = ({ active, onComplete, onSkip }: ProductTourProps) => {
  const [currentStep, setCurrentStep] = useState(0);
  const [isVisible, setIsVisible] = useState(false);

  const tourSteps: TourStep[] = [
    {
      id: 'dashboard-overview',
      title: 'Your Security Command Center',
      description: 'This is your main dashboard showing real-time security metrics, threat alerts, and system status.',
      position: 'bottom',
      highlight: '[data-tour="dashboard"]'
    },
    {
      id: 'threat-feed',
      title: 'Live Threat Intelligence',
      description: 'Monitor threats in real-time with our AI-powered threat detection system.',
      position: 'left',
      highlight: '[data-tour="threat-feed"]'
    },
    {
      id: 'integration-hub',
      title: 'Integration Hub • KHEPRA Enhanced',
      description: 'Connect security tools with AI-powered configuration and cultural intelligence framework.',
      position: 'bottom',
      highlight: '[data-tour="integration-hub"]'
    },
    {
      id: 'compliance-status',
      title: 'CMMC Compliance Tracking',
      description: 'Track your progress toward CMMC certification with automated compliance monitoring.',
      position: 'top',
      highlight: '[data-tour="compliance"]'
    },
    {
      id: 'infrastructure-scan',
      title: 'Infrastructure Discovery',
      description: 'Automatically discover and catalog all your IT assets with our AI scanning engine.',
      position: 'right',
      highlight: '[data-tour="infrastructure"]',
      action: 'Run your first scan to see immediate results!'
    }
  ];

  useEffect(() => {
    if (active) {
      setIsVisible(true);
    }
  }, [active]);

  const handleNext = () => {
    if (currentStep < tourSteps.length - 1) {
      setCurrentStep(currentStep + 1);
    } else {
      handleComplete();
    }
  };

  const handlePrevious = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const handleComplete = () => {
    setIsVisible(false);
    onComplete();
  };

  if (!isVisible) return null;

  const currentTourStep = tourSteps[currentStep];
  const progress = ((currentStep + 1) / tourSteps.length) * 100;

  return (
    <>
      {/* Overlay */}
      <div className="fixed inset-0 bg-black/50 z-40 backdrop-blur-sm" />
      
      {/* Tour Card */}
      <Card className="fixed z-50 w-80 shadow-lg border-primary/20 bg-background/95 backdrop-blur-lg">
        <CardContent className="p-6">
          {/* Header */}
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-2">
              <Target className="h-5 w-5 text-primary" />
              <Badge variant="outline" className="text-xs">
                Step {currentStep + 1} of {tourSteps.length}
              </Badge>
            </div>
            <Button variant="ghost" size="sm" onClick={onSkip}>
              <X className="h-4 w-4" />
            </Button>
          </div>

          {/* Progress Bar */}
          <div className="w-full bg-muted rounded-full h-2 mb-4">
            <div 
              className="bg-primary h-2 rounded-full transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          </div>

          {/* Content */}
          <div className="space-y-4">
            <div>
              <h3 className="font-semibold text-lg mb-2">{currentTourStep.title}</h3>
              <p className="text-muted-foreground text-sm leading-relaxed">
                {currentTourStep.description}
              </p>
            </div>

            {currentTourStep.action && (
              <div className="flex items-start space-x-2 p-3 bg-blue-500/10 border border-blue-500/20 rounded-lg">
                <Lightbulb className="h-4 w-4 text-blue-500 flex-shrink-0 mt-0.5" />
                <p className="text-sm font-medium text-blue-600 dark:text-blue-400">
                  {currentTourStep.action}
                </p>
              </div>
            )}
          </div>

          {/* Navigation */}
          <div className="flex justify-between items-center mt-6">
            <Button 
              variant="ghost" 
              size="sm" 
              onClick={handlePrevious}
              disabled={currentStep === 0}
            >
              <ArrowLeft className="h-4 w-4 mr-2" />
              Previous
            </Button>

            <div className="flex space-x-2">
              <Button variant="ghost" size="sm" onClick={onSkip}>
                Skip Tour
              </Button>
              <Button size="sm" onClick={handleNext}>
                {currentStep === tourSteps.length - 1 ? (
                  <>
                    Complete
                    <CheckCircle2 className="h-4 w-4 ml-2" />
                  </>
                ) : (
                  <>
                    Next
                    <ArrowRight className="h-4 w-4 ml-2" />
                  </>
                )}
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </>
  );
};