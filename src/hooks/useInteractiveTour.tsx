import { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from '@/lib/router-compat';
import { useToast } from '@/hooks/use-toast';
import { useExecutiveAI } from '@/hooks/useExecutiveAI';

export interface TourAction {
  type: 'navigate' | 'ai-analysis' | 'highlight' | 'demo';
  route?: string;
  aiAction?: 'threat-analysis' | 'cmmc-planning' | 'team-performance' | 'security-report';
  targetElement?: string;
  duration?: number;
}

export interface InteractiveTourStep {
  id: string;
  title: string;
  description: string;
  category: 'security' | 'compliance' | 'operations' | 'analytics';
  actions: TourAction[];
  completionCriteria?: string[];
  estimatedTime?: number;
}

export const useInteractiveTour = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { toast } = useToast();
  const { callExecutiveAI, loading: aiLoading } = useExecutiveAI();
  
  const [currentStep, setCurrentStep] = useState(0);
  const [completedSteps, setCompletedSteps] = useState<Set<string>>(new Set());
  const [tourActive, setTourActive] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);

  // Define comprehensive tour steps
  const tourSteps: InteractiveTourStep[] = [
    {
      id: 'security-overview',
      title: 'Security Posture Overview',
      description: 'View high-level security metrics and compliance status at a glance',
      category: 'security',
      estimatedTime: 2,
      actions: [
        { 
          type: 'ai-analysis', 
          aiAction: 'security-report'
        },
        { 
          type: 'navigate', 
          route: '/security?view=executive'
        }
      ]
    },
    {
      id: 'cmmc-compliance',
      title: 'CMMC Compliance Dashboard',
      description: 'Track your organization\'s progress toward CMMC certification',
      category: 'compliance',
      estimatedTime: 3,
      actions: [
        {
          type: 'ai-analysis',
          aiAction: 'cmmc-planning'
        },
        {
          type: 'navigate',
          route: '/compliance-automation?view=cmmc&mode=executive'
        }
      ]
    },
    {
      id: 'threat-assessment',
      title: 'Risk Assessment Summary',
      description: 'Review critical security risks and mitigation strategies',
      category: 'security',
      estimatedTime: 3,
      actions: [
        {
          type: 'ai-analysis',
          aiAction: 'threat-analysis'
        },
        {
          type: 'navigate',
          route: '/security?tab=threats&view=executive'
        }
      ]
    },
    {
      id: 'operations-center',
      title: 'Security Operations Center',
      description: 'Monitor real-time threats, alerts, and security events',
      category: 'operations',
      estimatedTime: 4,
      actions: [
        {
          type: 'navigate',
          route: '/security?tab=events'
        },
        {
          type: 'highlight',
          targetElement: '[data-tour="threat-feed"]',
          duration: 3000
        }
      ]
    },
    {
      id: 'asset-discovery',
      title: 'Asset Discovery & Management',
      description: 'Scan and catalog your infrastructure automatically',
      category: 'operations',
      estimatedTime: 3,
      actions: [
        {
          type: 'navigate',
          route: '/infrastructure?tab=discovery'
        },
        {
          type: 'demo',
          targetElement: '[data-tour="scan-button"]'
        }
      ]
    },
    {
      id: 'team-performance',
      title: 'Team Performance Analytics',
      description: 'Monitor security team performance and KPIs',
      category: 'analytics',
      estimatedTime: 2,
      actions: [
        {
          type: 'ai-analysis',
          aiAction: 'team-performance'
        },
        {
          type: 'navigate',
          route: '/admin?tab=performance&view=executive'
        }
      ]
    }
  ];

  // Check if tour should be active based on URL params
  useEffect(() => {
    const tourParam = searchParams.get('tour');
    if (tourParam === 'quick' || tourParam === 'interactive') {
      setTourActive(true);
      setCurrentStep(0);
    }
  }, [searchParams]);

  const executeStepActions = async (step: InteractiveTourStep) => {
    setIsProcessing(true);
    
    try {
      for (const action of step.actions) {
        switch (action.type) {
          case 'ai-analysis':
            if (action.aiAction) {
              toast({
                title: `Analyzing ${step.title}`,
                description: "AI is generating personalized insights...",
              });
              await callExecutiveAI({ action: action.aiAction });
            }
            break;
            
          case 'navigate':
            if (action.route) {
              navigate(action.route);
              await new Promise(resolve => setTimeout(resolve, 1000));
            }
            break;
            
          case 'highlight':
            if (action.targetElement) {
              const element = document.querySelector(action.targetElement);
              if (element) {
                element.scrollIntoView({ behavior: 'smooth', block: 'center' });
                element.classList.add('tour-highlight');
                setTimeout(() => {
                  element.classList.remove('tour-highlight');
                }, action.duration || 3000);
              }
            }
            break;
            
          case 'demo':
            // Trigger demo animations or interactions
            toast({
              title: "Interactive Demo",
              description: `Try the ${step.title} feature`,
              variant: "default"
            });
            break;
        }
      }
      
      // Mark step as completed
      setCompletedSteps(prev => new Set([...prev, step.id]));
      
    } catch (error) {
      console.error('Tour step execution failed:', error);
      toast({
        title: "Tour Step Failed",
        description: "Please try again or skip this step",
        variant: "destructive"
      });
    } finally {
      setIsProcessing(false);
    }
  };

  const goToStep = async (stepIndex: number) => {
    if (stepIndex >= 0 && stepIndex < tourSteps.length) {
      setCurrentStep(stepIndex);
      const step = tourSteps[stepIndex];
      await executeStepActions(step);
    }
  };

  const nextStep = async () => {
    if (currentStep < tourSteps.length - 1) {
      await goToStep(currentStep + 1);
    } else {
      completeTour();
    }
  };

  const previousStep = async () => {
    if (currentStep > 0) {
      await goToStep(currentStep - 1);
    }
  };

  const skipTour = () => {
    setTourActive(false);
    navigate('/dashboard');
    toast({
      title: "Tour Skipped",
      description: "You can restart the tour anytime from settings",
    });
  };

  const completeTour = () => {
    setTourActive(false);
    localStorage.setItem('tour_completed', 'true');
    navigate('/dashboard');
    toast({
      title: "Tour Complete!",
      description: "You're ready to start using the platform",
      variant: "default"
    });
  };

  const restartTour = () => {
    setCurrentStep(0);
    setCompletedSteps(new Set());
    setTourActive(true);
    navigate('/dashboard?tour=quick');
  };

  const progress = (completedSteps.size / tourSteps.length) * 100;

  return {
    // State
    tourActive,
    currentStep,
    completedSteps,
    isProcessing: isProcessing || aiLoading,
    progress,
    
    // Data
    tourSteps,
    currentTourStep: tourSteps[currentStep],
    
    // Actions
    goToStep,
    nextStep,
    previousStep,
    skipTour,
    completeTour,
    restartTour,
    executeStepActions
  };
};