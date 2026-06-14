import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { 
  CheckCircle2, 
  Shield, 
  Zap, 
  FileText, 
  Users, 
  ArrowRight,
  Star,
  Clock,
  Target
} from 'lucide-react';
import { useTrialStatus } from '@/hooks/useTrialStatus';
import { useUsageTracker } from '@/components/UsageTracker';
import { useNavigate } from 'react-router-dom';

interface OnboardingStep {
  id: string;
  title: string;
  description: string;
  icon: any;
  route?: string;
  completed: boolean;
  value: string;
}

export const TrialOnboarding = () => {
  const { trialStatus: _trialStatus } = useTrialStatus();
  const { trackFeatureAccess } = useUsageTracker();
  const navigate = useNavigate();
  const [currentStep, setCurrentStep] = useState(0);

  const steps: OnboardingStep[] = [
    {
      id: 'explore-dashboard',
      title: 'Explore Security Dashboard',
      description: 'Get familiar with your security overview and real-time metrics',
      icon: Shield,
      route: '/security',
      completed: false,
      value: "See live security metrics, threat intelligence, and compliance status"
    },
    {
      id: 'connect-integrations',
      title: 'Connect Security Tools',
      description: 'Integrate with your existing security infrastructure using the KHEPRA-enhanced Integration Hub',
      icon: Zap,
      route: '/?tab=integrations',
      completed: false,
      value: "Connect to industry-standard tools like Splunk, CrowdStrike, and more with AI-powered configuration"
    },
    {
      id: 'review-compliance',
      title: 'Review Compliance Status',
      description: 'See your CMMC readiness and required controls',
      icon: FileText,
      route: '/security?tab=compliance',
      completed: false,
      value: "Track progress toward CMMC Level 3 certification"
    },
    {
      id: 'invite-team',
      title: 'Invite Your Team',
      description: 'Add team members and configure access controls',
      icon: Users,
      route: '/setup',
      completed: false,
      value: "Collaborate with unlimited team members"
    }
  ];

  const handleStepClick = (step: OnboardingStep, index: number) => {
    trackFeatureAccess(step.id, 'premium');
    setCurrentStep(index);
    if (step.route) {
      navigate(step.route);
    }
  };

  const progress = ((currentStep + 1) / steps.length) * 100;

  return (
    <div className="space-y-6">
      {/* Beta Status Header */}
      <Card className="border-2 border-primary/20 bg-gradient-to-r from-primary/5 to-secondary/5">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-primary/10 rounded-lg">
                <Star className="h-6 w-6 text-primary" />
              </div>
              <div>
                <CardTitle className="text-xl">Trailblazer Beta Access</CardTitle>
                <div className="flex items-center space-x-2 text-sm text-muted-foreground">
                  <Clock className="h-4 w-4" />
                  <span>Free basic features included</span>
                </div>
              </div>
            </div>
            <Badge variant="default" className="bg-primary">
              Beta Access
            </Badge>
          </div>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground mb-4">
            You have complete access to basic security features. Follow this guide to get started and see the value of upgrading to Plus.
          </p>
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span>Onboarding Progress</span>
              <span>{Math.round(progress)}% complete</span>
            </div>
            <Progress value={progress} className="h-2" />
          </div>
        </CardContent>
      </Card>

      {/* Onboarding Steps */}
      <div className="grid gap-4">
        {steps.map((step, index) => {
          const Icon = step.icon;
          const isActive = index === currentStep;
          const isCompleted = step.completed;
          
          return (
            <Card 
              key={step.id}
              className={`cursor-pointer transition-all duration-200 hover:shadow-md ${
                isActive ? 'border-primary shadow-sm' : ''
              } ${isCompleted ? 'bg-muted/30' : ''}`}
              onClick={() => handleStepClick(step, index)}
            >
              <CardContent className="p-6">
                <div className="flex items-start space-x-4">
                  <div className={`p-3 rounded-lg ${
                    isCompleted ? 'bg-primary text-primary-foreground' : 
                    isActive ? 'bg-primary/10 text-primary' : 'bg-muted text-muted-foreground'
                  }`}>
                    {isCompleted ? (
                      <CheckCircle2 className="h-6 w-6" />
                    ) : (
                      <Icon className="h-6 w-6" />
                    )}
                  </div>
                  
                  <div className="flex-1 space-y-2">
                    <div className="flex items-center justify-between">
                      <h3 className="font-semibold text-lg">{step.title}</h3>
                      <div className="flex items-center space-x-2">
                        <Badge variant="outline" className="text-xs">
                          Step {index + 1}
                        </Badge>
                        <ArrowRight className="h-4 w-4 text-muted-foreground" />
                      </div>
                    </div>
                    
                    <p className="text-muted-foreground">{step.description}</p>
                    
                    <div className="flex items-center space-x-2 text-sm">
                      <Target className="h-4 w-4 text-primary" />
                      <span className="font-medium text-primary">{step.value}</span>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Value Proposition */}
      <Card className="bg-gradient-to-br from-primary/5 to-secondary/5 border-primary/20">
        <CardContent className="p-6 text-center">
          <h3 className="text-xl font-semibold mb-2">Complete Setup in Under 30 Minutes</h3>
          <p className="text-muted-foreground mb-4">
            Follow these steps to see immediate value and understand how our platform can accelerate your CMMC certification.
          </p>
          <Button onClick={() => navigate('/billing')} className="bg-primary hover:bg-primary/90">
            Upgrade to Trailblazer Plus - $19/month
          </Button>
        </CardContent>
      </Card>
    </div>
  );
};