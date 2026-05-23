import { useState, useEffect, createElement } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { useToast } from '@/hooks/use-toast';
import { useExecutiveAI } from '@/hooks/useExecutiveAI';
import { 
  CheckCircle2, 
  Shield, 
  Users, 
  FileText, 
  Zap, 
  Target,
  ArrowRight,
  ChevronRight,
  X,
  Play,
  UserCheck,
  Building,
  Settings,
  Activity,
  AlertTriangle,
  Brain
} from 'lucide-react';
import { useNavigate } from '@/lib/router-compat';
import { useUserProfile } from '@/hooks/useUserProfile';

interface TourStep {
  id: string;
  title: string;
  description: string;
  icon: React.ComponentType<any>;
  route?: string;
  action?: () => void;
  highlight?: string;
  roles: string[];
  aiAction?: 'threat-analysis' | 'cmmc-planning' | 'team-performance' | 'security-report';
  requiresAI?: boolean;
}

interface RoleBasedTourProps {
  open: boolean;
  onClose: () => void;
  onComplete: () => void;
}

export const RoleBasedTour = ({ open, onClose, onComplete }: RoleBasedTourProps) => {
  const { profile } = useUserProfile();
  const navigate = useNavigate();
  const { toast } = useToast();
  const { getThreatAnalysis, getCMMCPlanning, getTeamPerformance, getSecurityReport, loading } = useExecutiveAI();
  const [currentStep, setCurrentStep] = useState(0);
  const [completedSteps, setCompletedSteps] = useState<Set<string>>(new Set());

  const executiveSteps: TourStep[] = [
    {
      id: 'executive-overview',
      title: 'Security Posture Overview',
      description: 'View high-level security metrics and compliance status at a glance',
      icon: Shield,
      route: '/dashboard?view=executive',
      roles: ['admin', 'executive'],
      aiAction: 'security-report',
      requiresAI: true
    },
    {
      id: 'compliance-status',
      title: 'CMMC Compliance Dashboard',
      description: 'Track your organization\'s progress toward CMMC certification',
      icon: FileText,
      route: '/compliance-automation?view=cmmc&mode=executive',
      roles: ['admin', 'executive'],
      aiAction: 'cmmc-planning',
      requiresAI: true
    },
    {
      id: 'risk-assessment',
      title: 'Risk Assessment Summary',
      description: 'Review critical security risks and mitigation strategies',
      icon: Target,
      route: '/security?tab=threats&view=executive',
      roles: ['admin', 'executive'],
      aiAction: 'threat-analysis',
      requiresAI: true
    },
    {
      id: 'team-performance',
      title: 'Team Performance Analytics',
      description: 'Monitor security team performance and KPIs',
      icon: Users,
      route: '/admin?tab=performance&view=executive',
      roles: ['admin', 'executive'],
      aiAction: 'team-performance',
      requiresAI: true
    }
  ];

  const technicalSteps: TourStep[] = [
    {
      id: 'security-dashboard',
      title: 'Security Operations Center',
      description: 'Monitor real-time threats, alerts, and security events',
      icon: Shield,
      route: '/security?tab=events',
      roles: ['admin', 'security_engineer', 'analyst']
    },
    {
      id: 'infrastructure-discovery',
      title: 'Asset Discovery & Management',
      description: 'Scan and catalog your infrastructure automatically',
      icon: Zap,
      route: '/infrastructure?tab=discovery',
      roles: ['admin', 'security_engineer', 'analyst']
    },
    {
      id: 'threat-intelligence',
      title: 'Threat Intelligence Hub',
      description: 'Access real-time threat feeds and OSINT data',
      icon: Target,
      route: '/dashboard?view=threat-feeds',
      roles: ['admin', 'security_engineer', 'analyst']
    },
    {
      id: 'automation-setup',
      title: 'Automated Response Configuration',
      description: 'Configure automated remediation and response workflows',
      icon: Settings,
      route: '/compliance-automation?tab=remediation',
      roles: ['admin', 'security_engineer']
    },
    {
      id: 'khepra-protocol',
      title: 'KHEPRA Protocol Integration',
      description: 'AI-powered cultural threat intelligence and agentic security',
      icon: Brain,
      route: '/khepra?view=dashboard',
      roles: ['admin', 'security_engineer', 'analyst']
    },
    {
      id: 'integration-hub',
      title: 'Security Tool Integration',
      description: 'Connect and manage your security stack integrations',
      icon: Activity,
      route: '/integration-guide?view=hub',
      roles: ['admin', 'security_engineer']
    }
  ];

  const getRelevantSteps = (): TourStep[] => {
    const role = profile?.role || 'viewer';
    const isExecutive = ['admin', 'executive'].includes(role);
    
    if (isExecutive) {
      return [...executiveSteps, ...technicalSteps.slice(0, 2)];
    }
    
    return technicalSteps.filter(step => 
      step.roles.includes(role) || step.roles.includes('analyst')
    );
  };

  const steps = getRelevantSteps();
  const progress = (completedSteps.size / steps.length) * 100;

  const handleStepClick = async (step: TourStep, index: number) => {
    setCurrentStep(index);
    setCompletedSteps(prev => new Set([...prev, step.id]));
    
    // Execute AI action if required
    if (step.requiresAI && step.aiAction) {
      toast({
        title: `Preparing ${step.title}`,
        description: "AI is generating personalized insights...",
      });

      try {
        switch (step.aiAction) {
          case 'threat-analysis':
            await getThreatAnalysis();
            break;
          case 'cmmc-planning':
            await getCMMCPlanning();
            break;
          case 'team-performance':
            await getTeamPerformance();
            break;
          case 'security-report':
            await getSecurityReport();
            break;
        }
      } catch (error) {
        console.error('AI action failed:', error);
      }
    }
    
    if (step.route) {
      navigate(step.route);
      // Close tour after navigation to let user explore
      setTimeout(() => {
        onClose();
      }, 1500);
    }
    
    if (step.action) {
      step.action();
    }
  };

  const handleNext = () => {
    if (currentStep < steps.length - 1) {
      setCurrentStep(currentStep + 1);
    } else {
      onComplete();
    }
  };

  const handleSkip = () => {
    onClose();
  };

  const getRoleDisplayName = () => {
    const role = profile?.role || 'viewer';
    switch (role) {
      case 'admin': return 'Administrator';
      case 'executive': return 'Executive';
      case 'security_engineer': return 'Security Engineer';
      case 'analyst': return 'Security Analyst';
      default: return 'Team Member';
    }
  };

  useEffect(() => {
    if (open) {
      setCurrentStep(0);
      setCompletedSteps(new Set());
    }
  }, [open]);

  if (!open) return null;

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-primary/10 rounded-lg">
                <UserCheck className="h-6 w-6 text-primary" />
              </div>
              <div>
                <DialogTitle className="text-xl">
                  Welcome, {getRoleDisplayName()}
                </DialogTitle>
                <p className="text-sm text-muted-foreground">
                  Personalized tour based on your role and responsibilities
                </p>
              </div>
            </div>
            <Button variant="ghost" size="icon" onClick={onClose}>
              <X className="h-4 w-4" />
            </Button>
          </div>
        </DialogHeader>

        <div className="space-y-6">
          {/* Progress Section */}
          <Card className="border-primary/20 bg-gradient-to-r from-primary/5 to-secondary/5">
            <CardContent className="p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium">Tour Progress</span>
                <span className="text-sm text-muted-foreground">
                  {completedSteps.size} of {steps.length} steps
                </span>
              </div>
              <Progress value={progress} className="h-2" />
            </CardContent>
          </Card>

          {/* Current Step */}
          {steps[currentStep] && (
            <Card className="border-primary shadow-sm">
              <CardHeader>
                <div className="flex items-start space-x-4">
                  <div className="p-3 bg-primary/10 rounded-lg">
                    {createElement(steps[currentStep].icon, { className: "h-6 w-6 text-primary" })}
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-lg">
                        {steps[currentStep].title}
                      </CardTitle>
                      <Badge variant="outline">
                        Step {currentStep + 1} of {steps.length}
                      </Badge>
                    </div>
                    <p className="text-muted-foreground mt-2">
                      {steps[currentStep].description}
                    </p>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between">
                  <Button
                    variant="outline"
                    onClick={handleSkip}
                    className="text-muted-foreground"
                  >
                    Skip Tour
                  </Button>
                  <div className="flex space-x-2">
                    {currentStep > 0 && (
                      <Button
                        variant="outline"
                        onClick={() => setCurrentStep(currentStep - 1)}
                      >
                        Previous
                      </Button>
                    )}
                    <Button
                      onClick={() => handleStepClick(steps[currentStep], currentStep)}
                      disabled={loading}
                      className="flex items-center space-x-2"
                    >
                      <Play className="h-4 w-4" />
                      <span>
                        {loading ? 'Preparing...' : 
                         steps[currentStep].route ? 'Go to Feature' : 'Continue'}
                      </span>
                      <ChevronRight className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* All Steps Overview */}
          <div className="grid gap-3">
            <h3 className="font-semibold">Tour Overview</h3>
            {steps.map((step, index) => {
              const Icon = step.icon;
              const isActive = index === currentStep;
              const isCompleted = completedSteps.has(step.id);
              
              return (
                <Card 
                  key={step.id}
                  className={`cursor-pointer transition-all duration-200 hover:shadow-md ${
                    isActive ? 'border-primary bg-primary/5' : ''
                  } ${isCompleted ? 'bg-success/10 border-success/20' : ''} ${
                    step.requiresAI ? 'border-l-4 border-l-accent' : ''
                  }`}
                  onClick={() => setCurrentStep(index)}
                >
                  <CardContent className="p-4">
                    <div className="flex items-center space-x-3">
                      <div className={`p-2 rounded-lg ${
                        isCompleted ? 'bg-success text-primary-foreground' : 
                        isActive ? 'bg-primary/10 text-primary' : 'bg-muted text-muted-foreground'
                      }`}>
                        {isCompleted ? (
                          <CheckCircle2 className="h-5 w-5" />
                        ) : (
                          <Icon className="h-5 w-5" />
                        )}
                      </div>
                      
                      <div className="flex-1">
                        <div className="flex items-center space-x-2">
                          <h4 className="font-medium">{step.title}</h4>
                          {step.requiresAI && (
                            <Badge variant="secondary" className="text-xs">
                              <Brain className="h-3 w-3 mr-1" />
                              AI-Powered
                            </Badge>
                          )}
                        </div>
                        <p className="text-sm text-muted-foreground">
                          {step.description}
                        </p>
                      </div>
                      
                      {isActive && (
                        <ArrowRight className="h-4 w-4 text-primary" />
                      )}
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>

          {/* Completion Actions */}
          {completedSteps.size === steps.length && (
            <Card className="border-green-500/20 bg-green-500/5">
              <CardContent className="p-6 text-center">
                <CheckCircle2 className="h-12 w-12 text-green-500 mx-auto mb-4" />
                <h3 className="text-xl font-semibold mb-2">Tour Complete!</h3>
                <p className="text-muted-foreground mb-4">
                  You're ready to start securing your organization with our platform.
                </p>
                <Button onClick={onComplete} className="bg-success hover:bg-success/90">
                  Start Using Platform
                </Button>
              </CardContent>
            </Card>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
};