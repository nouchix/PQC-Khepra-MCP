import { useState } from 'react';
import { Check, ChevronRight, Loader2 } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { useOrganizationOnboarding } from '@/hooks/useOrganizationOnboarding';
import { PreOnboardingPhase } from './phases/PreOnboardingPhase';
import DiscoveryPhase from './phases/DiscoveryPhase';
import { IntegrationPhase } from './phases/IntegrationPhase';
import { TrainingPhase } from './phases/TrainingPhase';
import { GoLivePhase } from './phases/GoLivePhase';

interface OnboardingWizardProps {
  organizationId: string;
}

const PHASES = [
  {
    id: 'pre_onboarding',
    title: 'Pre-Onboarding',
    description: 'Complete intake questionnaire and assign team leads',
  },
  {
    id: 'discovery',
    title: 'Discovery & Assessment',
    description: 'Automated asset scanning and baseline STIG compliance analysis',
  },
  {
    id: 'integration',
    title: 'Environment Integration',
    description: 'Deploy Ansible playbooks and continuous monitoring',
  },
  {
    id: 'training',
    title: 'Training & Documentation',
    description: 'Role-based training and audit-ready documentation',
  },
  {
    id: 'go_live',
    title: 'Go-Live & Support',
    description: 'Continuous monitoring and quarterly reviews',
  },
];

export function OnboardingWizard({ organizationId }: OnboardingWizardProps) {
  const { onboarding, loading, updatePhase } = useOrganizationOnboarding(organizationId);
  const [currentStep, setCurrentStep] = useState(0);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  if (!onboarding) {
    return (
      <Card>
        <CardContent className="pt-6">
          <p className="text-muted-foreground">Failed to load onboarding data</p>
        </CardContent>
      </Card>
    );
  }

  const currentPhaseId = PHASES[currentStep].id;
  const progress = ((currentStep + 1) / PHASES.length) * 100;

  const handleNext = async () => {
    if (currentStep < PHASES.length - 1) {
      await updatePhase(PHASES[currentStep].id, 'completed');
      setCurrentStep(currentStep + 1);
      await updatePhase(PHASES[currentStep + 1].id, 'in_progress');
    }
  };

  const handlePrevious = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const renderPhaseContent = () => {
    switch (currentPhaseId) {
      case 'pre_onboarding':
        return <PreOnboardingPhase organizationId={organizationId} onboardingId={onboarding.id} />;
      case 'discovery':
        return <DiscoveryPhase organizationId={organizationId} onboardingId={onboarding.id} />;
      case 'integration':
        return <IntegrationPhase organizationId={organizationId} onboardingId={onboarding.id} />;
      case 'training':
        return <TrainingPhase />;
      case 'go_live':
        return <GoLivePhase />;
      default:
        return null;
    }
  };

  return (
    <div className="space-y-6">
      {/* Progress Overview */}
      <Card>
        <CardHeader>
          <CardTitle>Onboarding Progress</CardTitle>
          <CardDescription>
            Phase {currentStep + 1} of {PHASES.length}: {PHASES[currentStep].title}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Progress value={progress} className="mb-4" />
          <div className="grid grid-cols-5 gap-4">
            {PHASES.map((phase, index) => {
              const isCompleted = index < currentStep;
              const isCurrent = index === currentStep;
              const phaseStatus = onboarding.phase_status[phase.id];

              return (
                <div
                  key={phase.id}
                  className={`flex flex-col items-center text-center space-y-2 ${
                    isCurrent ? 'opacity-100' : isCompleted ? 'opacity-75' : 'opacity-50'
                  }`}
                >
                  <div
                    className={`w-10 h-10 rounded-full flex items-center justify-center border-2 ${
                      isCompleted
                        ? 'bg-primary border-primary text-primary-foreground'
                        : isCurrent
                        ? 'border-primary text-primary'
                        : 'border-muted'
                    }`}
                  >
                    {isCompleted ? <Check className="h-5 w-5" /> : index + 1}
                  </div>
                  <div className="text-xs font-medium">{phase.title}</div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Current Phase Content */}
      <Card>
        <CardHeader>
          <CardTitle>{PHASES[currentStep].title}</CardTitle>
          <CardDescription>{PHASES[currentStep].description}</CardDescription>
        </CardHeader>
        <CardContent>{renderPhaseContent()}</CardContent>
      </Card>

      {/* Navigation */}
      <div className="flex justify-between">
        <Button
          variant="outline"
          onClick={handlePrevious}
          disabled={currentStep === 0}
        >
          Previous
        </Button>
        <Button
          onClick={handleNext}
          disabled={currentStep === PHASES.length - 1}
        >
          {currentStep === PHASES.length - 1 ? 'Complete' : 'Next'}
          <ChevronRight className="ml-2 h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}
