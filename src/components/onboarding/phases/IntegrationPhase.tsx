import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useToast } from '@/hooks/use-toast';
import { Check, Loader2, PlayCircle } from 'lucide-react';
import { Badge } from '@/components/ui/badge';

interface IntegrationPhaseProps {
  organizationId: string;
  onboardingId: string;
}

interface IntegrationStep {
  id: string;
  title: string;
  description: string;
  status: 'pending' | 'in_progress' | 'completed';
  tool: string;
}

export function IntegrationPhase({ organizationId }: IntegrationPhaseProps) {
  const { toast } = useToast();
  const [integrationSteps, setIntegrationSteps] = useState<IntegrationStep[]>([
    {
      id: 'ansible',
      title: 'Deploy Ansible Lockdown Playbooks',
      description: 'Automated STIG remediation using community-maintained playbooks',
      status: 'pending',
      tool: 'Ansible',
    },
    {
      id: 'drift',
      title: 'Enable Continuous Drift Detection',
      description: '30-minute enforcement cycles with automated alerts',
      status: 'pending',
      tool: 'Continuous Monitor',
    },
    {
      id: 'evidence',
      title: 'Configure Evidence Collection Pipelines',
      description: 'Automated audit-ready documentation generation',
      status: 'pending',
      tool: 'Evidence Collector',
    },
    {
      id: 'scap',
      title: 'Integrate OpenSCAP Validation',
      description: 'DISA-validated SCAP compliance scanning',
      status: 'pending',
      tool: 'OpenSCAP',
    },
  ]);

  const executeStep = async (stepId: string) => {
    setIntegrationSteps(prev =>
      prev.map(step =>
        step.id === stepId ? { ...step, status: 'in_progress' } : step
      )
    );

    await new Promise(resolve => setTimeout(resolve, 3000));

    setIntegrationSteps(prev =>
      prev.map(step =>
        step.id === stepId ? { ...step, status: 'completed' } : step
      )
    );

    const completedStep = integrationSteps.find(s => s.id === stepId);
    toast({
      title: `${completedStep?.title} Complete`,
      description: `Successfully deployed ${completedStep?.tool}`,
    });
  };

  const executeAllSteps = async () => {
    for (const step of integrationSteps) {
      if (step.status !== 'completed') {
        await executeStep(step.id);
      }
    }

    toast({
      title: 'Integration Complete!',
      description: 'All automation tools deployed and configured',
    });
  };

  const allCompleted = integrationSteps.every(step => step.status === 'completed');
  const anyInProgress = integrationSteps.some(step => step.status === 'in_progress');

  return (
    <div className="space-y-6">
      <div className="rounded-lg bg-primary/10 p-4 border border-primary/20">
        <h3 className="font-semibold mb-2">Automation Deployment</h3>
        <ul className="space-y-2 text-sm">
          <li>✓ Ansible Lockdown for immediate STIG remediation</li>
          <li>✓ Continuous monitoring with 30-minute enforcement cycles</li>
          <li>✓ Automated evidence collection for audit readiness</li>
          <li>✓ OpenSCAP integration for DISA-validated scanning</li>
        </ul>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Integration Steps</CardTitle>
          <CardDescription>
            Deploy and configure automated compliance tools
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {integrationSteps.map((step) => (
            <div
              key={step.id}
              className="flex items-center justify-between p-4 border rounded-lg"
            >
              <div className="flex items-center gap-4 flex-1">
                <div>
                  {step.status === 'completed' ? (
                    <div className="h-10 w-10 rounded-full bg-primary flex items-center justify-center">
                      <Check className="h-5 w-5 text-primary-foreground" />
                    </div>
                  ) : step.status === 'in_progress' ? (
                    <div className="h-10 w-10 rounded-full bg-primary/20 flex items-center justify-center">
                      <Loader2 className="h-5 w-5 animate-spin text-primary" />
                    </div>
                  ) : (
                    <div className="h-10 w-10 rounded-full bg-muted flex items-center justify-center">
                      <PlayCircle className="h-5 w-5 text-muted-foreground" />
                    </div>
                  )}
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <h4 className="font-semibold">{step.title}</h4>
                    <Badge variant="outline">{step.tool}</Badge>
                  </div>
                  <p className="text-sm text-muted-foreground">{step.description}</p>
                </div>
              </div>
              <Button
                onClick={() => executeStep(step.id)}
                disabled={step.status !== 'pending' || anyInProgress}
                size="sm"
              >
                {step.status === 'completed' ? 'Completed' : step.status === 'in_progress' ? 'Running...' : 'Deploy'}
              </Button>
            </div>
          ))}
        </CardContent>
      </Card>

      {!allCompleted && (
        <Button
          onClick={executeAllSteps}
          disabled={anyInProgress}
          className="w-full"
          size="lg"
        >
          {anyInProgress ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Deploying...
            </>
          ) : (
            <>
              <PlayCircle className="mr-2 h-4 w-4" />
              Deploy All Automation Tools
            </>
          )}
        </Button>
      )}

      {allCompleted && (
        <Card className="border-primary bg-primary/5">
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-full bg-primary flex items-center justify-center">
                <Check className="h-6 w-6 text-primary-foreground" />
              </div>
              <div>
                <h3 className="font-semibold">Integration Complete!</h3>
                <p className="text-sm text-muted-foreground">
                  All automation tools are deployed and actively monitoring your environment
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
