import { useState } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { useToast } from '@/hooks/use-toast';
import { 
  ChevronLeft, 
  ChevronRight, 
  CheckCircle,
  AlertCircle
} from 'lucide-react';
import { EnvironmentSelectionStep } from './wizard-steps/EnvironmentSelectionStep';
import { ConnectionMethodStep } from './wizard-steps/ConnectionMethodStep';
import { ConnectionDetailsStep } from './wizard-steps/ConnectionDetailsStep';
import { TestConnectionsStep } from './wizard-steps/TestConnectionsStep';
import { ScanningConfigStep } from './wizard-steps/ScanningConfigStep';
import { ReviewConfirmationStep } from './wizard-steps/ReviewConfirmationStep';

export interface WizardData {
  environments: string[];
  useCases: string[];
  connectionMethods: Record<string, string>;
  connectionDetails: Record<string, any>;
  scanningConfig: {
    schedule: string;
    stigRuleSets: string[];
    frameworks: string[];
    notifications: boolean;
  };
}

interface DataSourcesWizardProps {
  open: boolean;
  onClose: () => void;
  organizationId: string;
}

const WIZARD_STEPS = [
  { id: 'environment', title: 'Select Environments', description: 'Choose infrastructure types to connect' },
  { id: 'connection', title: 'Connection Methods', description: 'Configure how to connect to your systems' },
  { id: 'details', title: 'Connection Details', description: 'Enter credentials and connection information' },
  { id: 'test', title: 'Test Connections', description: 'Verify connectivity and discover assets' },
  { id: 'config', title: 'Scanning Configuration', description: 'Set up compliance scanning parameters' },
  { id: 'review', title: 'Review & Deploy', description: 'Confirm settings and start data collection' }
];

export const DataSourcesWizard: React.FC<DataSourcesWizardProps> = ({
  open,
  onClose,
  organizationId
}) => {
  const [currentStep, setCurrentStep] = useState(0);
  const [wizardData, setWizardData] = useState<WizardData>({
    environments: [],
    useCases: [],
    connectionMethods: {},
    connectionDetails: {},
    scanningConfig: {
      schedule: 'daily',
      stigRuleSets: [],
      frameworks: [],
      notifications: true
    }
  });
  const [isLoading, setIsLoading] = useState(false);
  const { toast } = useToast();

  const progress = ((currentStep + 1) / WIZARD_STEPS.length) * 100;

  const updateWizardData = (updates: Partial<WizardData>) => {
    setWizardData(prev => ({ ...prev, ...updates }));
  };

  const canProceed = () => {
    switch (currentStep) {
      case 0: return wizardData.environments.length > 0;
      case 1: return Object.keys(wizardData.connectionMethods).length > 0;
      case 2: return Object.keys(wizardData.connectionDetails).length > 0;
      case 3: return true; // Test results handled internally
      case 4: return wizardData.scanningConfig.stigRuleSets.length > 0;
      case 5: return true;
      default: return false;
    }
  };

  const handleNext = () => {
    if (currentStep < WIZARD_STEPS.length - 1) {
      setCurrentStep(currentStep + 1);
    }
  };

  const handlePrevious = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const handleFinish = async () => {
    setIsLoading(true);
    try {
      // TODO: Replace with actual STIG-Connector integration
      // await STIGConnectorService.configureDataSources(organizationId, wizardData);
      
      // TODO: Store configuration in Supabase
      // await supabase.from('data_source_configurations').insert({
      //   organization_id: organizationId,
      //   environments: wizardData.environments,
      //   use_cases: wizardData.useCases,
      //   connection_methods: wizardData.connectionMethods,
      //   connection_details: wizardData.connectionDetails,
      //   scanning_config: wizardData.scanningConfig
      // });
      
      // Simulate deployment with GitHub/Supabase integration
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      toast({
        title: "Data Sources Connected Successfully",
        description: `Connected ${wizardData.environments.length} environment types across ${wizardData.useCases.length} use cases. STIG-Connector is now active.`,
      });
      
      onClose();
    } catch (error) {
      toast({
        title: "Deployment Failed", 
        description: "Failed to configure data sources. Please try again.",
        variant: "destructive"
      });
    } finally {
      setIsLoading(false);
    }
  };

  const renderCurrentStep = () => {
    switch (currentStep) {
      case 0:
        return (
          <EnvironmentSelectionStep
            data={wizardData}
            onUpdate={updateWizardData}
          />
        );
      case 1:
        return (
          <ConnectionMethodStep
            data={wizardData}
            onUpdate={updateWizardData}
          />
        );
      case 2:
        return (
          <ConnectionDetailsStep
            data={wizardData}
            onUpdate={updateWizardData}
          />
        );
      case 3:
        return (
          <TestConnectionsStep
            data={wizardData}
            onUpdate={updateWizardData}
          />
        );
      case 4:
        return (
          <ScanningConfigStep
            data={wizardData}
            onUpdate={updateWizardData}
          />
        );
      case 5:
        return (
          <ReviewConfirmationStep
            data={wizardData}
            organizationId={organizationId}
          />
        );
      default:
        return null;
    }
  };

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-hidden">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <CheckCircle className="h-5 w-5 text-primary" />
            Connect Data Sources - {WIZARD_STEPS[currentStep].title}
          </DialogTitle>
          <DialogDescription>
            {WIZARD_STEPS[currentStep].description}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6">
          {/* Progress Bar */}
          <div className="space-y-2">
            <div className="flex justify-between text-sm text-muted-foreground">
              <span>Step {currentStep + 1} of {WIZARD_STEPS.length}</span>
              <span>{Math.round(progress)}% complete</span>
            </div>
            <Progress value={progress} className="h-2" />
          </div>

          {/* Step Content */}
          <div className="h-[500px] overflow-y-auto border rounded-md bg-background/50" style={{
            scrollbarWidth: 'thin',
            scrollbarColor: 'hsl(var(--muted-foreground)) transparent'
          }}>
            <div className="p-1">
              {renderCurrentStep()}
            </div>
          </div>

          {/* Navigation */}
          <div className="flex justify-between pt-4 border-t">
            <Button
              variant="outline"
              onClick={handlePrevious}
              disabled={currentStep === 0}
            >
              <ChevronLeft className="h-4 w-4 mr-2" />
              Previous
            </Button>

            {currentStep === WIZARD_STEPS.length - 1 ? (
              <Button
                onClick={handleFinish}
                disabled={isLoading}
                className="min-w-[120px]"
              >
                {isLoading ? (
                  <div className="flex items-center gap-2">
                    <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
                    Deploying...
                  </div>
                ) : (
                  <>
                    <CheckCircle className="h-4 w-4 mr-2" />
                    Deploy
                  </>
                )}
              </Button>
            ) : (
              <Button
                onClick={handleNext}
                disabled={!canProceed()}
              >
                Next
                <ChevronRight className="h-4 w-4 ml-2" />
              </Button>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};