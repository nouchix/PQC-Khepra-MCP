import { useState, useEffect, createElement } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';
import { 
  Sparkles, 
  Shield, 
  Cloud, 
  Server, 
  Globe, 
  ChevronLeft, 
  ChevronRight,
  CheckCircle,
  AlertTriangle,
  Loader2,
  Brain,
  Eye,
  Zap
} from 'lucide-react';
import { AdinkraSymbolDisplay } from '../AdinkraSymbolDisplay';
import { EnvironmentDetection } from './EnvironmentDetection';
import { DeploymentVectorSelector } from './DeploymentVectorSelector';
import { DeploymentProgress } from './DeploymentProgress';
import { PapyrusAIAssistant } from './PapyrusAIAssistant';

interface DeploymentStep {
  id: string;
  title: string;
  description: string;
  symbol: string;
  component: React.ComponentType<any>;
}

const deploymentSteps: DeploymentStep[] = [
  {
    id: 'welcome',
    title: 'Welcome to KHEPRA Protocol',
    description: 'Begin your journey into Afrofuturist cybersecurity',
    symbol: 'Sankofa',
    component: WelcomeStep
  },
  {
    id: 'detection',
    title: 'Environment Discovery',
    description: 'AI-powered infrastructure scanning and analysis',
    symbol: 'Gye_Nyame',
    component: EnvironmentDetection
  },
  {
    id: 'selection',
    title: 'Deployment Vectors',
    description: 'Choose your deployment strategy and security profile',
    symbol: 'Eban',
    component: DeploymentVectorSelector
  },
  {
    id: 'configuration',
    title: 'Security Configuration',
    description: 'Configure KHEPRA protocol settings and cultural context',
    symbol: 'Fawohodie',
    component: ConfigurationStep
  },
  {
    id: 'deployment',
    title: 'Protocol Deployment',
    description: 'Execute deployment with real-time monitoring',
    symbol: 'Nkyinkyim',
    component: DeploymentProgress
  },
  {
    id: 'verification',
    title: 'Security Verification',
    description: 'Validate deployment and establish monitoring',
    symbol: 'Adwo',
    component: VerificationStep
  }
];

export interface DeploymentWizardProps {
  onComplete?: (deploymentData?: any) => void;
  onCancel?: () => void;
  discoveredAssets?: any[];
}

export const DeploymentWizard: React.FC<DeploymentWizardProps> = ({ 
  onComplete, 
  onCancel,
  discoveredAssets = []
}) => {
  const [currentStep, setCurrentStep] = useState(0);
  const [isDeploying, setIsDeploying] = useState(false);
  const [deploymentData, setDeploymentData] = useState<any>({});
  const [showPapyrus, setShowPapyrus] = useState(true);

  const progress = ((currentStep + 1) / deploymentSteps.length) * 100;
  const currentStepData = deploymentSteps[currentStep];

  const handleNext = () => {
    if (currentStep < deploymentSteps.length - 1) {
      setCurrentStep(currentStep + 1);
    } else {
      // On completion, pass the selected assets back
      onComplete?.({
        selectedAssets: deploymentData.selectedAssets || discoveredAssets.map(a => a.id),
        ...deploymentData
      });
    }
  };

  const handlePrevious = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const handleStepData = (data: any) => {
    setDeploymentData(prev => ({ ...prev, [currentStepData.id]: data }));
  };

  return (
    <div className="fixed inset-0 bg-background/95 backdrop-blur-sm z-50 flex items-center justify-center p-2 sm:p-4">
      <div className="w-full h-full sm:h-auto max-w-7xl sm:max-h-[95vh] flex flex-col sm:flex-row gap-2 sm:gap-4">
        {/* Papyrus AI Assistant - Hidden on mobile */}
        {showPapyrus && (
          <div className="hidden lg:block w-80 flex-shrink-0">
            <PapyrusAIAssistant 
              currentStep={currentStepData}
              deploymentData={deploymentData}
              onClose={() => setShowPapyrus(false)}
            />
          </div>
        )}

        {/* Main Wizard */}
        <Card className="flex-1 flex flex-col h-full card-cyber">
          {/* Wizard Header - Responsive */}
          <CardHeader className="border-b border-primary/20 bg-gradient-to-r from-primary/5 to-purple-500/5 flex-shrink-0">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="flex items-center space-x-4">
                <AdinkraSymbolDisplay 
                  symbolName={currentStepData.symbol} 
                  size="small" 
                  showMatrix={false} 
                />
                <div>
                  <CardTitle className="text-lg sm:text-xl text-primary">
                    KHEPRA Deployment Wizard
                  </CardTitle>
                  <p className="text-xs sm:text-sm text-muted-foreground">
                    Step {currentStep + 1} of {deploymentSteps.length}: {currentStepData.title}
                  </p>
                </div>
              </div>
              <div className="flex items-center space-x-2 self-end sm:self-auto">
                {!showPapyrus && (
                  <Button 
                    size="sm" 
                    variant="outline"
                    onClick={() => setShowPapyrus(true)}
                    className="hidden lg:flex"
                  >
                    <Brain className="h-4 w-4 mr-2" />
                    Show Papyrus
                  </Button>
                )}
                <Button size="sm" variant="outline" onClick={onCancel}>
                  Cancel
                </Button>
              </div>
            </div>
            
            {/* Progress Bar */}
            <div className="space-y-2 mt-4">
              <div className="flex justify-between text-xs text-muted-foreground">
                <span>Progress</span>
                <span>{Math.round(progress)}%</span>
              </div>
              <Progress value={progress} className="h-2" />
            </div>

            {/* Step Indicators - Responsive */}
            <div className="grid grid-cols-3 sm:flex sm:justify-between gap-2 mt-4">
              {deploymentSteps.map((step, index) => (
                <div 
                  key={step.id}
                  className={`flex flex-col items-center space-y-1 text-center ${
                    index <= currentStep ? 'text-primary' : 'text-muted-foreground'
                  }`}
                >
                  <div className={`w-6 h-6 sm:w-8 sm:h-8 rounded-full border-2 flex items-center justify-center ${
                    index < currentStep 
                      ? 'bg-primary border-primary text-primary-foreground' 
                      : index === currentStep
                      ? 'border-primary bg-primary/10'
                      : 'border-muted'
                  }`}>
                    {index < currentStep ? (
                      <CheckCircle className="h-3 w-3 sm:h-4 sm:w-4" />
                    ) : (
                      <span className="text-xs font-medium">{index + 1}</span>
                    )}
                  </div>
                  <span className="text-xs text-center">{step.title.split(' ')[0]}</span>
                </div>
              ))}
            </div>
          </CardHeader>

          {/* Step Content - Scrollable */}
          <div className="flex-1 flex flex-col min-h-0">
            <ScrollArea className="flex-1">
              <CardContent className="p-4 sm:p-6">
                <div className="mb-6">
                  <h2 className="text-xl sm:text-2xl font-bold mb-2">{currentStepData.title}</h2>
                  <p className="text-sm sm:text-base text-muted-foreground">{currentStepData.description}</p>
                </div>

                <div className="space-y-4">
                  {createElement(currentStepData.component, {
                    data: deploymentData[currentStepData.id],
                    onDataChange: handleStepData,
                    isActive: true
                  })}
                </div>
              </CardContent>
            </ScrollArea>

            {/* Navigation - Always visible at bottom */}
            <div className="flex-shrink-0 border-t border-border bg-card">
              <div className="flex flex-col sm:flex-row justify-between items-center gap-4 p-4 sm:p-6">
                <Button
                  variant="outline"
                  onClick={handlePrevious}
                  disabled={currentStep === 0}
                  className="w-full sm:w-auto order-2 sm:order-1"
                >
                  <ChevronLeft className="h-4 w-4 mr-2" />
                  Previous
                </Button>

                <div className="flex items-center space-x-2 order-1 sm:order-2">
                  <Badge variant="outline" className="bg-primary/10 border-primary/30 text-xs">
                    Ceremonial Deployment Active
                  </Badge>
                </div>

                <Button
                  onClick={handleNext}
                  disabled={isDeploying}
                  className="btn-cyber w-full sm:w-auto order-3"
                >
                  {isDeploying ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      Deploying...
                    </>
                  ) : currentStep === deploymentSteps.length - 1 ? (
                    <>
                      <CheckCircle className="h-4 w-4 mr-2" />
                      Complete Deployment
                    </>
                  ) : (
                    <>
                      Next
                      <ChevronRight className="h-4 w-4 ml-2" />
                    </>
                  )}
                </Button>
              </div>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
};

// Individual Step Components
function WelcomeStep({ onDataChange }: any) {
  useEffect(() => {
    onDataChange({ ready: true });
  }, [onDataChange]);

  return (
    <div className="space-y-6">
      <div className="text-center">
        <div className="w-32 h-32 mx-auto mb-6">
          <AdinkraSymbolDisplay 
            symbolName="Sankofa" 
            size="large" 
            showMatrix={false} 
            className="animate-cultural-pulse"
          />
        </div>
        <h3 className="text-xl font-bold mb-4">
          Welcome to the KHEPRA Protocol Deployment
        </h3>
        <p className="text-muted-foreground max-w-2xl mx-auto">
          You are about to deploy a revolutionary security framework that combines ancient African wisdom 
          with cutting-edge cryptographic technology. The KHEPRA Protocol will protect your infrastructure 
          using Adinkra-encoded security policies and quantum-resilient algorithms.
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-8">
        <Card className="border-primary/20 bg-primary/5">
          <CardContent className="p-4 text-center">
            <Shield className="h-6 w-6 sm:h-8 sm:w-8 mx-auto mb-2 text-primary" />
            <h4 className="font-medium text-sm sm:text-base">Quantum-Safe Security</h4>
            <p className="text-xs text-muted-foreground mt-1">
              Post-quantum cryptography with Adinkra encoding
            </p>
          </CardContent>
        </Card>

        <Card className="border-purple-500/20 bg-purple-500/5">
          <CardContent className="p-4 text-center">
            <Brain className="h-6 w-6 sm:h-8 sm:w-8 mx-auto mb-2 text-purple-400" />
            <h4 className="font-medium text-sm sm:text-base">AI-Powered Defense</h4>
            <p className="text-xs text-muted-foreground mt-1">
              Autonomous agents with cultural threat intelligence
            </p>
          </CardContent>
        </Card>

        <Card className="border-amber-500/20 bg-amber-500/5">
          <CardContent className="p-4 text-center">
            <Sparkles className="h-6 w-6 sm:h-8 sm:w-8 mx-auto mb-2 text-amber-400" />
            <h4 className="font-medium text-sm sm:text-base">Cultural Resilience</h4>
            <p className="text-xs text-muted-foreground mt-1">
              Symbolic logic rooted in African mathematical traditions
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function ConfigurationStep({ data, onDataChange }: any) {
  const [config, setConfig] = useState(data || {
    securityProfile: 'fortress',
    culturalContext: 'west_african',
    encryptionLevel: 'quantum_safe',
    agentBehavior: 'protective'
  });

  useEffect(() => {
    onDataChange(config);
  }, [config, onDataChange]);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="border-primary/20">
          <CardHeader>
            <CardTitle className="text-base sm:text-lg">Security Profile</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {['fortress', 'guardian', 'explorer'].map(profile => (
              <label key={profile} className="flex items-start space-x-3 cursor-pointer">
                <input
                  type="radio"
                  name="securityProfile"
                  value={profile}
                  checked={config.securityProfile === profile}
                  onChange={(e) => setConfig(prev => ({ ...prev, securityProfile: e.target.value }))}
                  className="text-primary mt-1"
                />
                <div className="flex-1">
                  <div className="font-medium capitalize text-sm sm:text-base">{profile} Mode</div>
                  <div className="text-xs text-muted-foreground mt-1">
                    {profile === 'fortress' && 'Maximum security, minimal access'}
                    {profile === 'guardian' && 'Balanced security and accessibility'}
                    {profile === 'explorer' && 'Adaptive security for dynamic environments'}
                  </div>
                </div>
              </label>
            ))}
          </CardContent>
        </Card>

        <Card className="border-purple-500/20">
          <CardHeader>
            <CardTitle className="text-base sm:text-lg">Cultural Context</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {['west_african', 'east_african', 'southern_african', 'pan_african'].map(context => (
              <label key={context} className="flex items-center space-x-3 cursor-pointer">
                <input
                  type="radio"
                  name="culturalContext"
                  value={context}
                  checked={config.culturalContext === context}
                  onChange={(e) => setConfig(prev => ({ ...prev, culturalContext: e.target.value }))}
                  className="text-purple-400"
                />
                <div className="font-medium text-sm sm:text-base">
                  {context.split('_').map(word => 
                    word.charAt(0).toUpperCase() + word.slice(1)
                  ).join(' ')}
                </div>
              </label>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function VerificationStep({ data, onDataChange }: any) {
  const [verificationStatus, setVerificationStatus] = useState({
    agentRegistry: false,
    cryptographicValidation: false,
    culturalAlignment: false,
    networkSecurity: false
  });

  useEffect(() => {
    // Simulate verification process
    const verifySteps = async () => {
      const steps = Object.keys(verificationStatus);
      for (let i = 0; i < steps.length; i++) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        setVerificationStatus(prev => ({
          ...prev,
          [steps[i]]: true
        }));
      }
      onDataChange({ verified: true });
    };
    verifySteps();
  }, [onDataChange]);

  return (
    <div className="space-y-6">
      <div className="text-center">
        <h3 className="text-xl font-bold mb-4">Verifying KHEPRA Protocol Deployment</h3>
        <p className="text-muted-foreground">
          Performing final security validation and cultural alignment checks
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {Object.entries(verificationStatus).map(([key, status]) => (
          <div
            key={key}
            className={`flex items-center space-x-3 p-4 rounded-lg border ${
              status ? 'border-green-500/20 bg-green-500/5' : 'border-border'
            }`}
          >
            {status ? (
              <CheckCircle className="h-5 w-5 text-green-500 flex-shrink-0" />
            ) : (
              <Loader2 className="h-5 w-5 animate-spin text-muted-foreground flex-shrink-0" />
            )}
            <div className="flex-1">
              <div className="font-medium text-sm sm:text-base">
                {key.split(/(?=[A-Z])/).join(' ')}
              </div>
              <div className="text-xs text-muted-foreground">
                {status ? 'Verified' : 'Verifying...'}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}