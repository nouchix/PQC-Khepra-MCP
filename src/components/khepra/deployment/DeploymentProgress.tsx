import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { ScrollArea } from '@/components/ui/scroll-area';
import { 
  CheckCircle, 
  Loader2, 
  AlertTriangle, 
  XCircle,
  Play,
  Pause,
  RotateCcw,
  Shield,
  Zap,
  Eye,
  Settings
} from 'lucide-react';
import { AdinkraSymbolDisplay } from '../AdinkraSymbolDisplay';

interface DeploymentStep {
  id: string;
  name: string;
  description: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
  duration?: number;
  cultural_symbol?: string;
  details?: string[];
  error?: string;
}

interface DeploymentProgressProps {
  data?: any;
  onDataChange?: (data: any) => void;
  isActive?: boolean;
}

export const DeploymentProgress: React.FC<DeploymentProgressProps> = ({
  data,
  onDataChange,
  isActive
}) => {
  const [isDeploying, setIsDeploying] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [overallProgress, setOverallProgress] = useState(0);
  const [deploymentSteps, setDeploymentSteps] = useState<DeploymentStep[]>([
    {
      id: 'initialization',
      name: 'KHEPRA Protocol Initialization',
      description: 'Setting up Adinkra algebraic foundations',
      status: 'pending',
      progress: 0,
      cultural_symbol: 'Sankofa'
    },
    {
      id: 'agent_registry',
      name: 'Trusted Agent Registry Setup',
      description: 'Establishing decentralized identity framework',
      status: 'pending',
      progress: 0,
      cultural_symbol: 'Gye_Nyame'
    },
    {
      id: 'cryptographic_layer',
      name: 'Quantum-Safe Cryptography',
      description: 'Deploying lattice-based encryption with Adinkra keys',
      status: 'pending',
      progress: 0,
      cultural_symbol: 'Eban'
    },
    {
      id: 'dag_consensus',
      name: 'DAG Consensus Network',
      description: 'Initializing supersymmetric agent interactions',
      status: 'pending',
      progress: 0,
      cultural_symbol: 'Nkyinkyim'
    },
    {
      id: 'osint_integration',
      name: 'OSINT Feed Integration',
      description: 'Connecting cultural threat intelligence sources',
      status: 'pending',
      progress: 0,
      cultural_symbol: 'Adwo'
    },
    {
      id: 'monitoring_deployment',
      name: 'Monitoring Infrastructure',
      description: 'Deploying real-time security visualization',
      status: 'pending',
      progress: 0,
      cultural_symbol: 'Fawohodie'
    },
    {
      id: 'validation',
      name: 'Protocol Validation',
      description: 'Verifying cultural alignment and security posture',
      status: 'pending',
      progress: 0,
      cultural_symbol: 'Dwennimmen'
    }
  ]);

  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const [deploymentLogs, setDeploymentLogs] = useState<string[]>([]);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'running': return <Loader2 className="h-4 w-4 text-primary animate-spin" />;
      case 'failed': return <XCircle className="h-4 w-4 text-red-500" />;
      default: return <div className="h-4 w-4 rounded-full border-2 border-muted" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'text-green-500';
      case 'running': return 'text-primary';
      case 'failed': return 'text-red-500';
      default: return 'text-muted-foreground';
    }
  };

  const addLog = (message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setDeploymentLogs(prev => [...prev, `[${timestamp}] ${message}`]);
  };

  const startDeployment = async () => {
    setIsDeploying(true);
    setIsPaused(false);
    
    addLog('Starting KHEPRA Protocol deployment...');
    addLog('Ceremonial deployment sequence initiated');

    for (let stepIndex = 0; stepIndex < deploymentSteps.length; stepIndex++) {
      if (isPaused) break;
      
      setCurrentStepIndex(stepIndex);
      
      // Update step status to running
      setDeploymentSteps(prev => prev.map((step, index) => 
        index === stepIndex 
          ? { ...step, status: 'running' }
          : step
      ));

      const currentStep = deploymentSteps[stepIndex];
      addLog(`Starting: ${currentStep.name}`);
      
      // Simulate step execution with cultural elements
      const stepDetails = getStepDetails(currentStep.id);
      for (let i = 0; i < stepDetails.length; i++) {
        if (isPaused) break;
        
        addLog(`  ${stepDetails[i]}`);
        
        // Update step progress
        const stepProgress = ((i + 1) / stepDetails.length) * 100;
        setDeploymentSteps(prev => prev.map((step, index) => 
          index === stepIndex 
            ? { ...step, progress: stepProgress }
            : step
        ));
        
        // Update overall progress
        const overallProg = ((stepIndex + (i + 1) / stepDetails.length) / deploymentSteps.length) * 100;
        setOverallProgress(overallProg);
        
        await new Promise(resolve => setTimeout(resolve, 800));
      }

      // Mark step as completed
      setDeploymentSteps(prev => prev.map((step, index) => 
        index === stepIndex 
          ? { ...step, status: 'completed', progress: 100 }
          : step
      ));
      
      addLog(`✓ Completed: ${currentStep.name}`);
      addLog(`  Cultural symbol ${currentStep.cultural_symbol} activated`);
    }

    if (!isPaused) {
      addLog('🎉 KHEPRA Protocol deployment completed successfully!');
      addLog('All cultural validations passed');
      addLog('Your infrastructure is now protected by ancient wisdom and quantum cryptography');
      
      setIsDeploying(false);
      setOverallProgress(100);
      
      onDataChange?.({
        deployment_completed: true,
        deployment_time: Date.now(),
        steps_completed: deploymentSteps.length,
        cultural_alignment: 'verified'
      });
    }
  };

  const getStepDetails = (stepId: string): string[] => {
    switch (stepId) {
      case 'initialization':
        return [
          'Loading Adinkra symbol matrices...',
          'Establishing D8 symmetry groups...',
          'Initializing cultural fingerprint generation...',
          'Setting up symbolic transformation engine...'
        ];
      case 'agent_registry':
        return [
          'Creating decentralized identity framework...',
          'Generating DID certificates...',
          'Establishing trust scoring mechanisms...',
          'Validating agent authenticity protocols...'
        ];
      case 'cryptographic_layer':
        return [
          'Deploying post-quantum lattice structures...',
          'Generating Adinkra-derived encryption keys...',
          'Establishing quantum-safe key exchange...',
          'Validating cryptographic integrity...'
        ];
      case 'dag_consensus':
        return [
          'Initializing DAG network topology...',
          'Setting up supersymmetric validation nodes...',
          'Establishing agent consensus protocols...',
          'Testing anti-action traceability...'
        ];
      case 'osint_integration':
        return [
          'Connecting to MITRE ATT&CK framework...',
          'Integrating CVSS vulnerability feeds...',
          'Applying cultural threat taxonomy...',
          'Validating OSINT source authenticity...'
        ];
      case 'monitoring_deployment':
        return [
          'Deploying real-time dashboards...',
          'Setting up Adinkra status indicators...',
          'Configuring cultural alert systems...',
          'Testing visualization components...'
        ];
      case 'validation':
        return [
          'Running cultural alignment tests...',
          'Validating security posture...',
          'Testing agent communication paths...',
          'Finalizing protocol activation...'
        ];
      default:
        return ['Processing...'];
    }
  };

  const pauseDeployment = () => {
    setIsPaused(true);
    addLog('⏸ Deployment paused by user');
  };

  const resumeDeployment = () => {
    setIsPaused(false);
    addLog('▶ Deployment resumed');
    // Continue from current step
    startDeployment();
  };

  const restartDeployment = () => {
    setIsDeploying(false);
    setIsPaused(false);
    setOverallProgress(0);
    setCurrentStepIndex(0);
    setDeploymentLogs([]);
    setDeploymentSteps(prev => prev.map(step => ({
      ...step,
      status: 'pending',
      progress: 0
    })));
    addLog('🔄 Deployment reset');
  };

  useEffect(() => {
    if (isActive && !data?.deployment_completed && !isDeploying) {
      // Auto-start deployment when component becomes active
      setTimeout(() => startDeployment(), 1000);
    }
  }, [isActive]);

  return (
    <div className="space-y-6">
      {/* Overall Progress */}
      <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center space-x-2">
              <Shield className="h-5 w-5 text-primary" />
              <span>KHEPRA Protocol Deployment</span>
            </CardTitle>
            <div className="flex space-x-2">
              {!isDeploying ? (
                <Button size="sm" onClick={startDeployment} className="btn-cyber">
                  <Play className="h-4 w-4 mr-2" />
                  Start Deployment
                </Button>
              ) : isPaused ? (
                <Button size="sm" onClick={resumeDeployment}>
                  <Play className="h-4 w-4 mr-2" />
                  Resume
                </Button>
              ) : (
                <Button size="sm" variant="outline" onClick={pauseDeployment}>
                  <Pause className="h-4 w-4 mr-2" />
                  Pause
                </Button>
              )}
              <Button size="sm" variant="outline" onClick={restartDeployment}>
                <RotateCcw className="h-4 w-4 mr-2" />
                Restart
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span>Overall Progress</span>
              <span>{Math.round(overallProgress)}%</span>
            </div>
            <Progress value={overallProgress} className="h-3" />
            <div className="text-center text-sm text-muted-foreground">
              {isDeploying ? (
                isPaused ? 'Deployment Paused' : `Step ${currentStepIndex + 1} of ${deploymentSteps.length}`
              ) : overallProgress === 100 ? (
                'Deployment Complete 🎉'
              ) : (
                'Ready to Deploy'
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Deployment Steps */}
        <Card className="border-border">
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Zap className="h-5 w-5" />
              <span>Deployment Steps</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-64">
              <div className="space-y-3">
                {deploymentSteps.map((step, index) => (
                  <div
                    key={step.id}
                    className={`p-3 rounded-lg border transition-all ${
                      step.status === 'running' 
                        ? 'border-primary bg-primary/5' 
                        : step.status === 'completed'
                        ? 'border-green-500/20 bg-green-500/5'
                        : 'border-border'
                    }`}
                  >
                    <div className="flex items-start space-x-3">
                      <div className="mt-1">
                        {getStatusIcon(step.status)}
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <h4 className={`font-medium ${getStatusColor(step.status)}`}>
                            {step.name}
                          </h4>
                          {step.cultural_symbol && (
                            <div className="w-6 h-6">
                              <AdinkraSymbolDisplay 
                                symbolName={step.cultural_symbol} 
                                size="small" 
                                showMatrix={false}
                              />
                            </div>
                          )}
                        </div>
                        <p className="text-sm text-muted-foreground mt-1">
                          {step.description}
                        </p>
                        {step.status === 'running' && (
                          <div className="mt-2">
                            <Progress value={step.progress} className="h-1" />
                          </div>
                        )}
                        {step.error && (
                          <div className="mt-2 text-xs text-red-400">
                            Error: {step.error}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>

        {/* Deployment Logs */}
        <Card className="border-border">
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Eye className="h-5 w-5" />
              <span>Deployment Logs</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-64">
              <div className="space-y-1 font-mono text-xs">
                {deploymentLogs.map((log, index) => (
                  <div 
                    key={index} 
                    className={`${
                      log.includes('✓') ? 'text-green-400' :
                      log.includes('⏸') || log.includes('▶') || log.includes('🔄') ? 'text-yellow-400' :
                      log.includes('🎉') ? 'text-primary' :
                      'text-muted-foreground'
                    }`}
                  >
                    {log}
                  </div>
                ))}
                {deploymentLogs.length === 0 && (
                  <div className="text-muted-foreground">
                    Deployment logs will appear here...
                  </div>
                )}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      </div>

      {/* Cultural Wisdom */}
      {isDeploying && (
        <Card className="border-purple-500/20 bg-purple-500/5">
          <CardHeader>
            <CardTitle className="text-purple-400">Cultural Wisdom</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm italic">
              "The strength of the fortress (Eban) lies not just in its walls, but in the wisdom of those who built it. 
              As KHEPRA deploys, we weave ancient knowledge into modern protection, creating security that adapts and grows."
            </p>
            <div className="mt-3 text-xs text-muted-foreground">
              — Adinkra Proverb on Cybersecurity
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};