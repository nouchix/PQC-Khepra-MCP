import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { ScrollArea } from '@/components/ui/scroll-area';
import { 
  PlayCircle, 
  PauseCircle, 
  RotateCcw, 
  CheckCircle, 
  XCircle,
  AlertTriangle,
  Clock,
  Shield,
  Zap,
  Network,
  Database,
  Cpu,
  HardDrive
} from 'lucide-react';
import { toast } from 'sonner';

interface DeploymentTask {
  id: string;
  name: string;
  description: string;
  category: 'infrastructure' | 'security' | 'validation' | 'monitoring';
  priority: 'high' | 'medium' | 'low';
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
  progress: number;
  duration: number; // in seconds
  dependencies: string[];
  cultural_symbol: string;
  artifacts?: string[];
  error_message?: string;
}

interface DeploymentPlan {
  id: string;
  name: string;
  vector_type: string;
  total_tasks: number;
  estimated_duration: number;
  tasks: DeploymentTask[];
}

interface DeploymentOrchestratorProps {
  deploymentVector: any;
  selectedAssets: any[];
  configuration: any;
  onComplete?: (result: any) => void;
  onError?: (error: any) => void;
}

export const DeploymentOrchestrator: React.FC<DeploymentOrchestratorProps> = ({
  deploymentVector,
  selectedAssets,
  configuration,
  onComplete,
  onError
}) => {
  const [deploymentPlan, setDeploymentPlan] = useState<DeploymentPlan | null>(null);
  const [isExecuting, setIsExecuting] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [currentTaskIndex, setCurrentTaskIndex] = useState(0);
  const [overallProgress, setOverallProgress] = useState(0);
  const [executionLogs, setExecutionLogs] = useState<string[]>([]);
  const [startTime, setStartTime] = useState<Date | null>(null);

  // Generate deployment plan based on vector and assets
  useEffect(() => {
    if (deploymentVector && selectedAssets.length > 0) {
      const plan = generateDeploymentPlan(deploymentVector, selectedAssets, configuration);
      setDeploymentPlan(plan);
    }
  }, [deploymentVector, selectedAssets, configuration]);

  const generateDeploymentPlan = (vector: any, assets: any[], config: any): DeploymentPlan => {
    const baseTasks: DeploymentTask[] = [
      {
        id: 'pre_flight',
        name: 'Pre-flight Validation',
        description: 'Validate deployment environment and prerequisites',
        category: 'validation',
        priority: 'high',
        status: 'pending',
        progress: 0,
        duration: 30,
        dependencies: [],
        cultural_symbol: 'Sankofa'
      },
      {
        id: 'agent_registry_init',
        name: 'Initialize Trusted Agent Registry',
        description: 'Set up decentralized identity framework and DID certificates',
        category: 'infrastructure',
        priority: 'high',
        status: 'pending',
        progress: 0,
        duration: 45,
        dependencies: ['pre_flight'],
        cultural_symbol: 'Gye_Nyame'
      },
      {
        id: 'crypto_layer',
        name: 'Deploy Quantum-Safe Cryptography',
        description: 'Initialize lattice-based encryption with Adinkra key generation',
        category: 'security',
        priority: 'high',
        status: 'pending',
        progress: 0,
        duration: 60,
        dependencies: ['agent_registry_init'],
        cultural_symbol: 'Eban'
      },
      {
        id: 'dag_network',
        name: 'Establish DAG Consensus Network',
        description: 'Deploy supersymmetric agent interaction protocols',
        category: 'infrastructure',
        priority: 'high',
        status: 'pending',
        progress: 0,
        duration: 75,
        dependencies: ['crypto_layer'],
        cultural_symbol: 'Nkyinkyim'
      },
      {
        id: 'asset_deployment',
        name: 'Deploy Asset Protection',
        description: `Deploy KHEPRA agents to ${assets.length} selected assets`,
        category: 'security',
        priority: 'high',
        status: 'pending',
        progress: 0,
        duration: assets.length * 20,
        dependencies: ['dag_network'],
        cultural_symbol: 'Adwo'
      },
      {
        id: 'osint_integration',
        name: 'Integrate OSINT Feeds',
        description: 'Connect cultural threat intelligence and vulnerability feeds',
        category: 'monitoring',
        priority: 'medium',
        status: 'pending',
        progress: 0,
        duration: 40,
        dependencies: ['asset_deployment'],
        cultural_symbol: 'Fawohodie'
      },
      {
        id: 'monitoring_setup',
        name: 'Deploy Monitoring Infrastructure',
        description: 'Initialize real-time dashboards and alert systems',
        category: 'monitoring',
        priority: 'medium',
        status: 'pending',
        progress: 0,
        duration: 35,
        dependencies: ['osint_integration'],
        cultural_symbol: 'Dwennimmen'
      },
      {
        id: 'final_validation',
        name: 'Final Security Validation',
        description: 'Comprehensive security posture assessment and cultural alignment',
        category: 'validation',
        priority: 'high',
        status: 'pending',
        progress: 0,
        duration: 50,
        dependencies: ['monitoring_setup'],
        cultural_symbol: 'Aya'
      }
    ];

    // Add vector-specific tasks
    const vectorSpecificTasks = getVectorSpecificTasks(vector.id);
    const allTasks = [...baseTasks, ...vectorSpecificTasks];

    const totalDuration = allTasks.reduce((sum, task) => sum + task.duration, 0);

    return {
      id: `deployment-${Date.now()}`,
      name: `KHEPRA ${vector.name} Deployment`,
      vector_type: vector.id,
      total_tasks: allTasks.length,
      estimated_duration: totalDuration,
      tasks: allTasks
    };
  };

  const getVectorSpecificTasks = (vectorId: string): DeploymentTask[] => {
    switch (vectorId) {
      case 'cloud_native':
        return [
          {
            id: 'k8s_operator',
            name: 'Deploy Kubernetes Operator',
            description: 'Install KHEPRA Kubernetes operator for container orchestration',
            category: 'infrastructure',
            priority: 'high',
            status: 'pending',
            progress: 0,
            duration: 90,
            dependencies: ['dag_network'],
            cultural_symbol: 'Nkyinkyim'
          }
        ];
      case 'airgapped':
        return [
          {
            id: 'offline_validation',
            name: 'Offline Integrity Validation',
            description: 'Verify package integrity without external connectivity',
            category: 'validation',
            priority: 'high',
            status: 'pending',
            progress: 0,
            duration: 120,
            dependencies: ['pre_flight'],
            cultural_symbol: 'Eban'
          }
        ];
      case 'agent_propagation':
        return [
          {
            id: 'mesh_network',
            name: 'Initialize Agent Mesh Network',
            description: 'Deploy peer-to-peer agent communication mesh',
            category: 'infrastructure',
            priority: 'medium',
            status: 'pending',
            progress: 0,
            duration: 80,
            dependencies: ['dag_network'],
            cultural_symbol: 'Adwo'
          }
        ];
      default:
        return [];
    }
  };

  const addLog = (message: string, type: 'info' | 'success' | 'warning' | 'error' = 'info') => {
    const timestamp = new Date().toLocaleTimeString();
    const prefix = type === 'success' ? '✓' : 
                  type === 'warning' ? '⚠' : 
                  type === 'error' ? '✗' : 'ℹ';
    setExecutionLogs(prev => [...prev, `[${timestamp}] ${prefix} ${message}`]);
  };

  const executeTask = async (task: DeploymentTask): Promise<boolean> => {
    addLog(`Starting: ${task.name}`);
    
    // Update task status
    setDeploymentPlan(prev => prev ? {
      ...prev,
      tasks: prev.tasks.map(t => 
        t.id === task.id ? { ...t, status: 'running' } : t
      )
    } : prev);

    try {
      // Simulate task execution with real-like behavior
      const steps = getTaskSteps(task.id);
      
      for (let i = 0; i < steps.length; i++) {
        if (isPaused) return false;
        
        addLog(`  ${steps[i]}`);
        
        // Update task progress
        const progress = ((i + 1) / steps.length) * 100;
        setDeploymentPlan(prev => prev ? {
          ...prev,
          tasks: prev.tasks.map(t => 
            t.id === task.id ? { ...t, progress } : t
          )
        } : prev);
        
        // Simulate work time
        await new Promise(resolve => setTimeout(resolve, (task.duration * 1000) / steps.length));
      }

      // Mark as completed
      setDeploymentPlan(prev => prev ? {
        ...prev,
        tasks: prev.tasks.map(t => 
          t.id === task.id ? { 
            ...t, 
            status: 'completed', 
            progress: 100,
            artifacts: getTaskArtifacts(task.id)
          } : t
        )
      } : prev);

      addLog(`✓ Completed: ${task.name}`, 'success');
      addLog(`  Cultural symbol ${task.cultural_symbol} activated`, 'info');
      
      return true;
    } catch (error) {
      // Mark as failed
      setDeploymentPlan(prev => prev ? {
        ...prev,
        tasks: prev.tasks.map(t => 
          t.id === task.id ? { 
            ...t, 
            status: 'failed',
            error_message: error instanceof Error ? error.message : 'Unknown error'
          } : t
        )
      } : prev);

      addLog(`✗ Failed: ${task.name} - ${error}`, 'error');
      return false;
    }
  };

  const getTaskSteps = (taskId: string): string[] => {
    switch (taskId) {
      case 'pre_flight':
        return [
          'Checking system requirements...',
          'Validating network connectivity...',
          'Verifying permissions...',
          'Scanning for conflicts...'
        ];
      case 'agent_registry_init':
        return [
          'Generating DID certificates...',
          'Setting up trust scoring...',
          'Initializing agent validation...',
          'Configuring registry endpoints...'
        ];
      case 'crypto_layer':
        return [
          'Deploying lattice structures...',
          'Generating Adinkra keys...',
          'Setting up quantum-safe exchange...',
          'Validating cryptographic integrity...'
        ];
      case 'dag_network':
        return [
          'Initializing DAG topology...',
          'Setting up consensus nodes...',
          'Configuring validation protocols...',
          'Testing anti-action traceability...'
        ];
      case 'asset_deployment':
        return [
          'Analyzing asset configurations...',
          'Deploying protection agents...',
          'Configuring security policies...',
          'Validating agent connectivity...'
        ];
      default:
        return ['Processing...', 'Configuring...', 'Validating...', 'Finalizing...'];
    }
  };

  const getTaskArtifacts = (taskId: string): string[] => {
    switch (taskId) {
      case 'crypto_layer':
        return ['quantum-safe-keys.json', 'adinkra-matrices.bin', 'encryption-config.yaml'];
      case 'agent_registry_init':
        return ['did-certificates.json', 'trust-scores.db', 'registry-config.yaml'];
      case 'dag_network':
        return ['dag-topology.graph', 'consensus-config.json', 'validation-rules.yaml'];
      default:
        return [];
    }
  };

  const startExecution = async () => {
    if (!deploymentPlan) return;

    setIsExecuting(true);
    setIsPaused(false);
    setStartTime(new Date());
    
    addLog('🚀 Starting KHEPRA Protocol deployment...', 'info');
    addLog(`Deployment vector: ${deploymentPlan.vector_type}`, 'info');
    addLog(`Assets to protect: ${selectedAssets.length}`, 'info');

    const sortedTasks = topologicalSort(deploymentPlan.tasks);
    
    for (let i = 0; i < sortedTasks.length; i++) {
      if (isPaused) break;
      
      const task = sortedTasks[i];
      setCurrentTaskIndex(i);
      
      // Check dependencies
      const dependenciesCompleted = task.dependencies.every(depId => 
        deploymentPlan.tasks.find(t => t.id === depId)?.status === 'completed'
      );
      
      if (!dependenciesCompleted) {
        addLog(`⚠ Skipping ${task.name} - dependencies not met`, 'warning');
        continue;
      }
      
      const success = await executeTask(task);
      
      if (!success) {
        addLog('💥 Deployment failed', 'error');
        setIsExecuting(false);
        onError?.({ 
          task: task.id, 
          message: task.error_message || 'Task execution failed' 
        });
        return;
      }
      
      // Update overall progress
      const completedTasks = deploymentPlan.tasks.filter(t => t.status === 'completed').length;
      setOverallProgress((completedTasks / deploymentPlan.tasks.length) * 100);
    }

    if (!isPaused) {
      addLog('🎉 KHEPRA Protocol deployment completed successfully!', 'success');
      addLog('Your infrastructure is now protected by quantum-safe security and ancient wisdom', 'success');
      setIsExecuting(false);
      setOverallProgress(100);
      
      const result = {
        deployment_id: deploymentPlan.id,
        vector_type: deploymentPlan.vector_type,
        completed_at: new Date(),
        duration: startTime ? (Date.now() - startTime.getTime()) / 1000 : 0,
        protected_assets: selectedAssets.length,
        artifacts: deploymentPlan.tasks.flatMap(t => t.artifacts || [])
      };
      
      onComplete?.(result);
      toast.success('KHEPRA Protocol deployed successfully!');
    }
  };

  const topologicalSort = (tasks: DeploymentTask[]): DeploymentTask[] => {
    const result: DeploymentTask[] = [];
    const visited = new Set<string>();
    const visiting = new Set<string>();
    
    const visit = (taskId: string) => {
      if (visiting.has(taskId)) throw new Error('Circular dependency detected');
      if (visited.has(taskId)) return;
      
      visiting.add(taskId);
      const task = tasks.find(t => t.id === taskId);
      if (task) {
        task.dependencies.forEach(visit);
        result.push(task);
        visited.add(taskId);
      }
      visiting.delete(taskId);
    };
    
    tasks.forEach(task => visit(task.id));
    return result;
  };

  const pauseExecution = () => {
    setIsPaused(true);
    addLog('⏸ Deployment paused by user', 'warning');
  };

  const resumeExecution = () => {
    setIsPaused(false);
    addLog('▶ Deployment resumed', 'info');
    startExecution();
  };

  const resetExecution = () => {
    setIsExecuting(false);
    setIsPaused(false);
    setCurrentTaskIndex(0);
    setOverallProgress(0);
    setExecutionLogs([]);
    setStartTime(null);
    
    if (deploymentPlan) {
      setDeploymentPlan({
        ...deploymentPlan,
        tasks: deploymentPlan.tasks.map(task => ({
          ...task,
          status: 'pending',
          progress: 0,
          error_message: undefined,
          artifacts: undefined
        }))
      });
    }
    
    addLog('🔄 Deployment reset', 'info');
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'infrastructure': return <Cpu className="h-4 w-4" />;
      case 'security': return <Shield className="h-4 w-4" />;
      case 'validation': return <CheckCircle className="h-4 w-4" />;
      case 'monitoring': return <Network className="h-4 w-4" />;
      default: return <Zap className="h-4 w-4" />;
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'running': return <Zap className="h-4 w-4 text-primary animate-pulse" />;
      case 'failed': return <XCircle className="h-4 w-4 text-red-500" />;
      case 'skipped': return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      default: return <Clock className="h-4 w-4 text-muted-foreground" />;
    }
  };

  if (!deploymentPlan) {
    return (
      <Card className="border-border">
        <CardContent className="p-8 text-center">
          <div className="text-muted-foreground">Generating deployment plan...</div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Deployment Overview */}
      <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center space-x-2">
              <Shield className="h-5 w-5 text-primary" />
              <span>{deploymentPlan.name}</span>
            </CardTitle>
            <div className="flex space-x-2">
              {!isExecuting ? (
                <Button onClick={startExecution} className="btn-cyber">
                  <PlayCircle className="h-4 w-4 mr-2" />
                  Start Deployment
                </Button>
              ) : isPaused ? (
                <Button onClick={resumeExecution}>
                  <PlayCircle className="h-4 w-4 mr-2" />
                  Resume
                </Button>
              ) : (
                <Button variant="outline" onClick={pauseExecution}>
                  <PauseCircle className="h-4 w-4 mr-2" />
                  Pause
                </Button>
              )}
              <Button variant="outline" onClick={resetExecution}>
                <RotateCcw className="h-4 w-4 mr-2" />
                Reset
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">{deploymentPlan.total_tasks}</div>
              <div className="text-sm text-muted-foreground">Total Tasks</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-green-500">
                {deploymentPlan.tasks.filter(t => t.status === 'completed').length}
              </div>
              <div className="text-sm text-muted-foreground">Completed</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-500">{selectedAssets.length}</div>
              <div className="text-sm text-muted-foreground">Assets Protected</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-purple-500">
                {Math.round(deploymentPlan.estimated_duration / 60)}m
              </div>
              <div className="text-sm text-muted-foreground">Est. Duration</div>
            </div>
          </div>
          
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span>Overall Progress</span>
              <span>{Math.round(overallProgress)}%</span>
            </div>
            <Progress value={overallProgress} className="h-3" />
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Task List */}
        <Card className="border-border">
          <CardHeader>
            <CardTitle>Deployment Tasks</CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-80">
              <div className="space-y-2">
                {deploymentPlan.tasks.map((task, index) => (
                  <div
                    key={task.id}
                    className={`p-3 rounded-lg border transition-all ${
                      task.status === 'running' 
                        ? 'border-primary bg-primary/5' 
                        : task.status === 'completed'
                        ? 'border-green-500/20 bg-green-500/5'
                        : task.status === 'failed'
                        ? 'border-red-500/20 bg-red-500/5'
                        : 'border-border'
                    }`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-start space-x-3">
                        <div className="mt-1">
                          {getStatusIcon(task.status)}
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center space-x-2">
                            <h4 className="font-medium">{task.name}</h4>
                            <Badge variant="outline">
                              {task.category}
                            </Badge>
                            <Badge 
                              variant={task.priority === 'high' ? 'destructive' : 
                                      task.priority === 'medium' ? 'secondary' : 'outline'}
                            >
                              {task.priority}
                            </Badge>
                          </div>
                          <p className="text-sm text-muted-foreground mt-1">
                            {task.description}
                          </p>
                          
                          {task.status === 'running' && (
                            <div className="mt-2">
                              <Progress value={task.progress} className="h-1" />
                            </div>
                          )}
                          
                          {task.error_message && (
                            <div className="mt-2 text-xs text-red-400">
                              Error: {task.error_message}
                            </div>
                          )}
                          
                          {task.artifacts && task.artifacts.length > 0 && (
                            <div className="mt-2">
                              <div className="text-xs text-muted-foreground">Artifacts:</div>
                              <div className="flex flex-wrap gap-1 mt-1">
                                {task.artifacts.map(artifact => (
                                  <Badge key={artifact} variant="outline">
                                    <HardDrive className="h-3 w-3 mr-1" />
                                    {artifact}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {task.duration}s
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>

        {/* Execution Logs */}
        <Card className="border-border">
          <CardHeader>
            <CardTitle>Execution Logs</CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-80">
              <div className="space-y-1 font-mono text-xs">
                {executionLogs.map((log, index) => (
                  <div 
                    key={index} 
                    className={`${
                      log.includes('✓') ? 'text-green-400' :
                      log.includes('⚠') ? 'text-yellow-400' :
                      log.includes('✗') ? 'text-red-400' :
                      log.includes('🎉') ? 'text-primary' :
                      'text-muted-foreground'
                    }`}
                  >
                    {log}
                  </div>
                ))}
                {executionLogs.length === 0 && (
                  <div className="text-muted-foreground">
                    Execution logs will appear here...
                  </div>
                )}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};