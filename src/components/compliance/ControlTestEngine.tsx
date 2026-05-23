import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import {
  Play,
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  FileText,
  Database,
  Zap
} from 'lucide-react';

interface ControlTest {
  id: string;
  controlId: string;
  framework: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'pending' | 'running' | 'passed' | 'failed' | 'error';
  lastRun?: Date;
  duration?: number;
  passRate: number;
  connector: string;
  query: {
    path: string;
    method: string;
    params?: Record<string, any>;
  };
  passCondition: string;
  evidenceTypes: string[];
  automationPossible: boolean;
}

interface TestExecution {
  id: string;
  testId: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  startTime: Date;
  endTime?: Date;
  result?: {
    passed: boolean;
    evidence: Record<string, any>;
    metadata: Record<string, any>;
    reason?: string;
  };
}

// Awaiting telemetry for real control tests
const pendingControlTests: ControlTest[] = [];

export const ControlTestEngine: React.FC = () => {
  const [tests, setTests] = useState<ControlTest[]>(pendingControlTests);
  const [executions, setExecutions] = useState<TestExecution[]>([]);
  const [isRunningAll, setIsRunningAll] = useState(false);
  const [selectedFramework, setSelectedFramework] = useState<string>('all');
  const { toast } = useToast();

  useEffect(() => {
    // Real-time test execution updates require actual test runner integration; interval removed to avoid fabricated data
  }, []);

  const executeTest = async (test: ControlTest) => {
    const executionId = `exec-${Date.now()}`;
    const execution: TestExecution = {
      id: executionId,
      testId: test.id,
      status: 'running',
      startTime: new Date()
    };

    setExecutions(prev => [...prev, execution]);
    setTests(prev => prev.map(t =>
      t.id === test.id ? { ...t, status: 'running', lastRun: new Date() } : t
    ));

    try {
      // Call the control test execution function
      const { data, error } = await supabase.functions.invoke('grok-ai-agent', {
        body: {
          action: 'execute_control_test',
          test: {
            id: test.id,
            controlId: test.controlId,
            connector: test.connector,
            query: test.query,
            passCondition: test.passCondition
          }
        }
      });

      if (error) throw error;

      toast({
        title: "Test Executed",
        description: `Control test ${test.controlId} has been executed`,
      });

      // Update test result from real edge function response
      const passed = data?.passed ?? false;
      setTests(prev => prev.map(t =>
        t.id === test.id ? {
          ...t,
          status: passed ? 'passed' : 'failed',
          duration: data?.duration || 0, // Real duration from test execution
          passRate: data?.passRate || 0 // Real pass rate from test execution
        } : t
      ));

      setExecutions(prev => prev.map(exec =>
        exec.id === executionId ? {
          ...exec,
          status: 'completed',
          endTime: new Date(),
          result: {
            passed,
            evidence: data?.evidence || {},
            metadata: data?.metadata || {},
            reason: passed ? 'All checks passed' : 'Compliance violations detected'
          }
        } : exec
      ));

    } catch (error) {
      console.error('Failed to execute test:', error);
      setTests(prev => prev.map(t =>
        t.id === test.id ? { ...t, status: 'error' } : t
      ));

      toast({
        title: "Test Failed",
        description: "Failed to execute control test",
        variant: "destructive"
      });
    }
  };

  const executeAllTests = async () => {
    setIsRunningAll(true);

    const filteredTests = selectedFramework === 'all'
      ? tests
      : tests.filter(t => t.framework === selectedFramework);

    for (const test of filteredTests) {
      if (test.status !== 'running') {
        await executeTest(test);
        // Add delay between tests to avoid overwhelming systems
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }

    setIsRunningAll(false);

    toast({
      title: "Batch Execution Complete",
      description: `Executed ${filteredTests.length} control tests`,
    });
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'passed': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'failed': return <XCircle className="h-4 w-4 text-red-500" />;
      case 'running': return <Clock className="h-4 w-4 text-blue-500 animate-spin" />;
      case 'error': return <AlertTriangle className="h-4 w-4 text-orange-500" />;
      default: return <Clock className="h-4 w-4 text-gray-500" />;
    }
  };



  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-blue-500';
      default: return 'bg-gray-500';
    }
  };

  const frameworks = ['all', ...Array.from(new Set(tests.map(t => t.framework)))];
  const filteredTests = selectedFramework === 'all'
    ? tests
    : tests.filter(t => t.framework === selectedFramework);

  const overallStats = {
    total: filteredTests.length,
    passed: filteredTests.filter(t => t.status === 'passed').length,
    failed: filteredTests.filter(t => t.status === 'failed').length,
    running: filteredTests.filter(t => t.status === 'running').length,
    automated: filteredTests.filter(t => t.automationPossible).length
  };

  return (
    <div className="space-y-6">
      {/* Header Stats */}
      <div className="grid grid-cols-5 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-2xl font-bold">{overallStats.total}</div>
              <div className="text-sm text-muted-foreground">Total Tests</div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-green-500">{overallStats.passed}</div>
              <div className="text-sm text-muted-foreground">Passed</div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-red-500">{overallStats.failed}</div>
              <div className="text-sm text-muted-foreground">Failed</div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-500">{overallStats.running}</div>
              <div className="text-sm text-muted-foreground">Running</div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-purple-500">{overallStats.automated}</div>
              <div className="text-sm text-muted-foreground">Automated</div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Controls */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Zap className="h-5 w-5" />
                Control Test Engine
              </CardTitle>
              <CardDescription>
                Continuous automated testing of compliance controls with evidence collection
              </CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <select
                value={selectedFramework}
                onChange={(e) => setSelectedFramework(e.target.value)}
                className="px-3 py-2 border rounded-md"
              >
                {frameworks.map(framework => (
                  <option key={framework} value={framework}>
                    {framework === 'all' ? 'All Frameworks' : framework}
                  </option>
                ))}
              </select>
              <Button
                onClick={executeAllTests}
                disabled={isRunningAll}
                className="flex items-center gap-2"
              >
                <Play className="h-4 w-4" />
                {isRunningAll ? 'Running...' : 'Run All Tests'}
              </Button>
            </div>
          </div>
        </CardHeader>
      </Card>

      {/* Test List */}
      <div className="space-y-4">
        {filteredTests.map((test) => (
          <Card key={test.id}>
            <CardHeader>
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <Badge className={getSeverityColor(test.severity)}>
                      {test.severity.toUpperCase()}
                    </Badge>
                    <Badge variant="outline">{test.framework}</Badge>
                    {test.automationPossible && (
                      <Badge variant="secondary">Auto</Badge>
                    )}
                  </div>
                  <CardTitle className="flex items-center gap-2">
                    {getStatusIcon(test.status)}
                    {test.title}
                  </CardTitle>
                  <CardDescription>{test.controlId}</CardDescription>
                </div>
                <div className="flex items-center gap-2">
                  <div className="text-right text-sm">
                    <div className="font-medium">{test.passRate}%</div>
                    <div className="text-muted-foreground">Pass Rate</div>
                  </div>
                  <Button
                    onClick={() => executeTest(test)}
                    disabled={test.status === 'running'}
                    size="sm"
                    variant="outline"
                  >
                    {test.status === 'running' ? 'Running...' : 'Run Test'}
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-4 mb-4">
                <div>
                  <div className="text-sm text-muted-foreground mb-1">Connector</div>
                  <div className="font-medium">{test.connector}</div>
                </div>
                <div>
                  <div className="text-sm text-muted-foreground mb-1">Last Run</div>
                  <div className="font-medium">
                    {test.lastRun ? test.lastRun.toLocaleString() : 'Never'}
                  </div>
                </div>
              </div>

              <div className="mb-4">
                <div className="text-sm text-muted-foreground mb-1">Query</div>
                <div className="bg-muted p-2 rounded text-sm font-mono">
                  {test.query.method} {test.query.path}
                </div>
              </div>

              <div className="mb-4">
                <div className="text-sm text-muted-foreground mb-1">Pass Condition</div>
                <div className="bg-muted p-2 rounded text-sm font-mono">
                  {test.passCondition}
                </div>
              </div>

              <div className="flex items-center gap-4">
                <div className="flex items-center gap-2">
                  <FileText className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm">
                    Evidence: {test.evidenceTypes.join(', ')}
                  </span>
                </div>
                {Boolean(test.duration) && (
                  <div className="flex items-center gap-2">
                    <Clock className="h-4 w-4 text-muted-foreground" />
                    <span className="text-sm">
                      Duration: {test.duration}s
                    </span>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Recent Executions */}
      {executions.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Database className="h-5 w-5" />
              Recent Test Executions
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {executions.slice(-5).reverse().map((execution) => {
                const test = tests.find(t => t.id === execution.testId);
                return (
                  <div key={execution.id} className="flex items-center justify-between p-3 border rounded">
                    <div className="flex items-center gap-3">
                      {getStatusIcon(execution.status)}
                      <div>
                        <div className="font-medium">{test?.controlId}</div>
                        <div className="text-sm text-muted-foreground">
                          Started: {execution.startTime.toLocaleTimeString()}
                          {execution.endTime && ` • Completed: ${execution.endTime.toLocaleTimeString()}`}
                        </div>
                      </div>
                    </div>
                    <div className="text-right">
                      {execution.result && (
                        <div className="text-sm">
                          <div className={execution.result.passed ? 'text-green-600' : 'text-red-600'}>
                            {execution.result.passed ? 'PASSED' : 'FAILED'}
                          </div>
                          {execution.result.evidence.tested_resources && (
                            <div className="text-muted-foreground">
                              {execution.result.evidence.tested_resources} resources tested
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};