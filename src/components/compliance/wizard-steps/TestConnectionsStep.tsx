import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { 
  CheckCircle, 
  AlertCircle, 
  RefreshCw, 
  Play,
  Server,
  Eye,
  Clock,
  Zap
} from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { WizardData } from '../DataSourcesWizard';

interface TestResult {
  environmentType: string;
  status: 'pending' | 'testing' | 'success' | 'failed';
  message: string;
  discoveredAssets: number;
  responseTime: number;
  lastTested: Date | null;
}

interface TestConnectionsStepProps {
  data: WizardData;
  onUpdate: (updates: Partial<WizardData>) => void;
}

export const TestConnectionsStep: React.FC<TestConnectionsStepProps> = ({
  data,
  onUpdate
}) => {
  const [testResults, setTestResults] = useState<Record<string, TestResult>>({});
  const [isTestingAll, setIsTestingAll] = useState(false);
  const [testProgress, setTestProgress] = useState(0);

  useEffect(() => {
    // Initialize test results for each environment
    const initialResults: Record<string, TestResult> = {};
    Object.keys(data.connectionMethods).forEach(envType => {
      initialResults[envType] = {
        environmentType: envType,
        status: 'pending',
        message: 'Ready to test connection',
        discoveredAssets: 0,
        responseTime: 0,
        lastTested: null
      };
    });
    setTestResults(initialResults);
  }, [data.connectionMethods]);

  const testSingleConnection = async (environmentType: string) => {
    setTestResults(prev => ({
      ...prev,
      [environmentType]: {
        ...prev[environmentType],
        status: 'testing',
        message: 'Testing connection...'
      }
    }));

    // Test real connection via Supabase edge function
    try {
      const startTime = Date.now();
      const { data, error } = await supabase.functions.invoke('test-environment-connection', {
        body: { environment_type: environmentType }
      });
      const responseTime = Date.now() - startTime;

      const success = !error && data?.success;
      const discoveredAssets = data?.discovered_assets || 0;

      setTestResults(prev => ({
        ...prev,
        [environmentType]: {
          ...prev[environmentType],
          status: success ? 'success' : 'failed',
          message: success 
            ? `Connection successful. Discovered ${discoveredAssets} assets.`
            : 'Connection failed. Please check credentials and network connectivity.',
          discoveredAssets,
          responseTime,
          lastTested: new Date()
        }
      }));
    } catch (error) {
      setTestResults(prev => ({
        ...prev,
        [environmentType]: {
          ...prev[environmentType],
          status: 'failed',
          message: 'Connection test failed with error.',
          lastTested: new Date()
        }
      }));
    }
  };

  const testAllConnections = async () => {
    setIsTestingAll(true);
    setTestProgress(0);
    
    const environments = Object.keys(data.connectionMethods);
    const progressStep = 100 / environments.length;

    for (let i = 0; i < environments.length; i++) {
      const envType = environments[i];
      setTestProgress((i + 0.5) * progressStep);
      await testSingleConnection(envType);
      setTestProgress((i + 1) * progressStep);
    }
    
    setIsTestingAll(false);
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'testing':
        return <RefreshCw className="h-4 w-4 animate-spin text-blue-500" />;
      case 'success':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'failed':
        return <AlertCircle className="h-4 w-4 text-red-500" />;
      default:
        return <Clock className="h-4 w-4 text-gray-400" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'testing':
        return 'bg-blue-500/10 text-blue-600 border-blue-500/20';
      case 'success':
        return 'bg-green-500/10 text-green-600 border-green-500/20';
      case 'failed':
        return 'bg-red-500/10 text-red-600 border-red-500/20';
      default:
        return 'bg-gray-500/10 text-gray-600 border-gray-500/20';
    }
  };

  const getEnvironmentTitle = (envId: string) => {
    const titles: Record<string, string> = {
      'cloud-aws': 'AWS Cloud Infrastructure',
      'cloud-azure': 'Microsoft Azure',
      'cloud-gcp': 'Google Cloud Platform',
      'servers-windows': 'Windows Servers',
      'servers-linux': 'Linux Servers',
      'containers-docker': 'Docker Containers',
      'containers-k8s': 'Kubernetes Clusters',
      'industrial-plc': 'PLCs and RTUs',
      'industrial-scada': 'SCADA Systems',
      'energy-solar': 'Solar Power Systems',
      'energy-wind': 'Wind Power Systems',
      'energy-battery': 'Battery Storage Systems',
      'network-infrastructure': 'Network Infrastructure'
    };
    return titles[envId] || envId;
  };

  const totalAssets = Object.values(testResults).reduce((sum, result) => sum + result.discoveredAssets, 0);
  const successfulTests = Object.values(testResults).filter(result => result.status === 'success').length;
  const failedTests = Object.values(testResults).filter(result => result.status === 'failed').length;

  return (
    <div className="space-y-6">
      <div className="text-center space-y-2">
        <h3 className="text-lg font-semibold">Test Connections & Discover Assets</h3>
        <p className="text-muted-foreground">
          Verify connectivity and discover assets in your selected environments.
        </p>
      </div>

      <div className="flex justify-between items-center">
        <div className="text-sm text-muted-foreground">
          Testing {Object.keys(testResults).length} environment types
        </div>
        <Button 
          onClick={testAllConnections}
          disabled={isTestingAll}
          variant="default"
        >
          {isTestingAll ? (
            <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
          ) : (
            <Play className="h-4 w-4 mr-2" />
          )}
          {isTestingAll ? 'Testing All...' : 'Test All Connections'}
        </Button>
      </div>

      {isTestingAll && (
        <div className="space-y-2">
          <div className="flex justify-between text-sm">
            <span>Overall Progress</span>
            <span>{Math.round(testProgress)}%</span>
          </div>
          <Progress value={testProgress} className="h-2" />
        </div>
      )}

      <div className="grid gap-4">
        {Object.entries(testResults).map(([environmentType, result]) => (
          <Card key={environmentType} className="transition-all hover:shadow-md">
            <CardHeader className="pb-4">
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center space-x-2 text-base">
                  <Server className="h-4 w-4 text-primary" />
                  <span>{getEnvironmentTitle(environmentType)}</span>
                </CardTitle>
                <div className="flex items-center space-x-2">
                  <Badge 
                    variant="outline"
                    className={getStatusColor(result.status)}
                  >
                    {getStatusIcon(result.status)}
                    <span className="ml-1 capitalize">{result.status}</span>
                  </Badge>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => testSingleConnection(environmentType)}
                    disabled={result.status === 'testing' || isTestingAll}
                  >
                    {result.status === 'testing' ? (
                      <RefreshCw className="h-4 w-4 animate-spin" />
                    ) : (
                      <Zap className="h-4 w-4" />
                    )}
                  </Button>
                </div>
              </div>
              <CardDescription>
                Connection method: {data.connectionMethods[environmentType]}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <p className="text-sm text-muted-foreground">
                  {result.message}
                </p>
                
                {result.status === 'success' && (
                  <div className="grid grid-cols-3 gap-4 pt-2">
                    <div className="text-center">
                      <div className="text-lg font-semibold text-green-600">
                        {result.discoveredAssets}
                      </div>
                      <div className="text-xs text-muted-foreground">
                        Assets Found
                      </div>
                    </div>
                    <div className="text-center">
                      <div className="text-lg font-semibold text-blue-600">
                        {result.responseTime}ms
                      </div>
                      <div className="text-xs text-muted-foreground">
                        Response Time
                      </div>
                    </div>
                    <div className="text-center">
                      <div className="text-lg font-semibold text-primary">
                        <CheckCircle className="h-5 w-5 mx-auto" />
                      </div>
                      <div className="text-xs text-muted-foreground">
                        Ready to Scan
                      </div>
                    </div>
                  </div>
                )}
                
                {result.lastTested && (
                  <div className="text-xs text-muted-foreground">
                    Last tested: {result.lastTested.toLocaleTimeString()}
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {successfulTests > 0 && (
        <Card className="bg-primary/5 border-primary/20">
          <CardContent className="pt-6">
            <div className="flex items-center space-x-3">
              <Eye className="h-5 w-5 text-primary" />
              <div>
                <h4 className="font-medium">
                  Discovery Complete: {totalAssets} assets found across {successfulTests} environments
                </h4>
                <p className="text-sm text-muted-foreground">
                  {failedTests > 0 && `${failedTests} connection(s) failed and will be skipped. `}
                  Ready to configure STIG compliance scanning for discovered assets.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};