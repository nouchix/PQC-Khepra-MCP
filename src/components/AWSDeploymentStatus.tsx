import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Shield, 
  CheckCircle, 
  AlertTriangle, 
  Clock,
  Cloud,
  Database,
  Zap,
  Network,
  Settings,
  RefreshCw,
  Globe,
  Lock,
  Container,
  GitBranch,
  Activity
} from 'lucide-react';

interface AWSServiceStatus {
  name: string;
  status: 'healthy' | 'degraded' | 'offline';
  endpoint?: string;
  lastCheck: string;
  responseTime?: number;
}

interface DeploymentInfo {
  region: string;
  environment: string;
  version: string;
  lastDeployed: string;
  services: AWSServiceStatus[];
}

export const AWSDeploymentStatus = () => {
  const [deploymentInfo, setDeploymentInfo] = useState<DeploymentInfo | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());

  useEffect(() => {
    const checkDeploymentStatus = () => {
      // Simulate AWS service checks
      const mockDeploymentInfo: DeploymentInfo = {
        region: 'us-east-1',
        environment: 'production',
        version: '2.1.0',
        lastDeployed: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
        services: [
          {
            name: 'Application Load Balancer',
            status: 'healthy',
            endpoint: 'https://khepra-alb-123456789.us-east-1.elb.amazonaws.com',
            lastCheck: new Date().toISOString(),
            responseTime: 89
          },
          {
            name: 'ECS Fargate Service',
            status: 'healthy',
            lastCheck: new Date().toISOString(),
            responseTime: 145
          },
          {
            name: 'CodePipeline',
            status: 'healthy',
            lastCheck: new Date().toISOString()
          },
          {
            name: 'ECR Repository',
            status: 'healthy',
            lastCheck: new Date().toISOString()
          },
          {
            name: 'CloudWatch Logs',
            status: 'healthy',
            lastCheck: new Date().toISOString()
          },
          {
            name: 'GitHub App Lambda',
            status: 'healthy',
            lastCheck: new Date().toISOString(),
            responseTime: 234
          },
          {
            name: 'VPC & Networking',
            status: 'healthy',
            lastCheck: new Date().toISOString()
          },
          {
            name: 'Security Groups',
            status: 'healthy',
            lastCheck: new Date().toISOString()
          }
        ]
      };

      setDeploymentInfo(mockDeploymentInfo);
      setIsLoading(false);
      setLastRefresh(new Date());
    };

    checkDeploymentStatus();
    const interval = setInterval(checkDeploymentStatus, 60000); // Check every minute

    return () => clearInterval(interval);
  }, []);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'degraded': return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      case 'offline': return <Clock className="h-4 w-4 text-red-500" />;
      default: return <Clock className="h-4 w-4 text-muted-foreground" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return 'text-green-500 bg-green-500/10';
      case 'degraded': return 'text-yellow-500 bg-yellow-500/10';
      case 'offline': return 'text-red-500 bg-red-500/10';
      default: return 'text-muted-foreground bg-muted/10';
    }
  };

  const getServiceIcon = (serviceName: string) => {
    if (serviceName.includes('Load Balancer')) return <Globe className="h-4 w-4" />;
    if (serviceName.includes('ECS')) return <Container className="h-4 w-4" />;
    if (serviceName.includes('Pipeline')) return <GitBranch className="h-4 w-4" />;
    if (serviceName.includes('ECR')) return <Database className="h-4 w-4" />;
    if (serviceName.includes('CloudWatch')) return <Activity className="h-4 w-4" />;
    if (serviceName.includes('Lambda')) return <Zap className="h-4 w-4" />;
    if (serviceName.includes('VPC')) return <Network className="h-4 w-4" />;
    if (serviceName.includes('Security')) return <Lock className="h-4 w-4" />;
    return <Cloud className="h-4 w-4" />;
  };

  const healthyServices = deploymentInfo?.services.filter(s => s.status === 'healthy').length || 0;
  const totalServices = deploymentInfo?.services.length || 0;
  const healthPercentage = totalServices > 0 ? Math.round((healthyServices / totalServices) * 100) : 0;

  if (isLoading) {
    return (
      <Card className="border-border">
        <CardContent className="p-6">
          <div className="animate-pulse space-y-4">
            <div className="h-6 bg-muted rounded"></div>
            <div className="h-20 bg-muted rounded"></div>
          </div>
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
            <div className="flex items-center space-x-3">
              <Shield className="h-6 w-6 text-primary" />
              <div>
                <CardTitle>AWS Deployment Status</CardTitle>
                <div className="flex items-center space-x-2 mt-1">
                  {healthPercentage === 100 ? (
                    <CheckCircle className="h-4 w-4 text-green-500" />
                  ) : (
                    <AlertTriangle className="h-4 w-4 text-yellow-500" />
                  )}
                  <span className={`text-sm font-medium ${healthPercentage === 100 ? 'text-green-500' : 'text-yellow-500'}`}>
                    {healthPercentage === 100 ? 'All Systems Operational' : 'Some Issues Detected'}
                  </span>
                  <span className="text-sm text-muted-foreground">
                    • Health: {healthPercentage}%
                  </span>
                </div>
              </div>
            </div>
            
            <div className="flex items-center space-x-2">
              <Button 
                variant="outline" 
                size="sm"
                onClick={() => globalThis.location.reload()}
              >
                <RefreshCw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
            </div>
          </div>
        </CardHeader>
        
        <CardContent className="space-y-4">
          {/* Deployment Info */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="text-center">
              <div className="text-lg font-bold text-primary">{deploymentInfo?.region}</div>
              <div className="text-sm text-muted-foreground">AWS Region</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-bold text-blue-500">{deploymentInfo?.environment}</div>
              <div className="text-sm text-muted-foreground">Environment</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-bold text-purple-500">{deploymentInfo?.version}</div>
              <div className="text-sm text-muted-foreground">Version</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-bold text-green-500">{healthyServices}/{totalServices}</div>
              <div className="text-sm text-muted-foreground">Services Healthy</div>
            </div>
          </div>

          {/* Health Score */}
          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <span className="text-sm font-medium">Overall Deployment Health</span>
              <span className="text-sm text-muted-foreground">
                Last updated: {lastRefresh.toLocaleTimeString()}
              </span>
            </div>
            <Progress value={healthPercentage} className="h-3" />
          </div>
        </CardContent>
      </Card>

      {/* Service Status */}
      <Card className="border-border">
        <Tabs defaultValue="services" className="w-full">
          <div className="border-b border-border p-4">
            <TabsList className="grid grid-cols-3 w-full max-w-md">
              <TabsTrigger value="services">Services</TabsTrigger>
              <TabsTrigger value="infrastructure">Infrastructure</TabsTrigger>
              <TabsTrigger value="deployment">Deployment</TabsTrigger>
            </TabsList>
          </div>

          <div className="p-6">
            <TabsContent value="services" className="space-y-4 mt-0">
              <div className="grid gap-4">
                {deploymentInfo?.services.map((service, index) => (
                  <div key={index} className="flex items-center justify-between p-4 border border-border rounded-lg">
                    <div className="flex items-center space-x-3">
                      {getServiceIcon(service.name)}
                      <div>
                        <div className="font-medium">{service.name}</div>
                        {service.endpoint && (
                          <div className="text-sm text-muted-foreground">{service.endpoint}</div>
                        )}
                      </div>
                    </div>
                    
                    <div className="flex items-center space-x-3">
                      {service.responseTime && (
                        <span className="text-sm text-muted-foreground">
                          {service.responseTime}ms
                        </span>
                      )}
                      <Badge variant="outline" className={getStatusColor(service.status)}>
                        <div className="flex items-center space-x-1">
                          {getStatusIcon(service.status)}
                          <span>{service.status}</span>
                        </div>
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
            </TabsContent>

            <TabsContent value="infrastructure" className="space-y-4 mt-0">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <Card className="border-border">
                  <CardHeader>
                    <CardTitle className="flex items-center space-x-2">
                      <Network className="h-5 w-5" />
                      <span>Network Infrastructure</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="flex justify-between">
                      <span>VPC Configuration</span>
                      <Badge variant="outline" className="text-green-500 bg-green-500/10">
                        <CheckCircle className="h-3 w-3 mr-1" />
                        Configured
                      </Badge>
                    </div>
                    <div className="flex justify-between">
                      <span>Public Subnets</span>
                      <Badge variant="outline" className="text-green-500 bg-green-500/10">
                        <CheckCircle className="h-3 w-3 mr-1" />
                        2 Active
                      </Badge>
                    </div>
                    <div className="flex justify-between">
                      <span>Internet Gateway</span>
                      <Badge variant="outline" className="text-green-500 bg-green-500/10">
                        <CheckCircle className="h-3 w-3 mr-1" />
                        Attached
                      </Badge>
                    </div>
                    <div className="flex justify-between">
                      <span>Security Groups</span>
                      <Badge variant="outline" className="text-green-500 bg-green-500/10">
                        <CheckCircle className="h-3 w-3 mr-1" />
                        Configured
                      </Badge>
                    </div>
                  </CardContent>
                </Card>

                <Card className="border-border">
                  <CardHeader>
                    <CardTitle className="flex items-center space-x-2">
                      <Container className="h-5 w-5" />
                      <span>Container Platform</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="flex justify-between">
                      <span>ECS Cluster</span>
                      <Badge variant="outline" className="text-green-500 bg-green-500/10">
                        <CheckCircle className="h-3 w-3 mr-1" />
                        Running
                      </Badge>
                    </div>
                    <div className="flex justify-between">
                      <span>Fargate Service</span>
                      <Badge variant="outline" className="text-green-500 bg-green-500/10">
                        <CheckCircle className="h-3 w-3 mr-1" />
                        Healthy
                      </Badge>
                    </div>
                    <div className="flex justify-between">
                      <span>Application Load Balancer</span>
                      <Badge variant="outline" className="text-green-500 bg-green-500/10">
                        <CheckCircle className="h-3 w-3 mr-1" />
                        Active
                      </Badge>
                    </div>
                    <div className="flex justify-between">
                      <span>ECR Repository</span>
                      <Badge variant="outline" className="text-green-500 bg-green-500/10">
                        <CheckCircle className="h-3 w-3 mr-1" />
                        Available
                      </Badge>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>

            <TabsContent value="deployment" className="space-y-4 mt-0">
              <Card className="border-border">
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <GitBranch className="h-5 w-5" />
                    <span>Deployment Pipeline</span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-3">
                    <div className="flex items-center justify-between p-3 border border-border rounded-lg">
                      <div className="flex items-center space-x-3">
                        <CheckCircle className="h-5 w-5 text-green-500" />
                        <div>
                          <div className="font-medium">Source Stage</div>
                          <div className="text-sm text-muted-foreground">GitHub repository connected</div>
                        </div>
                      </div>
                      <Badge variant="outline" className="text-green-500 bg-green-500/10">
                        Success
                      </Badge>
                    </div>

                    <div className="flex items-center justify-between p-3 border border-border rounded-lg">
                      <div className="flex items-center space-x-3">
                        <CheckCircle className="h-5 w-5 text-green-500" />
                        <div>
                          <div className="font-medium">Build Stage</div>
                          <div className="text-sm text-muted-foreground">Docker image built and pushed to ECR</div>
                        </div>
                      </div>
                      <Badge variant="outline" className="text-green-500 bg-green-500/10">
                        Success
                      </Badge>
                    </div>

                    <div className="flex items-center justify-between p-3 border border-border rounded-lg">
                      <div className="flex items-center space-x-3">
                        <CheckCircle className="h-5 w-5 text-green-500" />
                        <div>
                          <div className="font-medium">Deploy Stage</div>
                          <div className="text-sm text-muted-foreground">Application deployed to ECS Fargate</div>
                        </div>
                      </div>
                      <Badge variant="outline" className="text-green-500 bg-green-500/10">
                        Success
                      </Badge>
                    </div>
                  </div>

                  <div className="border-t border-border pt-4">
                    <div className="flex justify-between items-center">
                      <span className="text-sm font-medium">Last Deployment</span>
                      <span className="text-sm text-muted-foreground">
                        {deploymentInfo && new Date(deploymentInfo.lastDeployed).toLocaleString()}
                      </span>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card className="border-border">
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <Globe className="h-5 w-5" />
                    <span>Access Points</span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex justify-between items-center">
                    <span>Application URL</span>
                    <Button variant="outline" size="sm" onClick={() => globalThis.open('https://khepra-alb-123456789.us-east-1.elb.amazonaws.com', '_blank')}>
                      Open Application
                    </Button>
                  </div>
                  <div className="flex justify-between items-center">
                    <span>AWS Console</span>
                    <Button variant="outline" size="sm" onClick={() => globalThis.open('https://console.aws.amazon.com/ecs/home?region=us-east-1', '_blank')}>
                      View in AWS
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </div>
        </Tabs>
      </Card>
    </div>
  );
};