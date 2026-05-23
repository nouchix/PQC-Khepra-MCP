import { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Switch } from '@/components/ui/switch';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Smartphone, 
  Monitor, 
  Clock,
  Eye,
  RefreshCw,
  ShieldCheck,
  Activity,
  Zap
} from 'lucide-react';
import { useContinuousAuth } from '@/hooks/useContinuousAuth';
import { useToast } from '@/hooks/use-toast';

export function ContinuousAuthManager() {
  const { toast } = useToast();
  const {
    isMonitoring,
    lastValidation,
    riskLevel,
    deviceTrusted,
    sessionValid,
    requiresReauth,
    startMonitoring,
    stopMonitoring,
    trustCurrentDevice,
    forceReauth,
    clearReauthRequirement,
    performAuthCheck
  } = useContinuousAuth();

  const [autoMonitoring, setAutoMonitoring] = useState(true);

  // Risk level styling
  const getRiskBadge = (level: string) => {
    switch (level) {
      case 'low':
        return <Badge className="bg-green-100 text-green-800 border-green-200">Low Risk</Badge>;
      case 'medium':
        return <Badge className="bg-yellow-100 text-yellow-800 border-yellow-200">Medium Risk</Badge>;
      case 'high':
        return <Badge className="bg-orange-100 text-orange-800 border-orange-200">High Risk</Badge>;
      case 'critical':
        return <Badge className="bg-red-100 text-red-800 border-red-200">Critical Risk</Badge>;
      default:
        return <Badge variant="outline">Unknown</Badge>;
    }
  };

  const getRiskProgress = (level: string) => {
    switch (level) {
      case 'low': return 25;
      case 'medium': return 50;
      case 'high': return 75;
      case 'critical': return 100;
      default: return 0;
    }
  };

  const handleToggleMonitoring = () => {
    if (isMonitoring) {
      stopMonitoring();
      setAutoMonitoring(false);
      toast({
        title: "Monitoring Disabled",
        description: "Continuous authentication monitoring has been stopped."
      });
    } else {
      startMonitoring();
      setAutoMonitoring(true);
      toast({
        title: "Monitoring Enabled",
        description: "Continuous authentication monitoring is now active."
      });
    }
  };

  const handleTrustDevice = async () => {
    await trustCurrentDevice();
    toast({
      title: "Device Trusted",
      description: "This device has been added to your trusted devices list."
    });
  };

  const handleForceReauth = () => {
    forceReauth();
    toast({
      title: "Re-authentication Required",
      description: "Please verify your identity to continue.",
      variant: "destructive"
    });
  };

  const simulateReauth = () => {
    // In a real implementation, this would trigger the actual re-auth flow
    clearReauthRequirement();
    toast({
      title: "Re-authentication Successful",
      description: "Your identity has been verified. Session restored."
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">Continuous Authentication</h2>
          <p className="text-muted-foreground">
            Real-time session monitoring and risk-based authentication
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <span className="text-sm">Auto-monitoring</span>
          <Switch 
            checked={autoMonitoring} 
            onCheckedChange={handleToggleMonitoring}
          />
        </div>
      </div>

      {/* Security Alert */}
      {requiresReauth && (
        <Alert className="border-red-200 bg-red-50">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription className="flex items-center justify-between">
            <span>High-risk activity detected. Re-authentication required to continue.</span>
            <Button onClick={simulateReauth} size="sm" variant="destructive">
              Re-authenticate
            </Button>
          </AlertDescription>
        </Alert>
      )}

      <Tabs defaultValue="overview" className="w-full">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="device">Device Trust</TabsTrigger>
          <TabsTrigger value="monitoring">Monitoring</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Session Status */}
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Session Status</CardTitle>
                <Activity className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="flex items-center space-x-2">
                  {sessionValid ? (
                    <CheckCircle className="h-4 w-4 text-green-500" />
                  ) : (
                    <AlertTriangle className="h-4 w-4 text-red-500" />
                  )}
                  <span className="text-sm font-medium">
                    {sessionValid ? 'Valid' : 'Requires Auth'}
                  </span>
                </div>
              </CardContent>
            </Card>

            {/* Device Trust */}
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Device Trust</CardTitle>
                <Smartphone className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="flex items-center space-x-2">
                  {deviceTrusted ? (
                    <ShieldCheck className="h-4 w-4 text-green-500" />
                  ) : (
                    <Shield className="h-4 w-4 text-yellow-500" />
                  )}
                  <span className="text-sm font-medium">
                    {deviceTrusted ? 'Trusted' : 'Unverified'}
                  </span>
                </div>
              </CardContent>
            </Card>

            {/* Risk Level */}
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Risk Level</CardTitle>
                <Eye className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                {getRiskBadge(riskLevel)}
              </CardContent>
            </Card>

            {/* Monitoring */}
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Monitoring</CardTitle>
                <Activity className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="flex items-center space-x-2">
                  {isMonitoring ? (
                    <Zap className="h-4 w-4 text-green-500" />
                  ) : (
                    <Clock className="h-4 w-4 text-gray-500" />
                  )}
                  <span className="text-sm font-medium">
                    {isMonitoring ? 'Active' : 'Inactive'}
                  </span>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Risk Assessment */}
          <Card>
            <CardHeader>
              <CardTitle>Risk Assessment</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Current Risk Level</span>
                {getRiskBadge(riskLevel)}
              </div>
              <Progress value={getRiskProgress(riskLevel)} className="w-full" />
              <div className="text-xs text-muted-foreground">
                Last validation: {lastValidation ? lastValidation.toLocaleString() : 'Never'}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="device" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Device Trust Management</CardTitle>
              <p className="text-sm text-muted-foreground">
                Manage trusted devices for enhanced security
              </p>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between p-4 border rounded-lg">
                <div className="flex items-center space-x-3">
                  <Monitor className="h-8 w-8 text-muted-foreground" />
                  <div>
                    <p className="font-medium">Current Device</p>
                    <p className="text-sm text-muted-foreground">
                      {navigator.platform} - {navigator.userAgent.split(' ')[0]}
                    </p>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  {deviceTrusted ? (
                    <Badge className="bg-green-100 text-green-800">Trusted</Badge>
                  ) : (
                    <Button onClick={handleTrustDevice} size="sm">
                      Trust Device
                    </Button>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="monitoring" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Monitoring Controls</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">Continuous Monitoring</p>
                  <p className="text-sm text-muted-foreground">
                    Real-time session validation every 5 minutes
                  </p>
                </div>
                <Button
                  onClick={handleToggleMonitoring}
                  variant={isMonitoring ? "destructive" : "default"}
                >
                  {isMonitoring ? "Stop" : "Start"} Monitoring
                </Button>
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">Manual Check</p>
                  <p className="text-sm text-muted-foreground">
                    Perform immediate authentication validation
                  </p>
                </div>
                <Button onClick={performAuthCheck} variant="outline">
                  <RefreshCw className="h-4 w-4 mr-2" />
                  Check Now
                </Button>
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">Force Re-authentication</p>
                  <p className="text-sm text-muted-foreground">
                    Require immediate identity verification
                  </p>
                </div>
                <Button onClick={handleForceReauth} variant="destructive">
                  Force Re-auth
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="settings" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Authentication Settings</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <p className="font-medium">Risk Thresholds</p>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>Low Risk: 0-24 points</div>
                  <div>Medium Risk: 25-49 points</div>
                  <div>High Risk: 50-69 points</div>
                  <div>Critical Risk: 70+ points</div>
                </div>
              </div>

              <div className="space-y-2">
                <p className="font-medium">Monitoring Frequency</p>
                <p className="text-sm text-muted-foreground">
                  Authentication checks run every 5 minutes during active sessions
                </p>
              </div>

              <div className="space-y-2">
                <p className="font-medium">Device Trust Duration</p>
                <p className="text-sm text-muted-foreground">
                  Trusted devices remain valid for 30 days
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}