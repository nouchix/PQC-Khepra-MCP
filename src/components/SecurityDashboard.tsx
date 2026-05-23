import { useState } from 'react';
import { useSecurityMonitor } from '@/hooks/useSecurityMonitor';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { 
  Shield, AlertTriangle, CheckCircle, Clock, MapPin, 
  Monitor, Smartphone, Globe, X, Eye, Activity,
  Lock, Wifi, AlertCircle
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';

export const SecurityDashboard = () => {
  const { alerts, sessions, riskScore, loading, resolveAlert, terminateSession } = useSecurityMonitor();
  const [selectedAlert, setSelectedAlert] = useState<string | null>(null);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'bg-destructive text-destructive-foreground';
      case 'HIGH': return 'bg-warning text-warning-foreground';
      case 'MEDIUM': return 'bg-info text-info-foreground';
      default: return 'bg-secondary text-secondary-foreground';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return <AlertTriangle className="h-4 w-4" />;
      case 'HIGH': return <AlertCircle className="h-4 w-4" />;
      default: return <Eye className="h-4 w-4" />;
    }
  };

  const getRiskScoreColor = () => {
    if (riskScore >= 75) return 'text-destructive';
    if (riskScore >= 50) return 'text-warning';
    if (riskScore >= 25) return 'text-info';
    return 'text-success';
  };

  const activeAlerts = alerts.filter(alert => !alert.resolved);
  const resolvedAlerts = alerts.filter(alert => alert.resolved);

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="text-foreground">Loading security data...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Security Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Risk Score</p>
                <p className={`text-2xl font-bold ${getRiskScoreColor()}`}>{riskScore}/100</p>
              </div>
              <Shield className={`h-8 w-8 ${getRiskScoreColor()}`} />
            </div>
          </CardContent>
        </Card>
        
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Active Alerts</p>
                <p className="text-2xl font-bold text-destructive">{activeAlerts.length}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-destructive" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Active Sessions</p>
                <p className="text-2xl font-bold text-success">{sessions.length}</p>
              </div>
              <Monitor className="h-8 w-8 text-success" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">System Status</p>
                <p className="text-sm font-bold text-success">SECURE</p>
              </div>
              <CheckCircle className="h-8 w-8 text-success" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Security Tabs */}
      <Tabs defaultValue="alerts" className="space-y-4">
        <TabsList className="bg-card border border-border">
          <TabsTrigger value="alerts" className="flex items-center space-x-2">
            <AlertTriangle className="h-4 w-4" />
            <span>Security Alerts</span>
            {activeAlerts.length > 0 && (
              <Badge variant="destructive" className="ml-1 text-xs">
                {activeAlerts.length}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="sessions" className="flex items-center space-x-2">
            <Monitor className="h-4 w-4" />
            <span>Active Sessions</span>
          </TabsTrigger>
          <TabsTrigger value="activity" className="flex items-center space-x-2">
            <Activity className="h-4 w-4" />
            <span>Security Activity</span>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="alerts" className="space-y-4">
          <Card className="card-cyber">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <AlertTriangle className="h-5 w-5 text-warning" />
                <span>Security Alerts</span>
                <Badge variant="outline" className="ml-2 text-xs bg-yellow-500/10 text-yellow-400 border-yellow-500/30">
                  BETA
                </Badge>
              </CardTitle>
              <CardDescription>
                Monitor and respond to security threats in real-time
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-96">
                <div className="space-y-3">
                  {alerts.length === 0 ? (
                    <div className="text-center text-muted-foreground py-8">
                      <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No security alerts</p>
                      <p className="text-sm">System is secure</p>
                    </div>
                  ) : (
                    alerts.map((alert) => (
                      <div
                        key={alert.id}
                        className={`p-4 rounded-lg border transition-colors cursor-pointer ${
                          alert.resolved 
                            ? 'border-border bg-muted/30' 
                            : 'border-border bg-card hover:bg-accent/50'
                        } ${selectedAlert === alert.id ? 'ring-2 ring-primary' : ''}`}
                        onClick={() => setSelectedAlert(selectedAlert === alert.id ? null : alert.id)}
                      >
                        <div className="flex items-start justify-between">
                          <div className="flex items-start space-x-3 flex-1">
                            <div className="flex flex-col items-center space-y-1">
                              {getSeverityIcon(alert.severity)}
                              {alert.resolved ? (
                                <CheckCircle className="h-4 w-4 text-success" />
                              ) : (
                                <div className="w-2 h-2 rounded-full bg-destructive animate-pulse" />
                              )}
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center space-x-2 mb-1">
                                <h4 className="font-medium text-foreground">{alert.title}</h4>
                                <Badge className={getSeverityColor(alert.severity)}>
                                  {alert.severity}
                                </Badge>
                                {alert.resolved && (
                                  <Badge variant="outline" className="text-success border-success">
                                    Resolved
                                  </Badge>
                                )}
                              </div>
                              <p className="text-sm text-muted-foreground mb-2">
                                {alert.description}
                              </p>
                              
                              {selectedAlert === alert.id && (
                                <div className="mt-3 space-y-2 text-xs text-muted-foreground">
                                  {alert.source_ip && (
                                    <div className="flex items-center space-x-2">
                                      <Globe className="h-3 w-3" />
                                      <span>IP: {alert.source_ip}</span>
                                    </div>
                                  )}
                                  {alert.location && (
                                    <div className="flex items-center space-x-2">
                                      <MapPin className="h-3 w-3" />
                                      <span>Location: {alert.location}</span>
                                    </div>
                                  )}
                                  {alert.user_agent && (
                                    <div className="flex items-center space-x-2">
                                      <Monitor className="h-3 w-3" />
                                      <span>User Agent: {alert.user_agent}</span>
                                    </div>
                                  )}
                                </div>
                              )}
                              
                              <div className="flex items-center justify-between mt-2">
                                <span className="text-xs text-muted-foreground">
                                  {formatDistanceToNow(new Date(alert.timestamp), { addSuffix: true })}
                                </span>
                                {!alert.resolved && (
                                  <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      resolveAlert(alert.id);
                                    }}
                                    className="h-6 px-2 text-xs"
                                  >
                                    <CheckCircle className="h-3 w-3 mr-1" />
                                    Resolve
                                  </Button>
                                )}
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="sessions" className="space-y-4">
          <Card className="card-cyber">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Monitor className="h-5 w-5 text-primary" />
                <span>Active Sessions</span>
                <Badge variant="outline" className="ml-2 text-xs bg-yellow-500/10 text-yellow-400 border-yellow-500/30">
                  BETA
                </Badge>
              </CardTitle>
              <CardDescription>
                Monitor and manage user sessions across devices
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {sessions.map((session) => (
                  <div
                    key={session.id}
                    className="p-4 rounded-lg border border-border bg-card hover:bg-accent/50 transition-colors"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <div className="flex items-center space-x-2">
                          {session.user_agent.includes('Mobile') ? (
                            <Smartphone className="h-5 w-5 text-info" />
                          ) : (
                            <Monitor className="h-5 w-5 text-primary" />
                          )}
                          {session.is_current && (
                            <Badge variant="outline" className="text-success border-success">
                              <Wifi className="h-3 w-3 mr-1" />
                              Current
                            </Badge>
                          )}
                        </div>
                        <div>
                          <p className="font-medium text-foreground">{session.user_agent}</p>
                          <div className="flex items-center space-x-4 text-sm text-muted-foreground">
                            <span className="flex items-center space-x-1">
                              <Globe className="h-3 w-3" />
                              <span>{session.ip_address}</span>
                            </span>
                            <span className="flex items-center space-x-1">
                              <MapPin className="h-3 w-3" />
                              <span>{session.location}</span>
                            </span>
                            <span className="flex items-center space-x-1">
                              <Clock className="h-3 w-3" />
                              <span>
                                {formatDistanceToNow(new Date(session.last_activity), { addSuffix: true })}
                              </span>
                            </span>
                          </div>
                        </div>
                      </div>
                      {!session.is_current && (
                        <Button
                          variant="destructive"
                          size="sm"
                          onClick={() => terminateSession(session.id)}
                          className="h-8 px-3"
                        >
                          <X className="h-3 w-3 mr-1" />
                          Terminate
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="activity" className="space-y-4">
          <Card className="card-cyber">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Activity className="h-5 w-5 text-accent" />
                <span>Security Activity Log</span>
              </CardTitle>
              <CardDescription>
                Recent security events and system activities
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <div className="text-center text-muted-foreground py-8">
                  <Lock className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>Security activity monitoring</p>
                  <p className="text-sm">All activities are logged and monitored</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};