import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Progress } from '@/components/ui/progress';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { 
  Bell, AlertTriangle, CheckCircle, Clock, User, 
  TrendingUp, Zap, Shield, Activity, Play, Pause,
  Settings, Send, RefreshCw, Archive, ChevronUp,
  Eye, MessageSquare, Phone, Mail
} from 'lucide-react';
import { useAlertManager } from '@/hooks/useAlertManager';
import { formatDistanceToNow } from 'date-fns';

export const AlertDashboard = () => {
  const { 
    alerts, 
    rules, 
    loading, 
    processing, 
    metrics,
    updateAlertStatus,
    processRules,
    sendTestNotification,
    toggleRule,
    escalateAlert,
    createAlert
  } = useAlertManager();

  const [selectedAlert, setSelectedAlert] = useState<string | null>(null);
  const [testChannel, setTestChannel] = useState('email');
  const [testRecipient, setTestRecipient] = useState('');

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'bg-destructive text-destructive-foreground';
      case 'HIGH': return 'bg-warning text-warning-foreground';
      case 'MEDIUM': return 'bg-info text-info-foreground';
      case 'LOW': return 'bg-success text-success-foreground';
      default: return 'bg-secondary text-secondary-foreground';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'OPEN': return 'bg-destructive text-destructive-foreground';
      case 'ACKNOWLEDGED': return 'bg-warning text-warning-foreground';
      case 'INVESTIGATING': return 'bg-info text-info-foreground';
      case 'RESOLVED': return 'bg-success text-success-foreground';
      case 'SUPPRESSED': return 'bg-muted text-muted-foreground';
      default: return 'bg-secondary text-secondary-foreground';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'OPEN': return <AlertTriangle className="h-4 w-4" />;
      case 'ACKNOWLEDGED': return <Eye className="h-4 w-4" />;
      case 'INVESTIGATING': return <Activity className="h-4 w-4" />;
      case 'RESOLVED': return <CheckCircle className="h-4 w-4" />;
      case 'SUPPRESSED': return <Archive className="h-4 w-4" />;
      default: return <Clock className="h-4 w-4" />;
    }
  };

  const isOverdue = (alert: any) => {
    return alert.status === 'OPEN' && new Date(alert.sla_deadline).getTime() < Date.now();
  };

  const handleCreateTestAlert = async () => {
    await createAlert({
      title: 'Test Alert - System Verification',
      description: 'This is a test alert to verify the alerting system functionality.',
      severity: 'MEDIUM',
      alert_type: 'test',
      source_type: 'manual',
      risk_score: 45,
      confidence_score: 90
    });
  };

  const handleTestNotification = async () => {
    if (!testRecipient) return;
    await sendTestNotification(testChannel, testRecipient);
    setTestRecipient('');
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <RefreshCw className="h-6 w-6 animate-spin text-primary" />
        <span className="ml-2 text-foreground">Loading alert system...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Alert Metrics Overview */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Total Alerts</p>
                <p className="text-2xl font-bold text-foreground">{metrics.total}</p>
              </div>
              <Bell className="h-8 w-8 text-primary" />
            </div>
          </CardContent>
        </Card>

        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Open Alerts</p>
                <p className="text-2xl font-bold text-destructive">{metrics.open}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-destructive" />
            </div>
          </CardContent>
        </Card>

        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Critical Alerts</p>
                <p className="text-2xl font-bold text-destructive">{metrics.critical}</p>
              </div>
              <Shield className="h-8 w-8 text-destructive" />
            </div>
          </CardContent>
        </Card>

        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Overdue</p>
                <p className="text-2xl font-bold text-warning">{metrics.overdue}</p>
              </div>
              <Clock className="h-8 w-8 text-warning" />
            </div>
          </CardContent>
        </Card>

        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Avg Risk Score</p>
                <p className="text-2xl font-bold text-info">{metrics.avgRiskScore}</p>
              </div>
              <TrendingUp className="h-8 w-8 text-info" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Alert Management Interface */}
      <Card className="card-cyber">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center space-x-2">
                <Bell className="h-5 w-5 text-primary" />
                <span>Alert Management System</span>
              </CardTitle>
              <CardDescription>
                Real-time security alert monitoring and response coordination
              </CardDescription>
            </div>
            <div className="flex items-center space-x-2">
              <Button
                variant="outline"
                size="sm"
                onClick={handleCreateTestAlert}
                disabled={processing}
              >
                <Zap className="h-4 w-4 mr-2" />
                Test Alert
              </Button>
              <Button
                onClick={() => processRules()}
                disabled={processing}
                className="bg-primary hover:bg-primary/90"
              >
                {processing ? (
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <Play className="h-4 w-4 mr-2" />
                )}
                Process Rules
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="alerts" className="space-y-4">
            <TabsList className="bg-card border border-border">
              <TabsTrigger value="alerts" className="flex items-center space-x-2">
                <AlertTriangle className="h-4 w-4" />
                <span>Active Alerts</span>
                {metrics.open > 0 && (
                  <Badge variant="destructive" className="ml-1 text-xs">
                    {metrics.open}
                  </Badge>
                )}
              </TabsTrigger>
              <TabsTrigger value="rules" className="flex items-center space-x-2">
                <Settings className="h-4 w-4" />
                <span>Alert Rules</span>
              </TabsTrigger>
              <TabsTrigger value="notifications" className="flex items-center space-x-2">
                <Send className="h-4 w-4" />
                <span>Notifications</span>
              </TabsTrigger>
              <TabsTrigger value="analytics" className="flex items-center space-x-2">
                <Activity className="h-4 w-4" />
                <span>Analytics</span>
              </TabsTrigger>
            </TabsList>

            <TabsContent value="alerts" className="space-y-4">
              <ScrollArea className="h-96">
                <div className="space-y-3">
                  {alerts.length === 0 ? (
                    <div className="text-center text-muted-foreground py-8">
                      <Bell className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No alerts to display</p>
                      <p className="text-sm">System is monitoring for security events</p>
                    </div>
                  ) : (
                    alerts.map((alert) => (
                      <div
                        key={alert.id}
                        className={`p-4 rounded-lg border transition-colors cursor-pointer ${
                          selectedAlert === alert.id 
                            ? 'border-primary bg-accent/50' 
                            : 'border-border bg-card hover:bg-accent/30'
                        } ${isOverdue(alert) ? 'border-destructive/50 bg-destructive/10' : ''}`}
                        onClick={() => setSelectedAlert(selectedAlert === alert.id ? null : alert.id)}
                      >
                        <div className="flex items-start justify-between">
                          <div className="flex items-start space-x-3 flex-1">
                            <div className="flex flex-col items-center space-y-1">
                              {getStatusIcon(alert.status)}
                              {alert.escalated && (
                                <ChevronUp className="h-3 w-3 text-destructive animate-pulse" />
                              )}
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center space-x-2 mb-1">
                                <h4 className="font-medium text-foreground truncate">{alert.title}</h4>
                                <Badge className={getSeverityColor(alert.severity)}>
                                  {alert.severity}
                                </Badge>
                                <Badge className={getStatusColor(alert.status)}>
                                  {alert.status}
                                </Badge>
                                {isOverdue(alert) && (
                                  <Badge variant="destructive" className="animate-pulse">
                                    OVERDUE
                                  </Badge>
                                )}
                              </div>
                              <p className="text-sm text-muted-foreground mb-2 line-clamp-2">
                                {alert.description}
                              </p>
                              
                              {selectedAlert === alert.id && (
                                <div className="mt-3 space-y-3">
                                  <div className="grid grid-cols-2 gap-4 text-xs">
                                    <div>
                                      <span className="font-medium">Risk Score:</span> {alert.risk_score}/100
                                    </div>
                                    <div>
                                      <span className="font-medium">Confidence:</span> {alert.confidence_score}%
                                    </div>
                                    <div>
                                      <span className="font-medium">Source:</span> {alert.source_type}
                                    </div>
                                    <div>
                                      <span className="font-medium">SLA Deadline:</span> {formatDistanceToNow(new Date(alert.sla_deadline), { addSuffix: true })}
                                    </div>
                                  </div>
                                  
                                  <div className="flex items-center space-x-2">
                                    {alert.status === 'OPEN' && (
                                      <Button
                                        variant="outline"
                                        size="sm"
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          updateAlertStatus(alert.id, 'ACKNOWLEDGED');
                                        }}
                                        className="h-7 px-3 text-xs"
                                      >
                                        <Eye className="h-3 w-3 mr-1" />
                                        Acknowledge
                                      </Button>
                                    )}
                                    
                                    {(alert.status === 'ACKNOWLEDGED' || alert.status === 'INVESTIGATING') && (
                                      <Button
                                        variant="outline"
                                        size="sm"
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          updateAlertStatus(alert.id, 'RESOLVED');
                                        }}
                                        className="h-7 px-3 text-xs"
                                      >
                                        <CheckCircle className="h-3 w-3 mr-1" />
                                        Resolve
                                      </Button>
                                    )}
                                    
                                    {alert.status !== 'RESOLVED' && !alert.escalated && (
                                      <Button
                                        variant="destructive"
                                        size="sm"
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          escalateAlert(alert.id);
                                        }}
                                        className="h-7 px-3 text-xs"
                                      >
                                        <ChevronUp className="h-3 w-3 mr-1" />
                                        Escalate
                                      </Button>
                                    )}
                                  </div>
                                </div>
                              )}
                              
                              <div className="flex items-center justify-between mt-2">
                                <span className="text-xs text-muted-foreground">
                                  {formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}
                                </span>
                                <div className="flex items-center space-x-2">
                                  {alert.escalation_level > 0 && (
                                    <Badge variant="outline" className="text-xs">
                                      Level {alert.escalation_level}
                                    </Badge>
                                  )}
                                  <Badge variant="outline" className="text-xs">
                                    Risk: {alert.risk_score}
                                  </Badge>
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </ScrollArea>
            </TabsContent>

            <TabsContent value="rules" className="space-y-4">
              <div className="space-y-3">
                {rules.map((rule) => (
                  <Card key={rule.id} className="card-cyber">
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => toggleRule(rule.id, !rule.enabled)}
                            className="p-1"
                          >
                            {rule.enabled ? (
                              <Play className="h-4 w-4 text-success" />
                            ) : (
                              <Pause className="h-4 w-4 text-muted-foreground" />
                            )}
                          </Button>
                          <div>
                            <h4 className="font-medium text-foreground">{rule.name}</h4>
                            <p className="text-sm text-muted-foreground">{rule.description}</p>
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          <Badge className={getSeverityColor(rule.severity)}>
                            {rule.severity}
                          </Badge>
                          <Badge variant="outline" className="text-xs">
                            {rule.trigger_count} triggers
                          </Badge>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </TabsContent>

            <TabsContent value="notifications" className="space-y-4">
              <Card className="card-cyber">
                <CardHeader>
                  <CardTitle className="text-sm">Test Notification System</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center space-x-2">
                    <Select value={testChannel} onValueChange={setTestChannel}>
                      <SelectTrigger className="w-32">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="email">
                          <div className="flex items-center space-x-2">
                            <Mail className="h-4 w-4" />
                            <span>Email</span>
                          </div>
                        </SelectItem>
                        <SelectItem value="sms">
                          <div className="flex items-center space-x-2">
                            <Phone className="h-4 w-4" />
                            <span>SMS</span>
                          </div>
                        </SelectItem>
                        <SelectItem value="webhook">
                          <div className="flex items-center space-x-2">
                            <Zap className="h-4 w-4" />
                            <span>Webhook</span>
                          </div>
                        </SelectItem>
                      </SelectContent>
                    </Select>
                    <Input
                      placeholder={testChannel === 'email' ? 'Enter email address' : testChannel === 'sms' ? 'Enter phone number' : 'Enter webhook URL'}
                      value={testRecipient}
                      onChange={(e) => setTestRecipient(e.target.value)}
                      className="flex-1"
                    />
                    <Button
                      onClick={handleTestNotification}
                      disabled={!testRecipient}
                      size="sm"
                    >
                      <Send className="h-4 w-4 mr-2" />
                      Send Test
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="analytics" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Card className="card-cyber">
                  <CardHeader>
                    <CardTitle className="text-sm">Alert Distribution</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      <div>
                        <div className="flex justify-between text-sm mb-1">
                          <span className="text-muted-foreground">Critical</span>
                          <span className="text-foreground">{metrics.critical}</span>
                        </div>
                        <Progress value={(metrics.critical / Math.max(metrics.total, 1)) * 100} className="h-2" />
                      </div>
                      <div>
                        <div className="flex justify-between text-sm mb-1">
                          <span className="text-muted-foreground">High</span>
                          <span className="text-foreground">{metrics.high}</span>
                        </div>
                        <Progress value={(metrics.high / Math.max(metrics.total, 1)) * 100} className="h-2" />
                      </div>
                      <div>
                        <div className="flex justify-between text-sm mb-1">
                          <span className="text-muted-foreground">Medium</span>
                          <span className="text-foreground">{metrics.medium}</span>
                        </div>
                        <Progress value={(metrics.medium / Math.max(metrics.total, 1)) * 100} className="h-2" />
                      </div>
                      <div>
                        <div className="flex justify-between text-sm mb-1">
                          <span className="text-muted-foreground">Low</span>
                          <span className="text-foreground">{metrics.low}</span>
                        </div>
                        <Progress value={(metrics.low / Math.max(metrics.total, 1)) * 100} className="h-2" />
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card className="card-cyber">
                  <CardHeader>
                    <CardTitle className="text-sm">Response Metrics</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-muted-foreground">Response Rate</span>
                        <Badge variant="outline" className="text-success border-success">
                          {metrics.total > 0 ? Math.round(((metrics.acknowledged + metrics.resolved) / metrics.total) * 100) : 0}%
                        </Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-muted-foreground">Resolution Rate</span>
                        <Badge variant="outline" className="text-info border-info">
                          {metrics.total > 0 ? Math.round((metrics.resolved / metrics.total) * 100) : 0}%
                        </Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-muted-foreground">Overdue Alerts</span>
                        <Badge 
                          variant="outline" 
                          className={metrics.overdue > 0 ? 'text-destructive border-destructive' : 'text-success border-success'}
                        >
                          {metrics.overdue}
                        </Badge>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};