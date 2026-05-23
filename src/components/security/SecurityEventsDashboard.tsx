import { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Progress } from '@/components/ui/progress';
import { 
  Shield, 
  AlertTriangle, 
  Activity, 
  Eye,
  Search,
  Filter,
  Download,
  RefreshCw,
  TrendingUp,
  TrendingDown,
  Clock,
  MapPin,
  User,
  Lock,
  Settings,
  Zap
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';
import { useAdvancedSecurityMonitor } from '@/hooks/useAdvancedSecurityMonitor';
import { ContextMenuGuide } from '@/components/ui/context-menu-guide';
import { FloatingAIAssistant } from '@/components/FloatingAIAssistant';

interface SecurityEvent {
  id: string;
  event_type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  details: any;
  source_system: string;
  created_at: string;
  resolved: boolean;
  resolved_at?: string;
  resolved_by?: string;
}

interface ThreatIndicator {
  type: string;
  value: string;
  risk_level: 'low' | 'medium' | 'high';
  first_seen: string;
  last_seen: string;
  occurrences: number;
}

export const SecurityEventsDashboard = () => {
  const [securityEvents, setSecurityEvents] = useState<SecurityEvent[]>([]);
  const [threatIndicators, setThreatIndicators] = useState<ThreatIndicator[]>([]);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [timeFilter, setTimeFilter] = useState<string>('24h');
  const [activeTab, setActiveTab] = useState('events');
  
  const { toast } = useToast();
  const { user } = useAuth();
  
  // Enhanced security monitoring
  const { 
    threats, 
    metrics, 
    isMonitoring, 
    validateUserAction,
    startMonitoring, 
    stopMonitoring 
  } = useAdvancedSecurityMonitor();

  useEffect(() => {
    if (user) {
      loadSecurityEvents();
      loadThreatIndicators();
      
      // Set up real-time subscriptions
      const eventsSubscription = supabase
        .channel('security_events_changes')
        .on('postgres_changes', 
          { event: '*', schema: 'public', table: 'security_events' },
          (payload) => {
            console.log('Security event change:', payload);
            loadSecurityEvents();
          }
        )
        .subscribe();

      return () => {
        supabase.removeChannel(eventsSubscription);
      };
    }
  }, [user, severityFilter, timeFilter]);

  const loadSecurityEvents = async () => {
    setLoading(true);
    try {
      let query = supabase
        .from('security_events')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(100);

      // Apply severity filter
      if (severityFilter !== 'all') {
        query = query.eq('severity', severityFilter);
      }

      // Apply time filter
      const timeFilters = {
        '1h': new Date(Date.now() - 60 * 60 * 1000),
        '24h': new Date(Date.now() - 24 * 60 * 60 * 1000),
        '7d': new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
        '30d': new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
      };

      if (timeFilter !== 'all' && timeFilters[timeFilter as keyof typeof timeFilters]) {
        query = query.gte('created_at', timeFilters[timeFilter as keyof typeof timeFilters].toISOString());
      }

      const { data, error } = await query;
      
      if (error) throw error;
      setSecurityEvents((data || []).map(event => ({
        ...event,
        severity: event.severity as 'low' | 'medium' | 'high' | 'critical'
      })));
    } catch (error) {
      console.error('Error loading security events:', error);
      toast({
        title: "Error",
        description: "Failed to load security events",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const loadThreatIndicators = async () => {
    try {
      const { data, error } = await supabase
        .from('threat_intelligence')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(50);
      
      if (error) throw error;
      
      // Transform to ThreatIndicator format
      const indicators: ThreatIndicator[] = (data || []).map(item => ({
        type: item.indicator_type,
        value: item.indicator_value,
        risk_level: item.threat_level?.toLowerCase() as 'low' | 'medium' | 'high' || 'medium',
        first_seen: item.created_at,
        last_seen: item.updated_at,
        occurrences: 1 // In production, this would be calculated
      }));
      
      setThreatIndicators(indicators);
    } catch (error) {
      console.error('Error loading threat indicators:', error);
    }
  };

  const resolveEvent = async (eventId: string) => {
    try {
      const { error } = await supabase
        .from('security_events')
        .update({
          resolved: true,
          resolved_at: new Date().toISOString(),
          resolved_by: user?.id
        })
        .eq('id', eventId);

      if (error) throw error;

      // Update local state
      setSecurityEvents(prev => 
        prev.map(event => 
          event.id === eventId 
            ? { ...event, resolved: true, resolved_at: new Date().toISOString() }
            : event
        )
      );

      toast({
        title: "Event Resolved",
        description: "Security event has been marked as resolved",
        variant: "default"
      });
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const exportEvents = async () => {
    try {
      const csvContent = [
        ['Timestamp', 'Event Type', 'Severity', 'Source', 'Resolved', 'Description'].join(','),
        ...securityEvents.map(event => [
          new Date(event.created_at).toISOString(),
          event.event_type,
          event.severity,
          event.source_system || 'Unknown',
          event.resolved ? 'Yes' : 'No',
          JSON.stringify(event.details).replace(/,/g, ';')
        ].join(','))
      ].join('\n');

      const blob = new Blob([csvContent], { type: 'text/csv' });
      const url = globalThis.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `security-events-${new Date().toISOString().split('T')[0]}.csv`;
      a.click();
      globalThis.URL.revokeObjectURL(url);

      toast({
        title: "Export Complete",
        description: "Security events exported successfully",
        variant: "default"
      });
    } catch (error: any) {
      toast({
        title: "Export Failed",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-50 border-red-200';
      case 'high': return 'text-orange-600 bg-orange-50 border-orange-200';
      case 'medium': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'low': return 'text-green-600 bg-green-50 border-green-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'high': return 'text-red-600';
      case 'medium': return 'text-yellow-600';
      case 'low': return 'text-green-600';
      default: return 'text-gray-600';
    }
  };

  const filteredEvents = securityEvents.filter(event =>
    searchTerm === '' ||
    event.event_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
    event.source_system?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const eventStats = {
    total: filteredEvents.length,
    resolved: filteredEvents.filter(e => e.resolved).length,
    critical: filteredEvents.filter(e => e.severity === 'critical').length,
    high: filteredEvents.filter(e => e.severity === 'high').length
  };

  const handleValidateAction = async (action: string, resource: string) => {
    const isValid = await validateUserAction(action, resource);
    
    if (isValid) {
      toast({
        title: "Action Validated",
        description: `${action} on ${resource} is authorized`,
        variant: "default"
      });
    } else {
      toast({
        title: "Action Blocked",
        description: `${action} on ${resource} was blocked for security reasons`,
        variant: "destructive"
      });
    }
  };

  const getRiskLevel = () => {
    if (metrics.riskScore >= 80) return { level: 'Critical', color: 'bg-destructive', text: 'text-destructive-foreground' };
    if (metrics.riskScore >= 60) return { level: 'High', color: 'bg-amber-500', text: 'text-amber-900' };
    if (metrics.riskScore >= 40) return { level: 'Medium', color: 'bg-yellow-500', text: 'text-yellow-900' };
    if (metrics.riskScore >= 20) return { level: 'Low', color: 'bg-blue-500', text: 'text-blue-900' };
    return { level: 'Minimal', color: 'bg-emerald-500', text: 'text-emerald-900' };
  };

  const riskLevel = getRiskLevel();

  return (
    <div className="space-y-6">
      {/* Enhanced Security Monitoring Status */}
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold flex items-center gap-2">
          <Shield className="h-8 w-8 text-primary" />
          Security Events Dashboard
        </h1>
        <div className="flex items-center gap-2">
          <ContextMenuGuide
            feature="Security Monitoring Controls"
            description="Real-time threat detection and security event monitoring with advanced AI analysis"
            menuItems={[
              {
                label: "Start Continuous Monitoring",
                description: "Enable 24/7 automated threat detection and analysis",
                action: () => !isMonitoring && startMonitoring(),
                icon: <Activity className="h-3 w-3" />,
                type: 'action'
              },
              {
                label: "Configure Alert Thresholds",
                description: "Set custom sensitivity levels for threat detection",
                action: () => console.log('Configure thresholds'),
                icon: <Settings className="h-3 w-3" />,
                type: 'action'
              },
              {
                label: "View Monitoring History",
                description: "Review past monitoring sessions and findings",
                action: () => setActiveTab('analytics'),
                icon: <Eye className="h-3 w-3" />,
                type: 'action'
              }
            ]}
          >
            <Badge 
              variant={isMonitoring ? "default" : "secondary"}
              className="cursor-pointer hover:bg-primary/20 transition-colors"
            >
              {isMonitoring ? "Monitoring Active" : "Monitoring Inactive"}
            </Badge>
          </ContextMenuGuide>
          
          <ContextMenuGuide
            feature="Threat Monitoring Toggle"
            description="Start or stop real-time security monitoring with one click"
            menuItems={[
              {
                label: isMonitoring ? "Stop Monitoring" : "Start Monitoring",
                description: isMonitoring 
                  ? "Pause automated threat detection (not recommended)" 
                  : "Begin continuous security monitoring and threat analysis",
                action: () => isMonitoring ? stopMonitoring() : startMonitoring(),
                icon: <Activity className="h-3 w-3" />,
                type: 'action'
              },
              {
                label: "Monitoring Best Practices",
                description: "Learn about optimal security monitoring strategies",
                action: () => globalThis.open('/docs/security-monitoring', '_blank'),
                icon: <Shield className="h-3 w-3" />,
                type: 'link'
              }
            ]}
          >
            <Button
              onClick={isMonitoring ? stopMonitoring : startMonitoring}
              variant={isMonitoring ? "destructive" : "default"}
              size="sm"
              className="transition-all duration-200 hover:scale-105"
            >
              <Activity className="h-4 w-4 mr-2" />
              {isMonitoring ? "Stop" : "Start"} Monitoring
            </Button>
          </ContextMenuGuide>
        </div>
      </div>

      {/* Risk Assessment Alert */}
      {metrics.riskScore >= 60 && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            High security risk detected (Score: {metrics.riskScore}/100). 
            {threats.filter(t => t.severity === 'HIGH' || t.severity === 'CRITICAL').length} critical threats require immediate attention.
          </AlertDescription>
        </Alert>
      )}

      {/* Enhanced Security Metrics Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <ContextMenuGuide
          feature="Risk Score Analysis"
          description="AI-powered risk assessment based on current threats and vulnerabilities"
          menuItems={[
            {
              label: "View Risk Breakdown",
              description: "See detailed analysis of risk factors",
              action: () => setActiveTab('analytics'),
              icon: <TrendingUp className="h-3 w-3" />,
              type: 'action'
            },
            {
              label: "Risk Mitigation Actions",
              description: "Get recommendations to reduce risk score",
              action: () => handleValidateAction('risk_mitigation', 'security_metrics'),
              icon: <Shield className="h-3 w-3" />,
              type: 'action'
            }
          ]}
        >
          <Card className="hover:shadow-lg transition-all duration-300 cursor-pointer">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Risk Score</CardTitle>
              <AlertTriangle className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{metrics.riskScore}/100</div>
              <Progress value={metrics.riskScore} className="mt-2" />
              <p className={`text-xs mt-2 font-medium ${riskLevel.text}`}>
                {riskLevel.level} Risk
              </p>
            </CardContent>
          </Card>
        </ContextMenuGuide>

        <ContextMenuGuide
          feature="Active Threats Monitor"
          description="Real-time tracking of security threats and incidents in your environment"
          menuItems={[
            {
              label: "View All Threats",
              description: "See detailed list of active security threats",
              action: () => setActiveTab('threats'),
              icon: <Eye className="h-3 w-3" />,
              type: 'action'
            },
            {
              label: "Threat Response Workflow",
              description: "Initiate automated threat response procedures",
              action: () => handleValidateAction('threat_response', 'active_threats'),
              icon: <Zap className="h-3 w-3" />,
              type: 'action'
            }
          ]}
        >
          <Card className="hover:shadow-lg transition-all duration-300 cursor-pointer">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Active Threats</CardTitle>
              <Shield className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{threats.length}</div>
              <p className="text-xs text-muted-foreground">
                {threats.filter(t => t.severity === 'HIGH' || t.severity === 'CRITICAL').length} high/critical
              </p>
            </CardContent>
          </Card>
        </ContextMenuGuide>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Failed Logins</CardTitle>
            <Lock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{metrics.failedLoginAttempts}</div>
            <p className="text-xs text-muted-foreground">Last hour</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Last Scan</CardTitle>
            <Eye className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {metrics.lastSecurityScan ? 
                new Date(metrics.lastSecurityScan).toLocaleTimeString() : 
                'Never'
              }
            </div>
            <p className="text-xs text-muted-foreground">Security scan</p>
          </CardContent>
        </Card>
      </div>

      <Card className="card-cyber">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Activity className="h-5 w-5 text-primary" />
            <span>Security Events & Threat Intelligence</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="events">Security Events</TabsTrigger>
              <TabsTrigger value="threats">Threat Intelligence</TabsTrigger>
              <TabsTrigger value="analytics">Analytics</TabsTrigger>
              <TabsTrigger value="testing">Security Testing</TabsTrigger>
            </TabsList>

            <TabsContent value="events" className="mt-6">
              <div className="space-y-4">
                {/* Controls */}
                <div className="flex flex-col sm:flex-row gap-4">
                  <div className="flex-1">
                    <Input
                      placeholder="Search events..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="w-full"
                    />
                  </div>
                  <Select value={severityFilter} onValueChange={setSeverityFilter}>
                    <SelectTrigger className="w-40">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Severities</SelectItem>
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                    </SelectContent>
                  </Select>
                  <Select value={timeFilter} onValueChange={setTimeFilter}>
                    <SelectTrigger className="w-32">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="1h">Last Hour</SelectItem>
                      <SelectItem value="24h">Last 24h</SelectItem>
                      <SelectItem value="7d">Last 7 Days</SelectItem>
                      <SelectItem value="30d">Last 30 Days</SelectItem>
                      <SelectItem value="all">All Time</SelectItem>
                    </SelectContent>
                  </Select>
                  <Button onClick={loadSecurityEvents} disabled={loading} size="sm" variant="outline">
                    <RefreshCw className="h-4 w-4" />
                  </Button>
                  <Button onClick={exportEvents} size="sm" variant="outline">
                    <Download className="h-4 w-4" />
                  </Button>
                </div>

                {/* Stats */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <Card className="border">
                    <CardContent className="p-3">
                      <div className="text-center">
                        <p className="text-2xl font-bold">{eventStats.total}</p>
                        <p className="text-xs text-muted-foreground">Total Events</p>
                      </div>
                    </CardContent>
                  </Card>
                  <Card className="border">
                    <CardContent className="p-3">
                      <div className="text-center">
                        <p className="text-2xl font-bold text-green-600">{eventStats.resolved}</p>
                        <p className="text-xs text-muted-foreground">Resolved</p>
                      </div>
                    </CardContent>
                  </Card>
                  <Card className="border">
                    <CardContent className="p-3">
                      <div className="text-center">
                        <p className="text-2xl font-bold text-red-600">{eventStats.critical}</p>
                        <p className="text-xs text-muted-foreground">Critical</p>
                      </div>
                    </CardContent>
                  </Card>
                  <Card className="border">
                    <CardContent className="p-3">
                      <div className="text-center">
                        <p className="text-2xl font-bold text-orange-600">{eventStats.high}</p>
                        <p className="text-xs text-muted-foreground">High</p>
                      </div>
                    </CardContent>
                  </Card>
                </div>

                {/* Events List */}
                <div className="space-y-2">
                  {filteredEvents.map((event) => (
                    <Card key={event.id} className="border">
                      <CardContent className="p-4">
                        <div className="flex justify-between items-start">
                          <div className="space-y-2 flex-1">
                            <div className="flex items-center space-x-2">
                              <Badge className={getSeverityColor(event.severity)}>
                                {event.severity.toUpperCase()}
                              </Badge>
                              <span className="font-medium">{event.event_type}</span>
                              {event.resolved && (
                                <Badge variant="secondary">Resolved</Badge>
                              )}
                            </div>
                            
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-sm text-muted-foreground">
                              <div className="flex items-center space-x-1">
                                <Clock className="h-3 w-3" />
                                <span>{new Date(event.created_at).toLocaleString()}</span>
                              </div>
                              <div className="flex items-center space-x-1">
                                <Shield className="h-3 w-3" />
                                <span>{event.source_system || 'System'}</span>
                              </div>
                              {event.details?.ip_address && (
                                <div className="flex items-center space-x-1">
                                  <MapPin className="h-3 w-3" />
                                  <span>{event.details.ip_address}</span>
                                </div>
                              )}
                            </div>
                            
                            {event.details && (
                              <div className="text-sm">
                                <p className="text-muted-foreground">Details:</p>
                                <pre className="text-xs bg-muted p-2 rounded mt-1 overflow-x-auto">
                                  {JSON.stringify(event.details, null, 2)}
                                </pre>
                              </div>
                            )}
                          </div>
                          
                          {!event.resolved && (
                            <Button
                              onClick={() => resolveEvent(event.id)}
                              size="sm"
                              variant="outline"
                            >
                              <Eye className="h-4 w-4 mr-2" />
                              Resolve
                            </Button>
                          )}
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                  
                  {filteredEvents.length === 0 && (
                    <div className="text-center py-8 text-muted-foreground">
                      <Activity className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No security events found</p>
                      <p className="text-sm">Adjust your filters or check back later</p>
                    </div>
                  )}
                </div>
              </div>
            </TabsContent>

            <TabsContent value="threats" className="mt-6">
              <div className="space-y-4">
                <h3 className="text-lg font-semibold">Threat Indicators</h3>
                
                <div className="grid gap-4">
                  {threatIndicators.map((indicator, index) => (
                    <Card key={index} className="border">
                      <CardContent className="p-4">
                        <div className="flex justify-between items-start">
                          <div className="space-y-2">
                            <div className="flex items-center space-x-2">
                              <Badge variant="outline">{indicator.type}</Badge>
                              <span className="font-mono text-sm">{indicator.value}</span>
                              <Badge className={`${getRiskColor(indicator.risk_level)}`}>
                                {indicator.risk_level.toUpperCase()}
                              </Badge>
                            </div>
                            
                            <div className="grid grid-cols-3 gap-4 text-sm text-muted-foreground">
                              <div>
                                <span>First Seen: </span>
                                <span>{new Date(indicator.first_seen).toLocaleDateString()}</span>
                              </div>
                              <div>
                                <span>Last Seen: </span>
                                <span>{new Date(indicator.last_seen).toLocaleDateString()}</span>
                              </div>
                              <div>
                                <span>Occurrences: </span>
                                <span>{indicator.occurrences}</span>
                              </div>
                            </div>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                  
                  {threatIndicators.length === 0 && (
                    <div className="text-center py-8 text-muted-foreground">
                      <AlertTriangle className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No threat indicators available</p>
                      <p className="text-sm">Threat intelligence feeds will populate here</p>
                    </div>
                  )}
                </div>
              </div>
            </TabsContent>

            <TabsContent value="analytics" className="mt-6">
              <div className="space-y-6">
                <h3 className="text-lg font-semibold">Security Analytics</h3>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <Card className="border">
                    <CardHeader>
                      <CardTitle className="text-base">Event Trends</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="flex items-center justify-center h-32">
                        <p className="text-muted-foreground">Analytics visualization would go here</p>
                      </div>
                    </CardContent>
                  </Card>
                  
                  <Card className="border">
                    <CardHeader>
                      <CardTitle className="text-base">Top Event Types</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-2">
                        {['login_failure', 'suspicious_activity', 'session_timeout'].map((type, index) => (
                          <div key={type} className="flex justify-between items-center">
                            <span className="text-sm">{type.replaceAll('_', ' ')}</span>
                            <Badge variant="secondary">{'N/A'}</Badge>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="testing" className="mt-6">
              <div className="space-y-4">
                <h3 className="text-lg font-semibold">Security Action Testing</h3>
                
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Test Security Validations</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <Button 
                        onClick={() => handleValidateAction('read', 'user_profile')}
                        variant="outline"
                        className="h-auto p-4 flex flex-col items-start"
                      >
                        <span className="font-medium">Test Read Access</span>
                        <span className="text-xs text-muted-foreground">Validate read permissions</span>
                      </Button>
                      
                      <Button 
                        onClick={() => handleValidateAction('update', 'security_settings')}
                        variant="outline"
                        className="h-auto p-4 flex flex-col items-start"
                      >
                        <span className="font-medium">Test Update Access</span>
                        <span className="text-xs text-muted-foreground">Validate update permissions</span>
                      </Button>
                      
                      <Button 
                        onClick={() => handleValidateAction('delete', 'critical_data')}
                        variant="outline"
                        className="h-auto p-4 flex flex-col items-start"
                      >
                        <span className="font-medium">Test Delete Access</span>
                        <span className="text-xs text-muted-foreground">Validate delete permissions</span>
                      </Button>
                      
                      <Button 
                        onClick={() => handleValidateAction('admin_escalation', 'user_roles')}
                        variant="outline"
                        className="h-auto p-4 flex flex-col items-start"
                      >
                        <span className="font-medium">Test Admin Escalation</span>
                        <span className="text-xs text-muted-foreground">Test privilege escalation detection</span>
                      </Button>
                    </div>

                    <Alert>
                      <AlertTriangle className="h-4 w-4" />
                      <AlertDescription>
                        These actions test the security monitoring system. 
                        Some actions may be blocked based on your current permissions and will trigger security events.
                      </AlertDescription>
                    </Alert>

                    <div className="space-y-2">
                      <h4 className="font-semibold">Current Security Metrics</h4>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                        <div className="space-y-2">
                          <p><span className="font-medium">Risk Score:</span> {metrics.riskScore}/100</p>
                          <p><span className="font-medium">Failed Login Attempts:</span> {metrics.failedLoginAttempts}</p>
                        </div>
                        <div className="space-y-2">
                          <p><span className="font-medium">Suspicious Activities:</span> {metrics.suspiciousActivities}</p>
                          <p><span className="font-medium">Monitoring Status:</span> {isMonitoring ? 'Active' : 'Inactive'}</p>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* Active Threats from Enhanced Monitoring */}
                {threats.length > 0 && (
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-base">Real-time Threat Detection</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-4">
                        {threats.slice(0, 3).map((threat) => (
                          <div key={threat.id} className="border rounded-lg p-4 space-y-2">
                            <div className="flex items-center justify-between">
                              <Badge variant={threat.severity === 'CRITICAL' ? 'destructive' : 'default'}>
                                {threat.severity}
                              </Badge>
                              <span className="text-sm text-muted-foreground">
                                {threat.timestamp.toLocaleString()}
                              </span>
                            </div>
                            <h4 className="font-semibold">{threat.type.replaceAll('_', ' ').toUpperCase()}</h4>
                            <p className="text-sm text-muted-foreground">{threat.description}</p>
                          </div>
                        ))}
                        {threats.length > 3 && (
                          <p className="text-sm text-muted-foreground text-center">
                            And {threats.length - 3} more threats detected...
                          </p>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                )}
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      {/* AI Assistant for Security Events */}
      <FloatingAIAssistant />
    </div>
  );
};

export default SecurityEventsDashboard;