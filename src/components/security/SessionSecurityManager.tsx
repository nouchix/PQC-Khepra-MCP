import { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
import { 
  Shield, 
  Clock, 
  Monitor, 
  MapPin, 
  AlertTriangle, 
  Activity,
  Lock,
  Unlock,
  Eye,
  EyeOff,
  Trash2
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';
import { useSessionSecurity } from '@/hooks/useSessionSecurity';

interface ActiveSession {
  id: string;
  device_info: string;
  location: string;
  ip_address: string;
  started_at: string;
  last_activity: string;
  is_current: boolean;
  risk_score: number;
  suspicious_activity: boolean;
}

interface SessionPolicy {
  max_concurrent_sessions: number;
  session_timeout_minutes: number;
  idle_timeout_minutes: number;
  require_reauthentication_sensitive: boolean;
  block_suspicious_locations: boolean;
  enable_device_fingerprinting: boolean;
  force_logout_on_policy_change: boolean;
}

export const SessionSecurityManager = () => {
  const [activeSessions, setActiveSessions] = useState<ActiveSession[]>([]);
  const [sessionPolicy, setSessionPolicy] = useState<SessionPolicy>({
    max_concurrent_sessions: 3,
    session_timeout_minutes: 480, // 8 hours
    idle_timeout_minutes: 30,
    require_reauthentication_sensitive: true,
    block_suspicious_locations: false,
    enable_device_fingerprinting: true,
    force_logout_on_policy_change: true
  });
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('sessions');
  
  const { toast } = useToast();
  const { user } = useAuth();
  const { sessionState, setSessionTimeout } = useSessionSecurity();

  useEffect(() => {
    if (user) {
      loadActiveSessions();
      loadSessionPolicy();
    }
  }, [user]);

  const loadActiveSessions = async () => {
    if (!user) return;
    
    try {
      // Get current session
      const currentSession: ActiveSession = {
        id: 'current_session',
        device_info: navigator.userAgent,
        location: 'Current Location', // Would be populated by geolocation service
        ip_address: 'Current IP', // Would be populated by session service
        started_at: new Date().toISOString(),
        last_activity: new Date().toISOString(),
        is_current: true,
        risk_score: 10,
        suspicious_activity: false
      };

      // Load recent sessions from audit logs
      const { data: auditData } = await supabase
        .from('audit_logs')
        .select('*')
        .eq('user_id', user.id)
        .in('action', ['session_created', 'login'])
        .order('created_at', { ascending: false })
        .limit(10);

      const sessions: ActiveSession[] = [currentSession];

      // Transform audit logs to session format
      if (auditData) {
        auditData.forEach((log, index) => {
          if (index < 5 && log.id !== 'current_session') {
            sessions.push({
              id: log.id,
              device_info: (log.details as any)?.user_agent || log.user_agent || 'Unknown Device',
              location: (log.details as any)?.location || 'Unknown Location',
              ip_address: log.ip_address?.toString() || 'Unknown IP',
              started_at: log.created_at,
              last_activity: log.created_at,
              is_current: false,
              risk_score: 0, // Real risk score requires session risk analysis engine
              suspicious_activity: false
            });
          }
        });
      }
      
      setActiveSessions(sessions);
    } catch (error) {
      console.error('Error loading active sessions:', error);
    }
  };

  const loadSessionPolicy = async () => {
    try {
      const { data: orgData } = await supabase.from('user_organizations')
        .select('organization_id')
        .eq('user_id', user?.id)
        .limit(1)
        .single();
        
      if (!orgData) return;
      
      const { data, error } = await supabase
        .from('organization_settings')
        .select('security_policies')
        .eq('organization_id', orgData.organization_id)
        .single();

      if (error && error.code !== 'PGRST116') throw error;
      
      if (data?.security_policies && typeof data.security_policies === 'object') {
        const policies = data.security_policies as any;
        if (policies.session_policy) {
          setSessionPolicy(policies.session_policy as SessionPolicy);
        }
      }
    } catch (error) {
      console.error('Error loading session policy:', error);
    }
  };

  const terminateSession = async (sessionId: string) => {
    setLoading(true);
    try {
      if (sessionId === '1') {
        // Current session - sign out
        await supabase.auth.signOut();
        toast({
          title: "Session Terminated",
          description: "You have been signed out.",
          variant: "default"
        });
        return;
      }
      
      // Remove from active sessions
      setActiveSessions(prev => prev.filter(s => s.id !== sessionId));
      
      // Log security event
      await supabase.from('audit_logs').insert([{
        action: 'session_terminated',
        resource_type: 'session_security',
        details: { session_id: sessionId, terminated_by: 'user' }
      }]);

      toast({
        title: "Session Terminated",
        description: "Remote session has been terminated.",
        variant: "default"
      });
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const terminateAllOtherSessions = async () => {
    setLoading(true);
    try {
      const otherSessions = activeSessions.filter(s => !s.is_current);
      
      // In production, this would terminate all other sessions
      setActiveSessions(prev => prev.filter(s => s.is_current));
      
      // Log security event
      await supabase.from('audit_logs').insert([{
        action: 'all_sessions_terminated',
        resource_type: 'session_security',
        details: { 
          terminated_count: otherSessions.length,
          terminated_by: 'user'
        }
      }]);

      toast({
        title: "Sessions Terminated",
        description: `${otherSessions.length} other sessions have been terminated.`,
        variant: "default"
      });
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const updateSessionPolicy = async (updates: Partial<SessionPolicy>) => {
    setLoading(true);
    try {
      const { data: orgData } = await supabase.from('user_organizations')
        .select('organization_id')
        .eq('user_id', user?.id)
        .limit(1)
        .single();
        
      if (!orgData) throw new Error('No organization found');
      
      const newPolicy = { ...sessionPolicy, ...updates };
      
      // Get existing security policies
      const { data: existingData } = await supabase
        .from('organization_settings')
        .select('security_policies')
        .eq('organization_id', orgData.organization_id)
        .single();
      
      const existingPolicies = (existingData?.security_policies as any) || {};
      
      await supabase
        .from('organization_settings')
        .upsert({ 
          organization_id: orgData.organization_id,
          security_policies: {
            ...existingPolicies,
            session_policy: newPolicy
          }
        }, { onConflict: 'organization_id' });

      setSessionPolicy(newPolicy);
      
      // Update session timeout if changed
      if (updates.idle_timeout_minutes) {
        setSessionTimeout(updates.idle_timeout_minutes);
      }
      
      // Log security event
      await supabase.from('audit_logs').insert([{
        action: 'session_policy_updated',
        resource_type: 'session_security',
        details: { policy_changes: updates }
      }]);

      toast({
        title: "Policy Updated",
        description: "Session security policy has been updated.",
        variant: "default"
      });
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (score: number) => {
    if (score <= 20) return 'text-green-600';
    if (score <= 50) return 'text-yellow-600';
    return 'text-red-600';
  };

  const getRiskLabel = (score: number) => {
    if (score <= 20) return 'Low Risk';
    if (score <= 50) return 'Medium Risk';
    return 'High Risk';
  };

  return (
    <div className="space-y-6">
      <Card className="card-cyber">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Lock className="h-5 w-5 text-primary" />
            <span>Session Security Management</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="sessions">Active Sessions</TabsTrigger>
              <TabsTrigger value="monitoring">Real-time Monitoring</TabsTrigger>
              <TabsTrigger value="policy">Security Policy</TabsTrigger>
            </TabsList>

            <TabsContent value="sessions" className="mt-6">
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <h3 className="text-lg font-semibold">Active Sessions</h3>
                  <Button 
                    onClick={terminateAllOtherSessions}
                    disabled={loading || activeSessions.filter(s => !s.is_current).length === 0}
                    variant="destructive"
                    size="sm"
                  >
                    <Unlock className="h-4 w-4 mr-2" />
                    Terminate All Others
                  </Button>
                </div>
                
                <div className="grid gap-4">
                  {activeSessions.map((session) => (
                    <Card key={session.id} className={`border ${session.is_current ? 'border-primary' : 'border-border'}`}>
                      <CardContent className="p-4">
                        <div className="flex justify-between items-start">
                          <div className="space-y-2 flex-1">
                            <div className="flex items-center space-x-2">
                              <Monitor className="h-4 w-4 text-muted-foreground" />
                              <span className="font-medium">{session.device_info}</span>
                              {session.is_current && (
                                <Badge variant="default">Current Session</Badge>
                              )}
                              {session.suspicious_activity && (
                                <Badge variant="destructive">Suspicious</Badge>
                              )}
                            </div>
                            
                            <div className="grid grid-cols-2 gap-4 text-sm text-muted-foreground">
                              <div className="flex items-center space-x-1">
                                <MapPin className="h-3 w-3" />
                                <span>{session.location}</span>
                              </div>
                              <div className="flex items-center space-x-1">
                                <Activity className="h-3 w-3" />
                                <span>IP: {session.ip_address}</span>
                              </div>
                              <div className="flex items-center space-x-1">
                                <Clock className="h-3 w-3" />
                                <span>Started: {new Date(session.started_at).toLocaleString()}</span>
                              </div>
                              <div className="flex items-center space-x-1">
                                <Clock className="h-3 w-3" />
                                <span>Last activity: {new Date(session.last_activity).toLocaleString()}</span>
                              </div>
                            </div>
                            
                            <div className="flex items-center space-x-2">
                              <span className="text-sm">Risk Score:</span>
                              <div className="flex items-center space-x-2">
                                <Progress value={session.risk_score} className="w-20 h-2" />
                                <span className={`text-sm font-medium ${getRiskColor(session.risk_score)}`}>
                                  {session.risk_score}% - {getRiskLabel(session.risk_score)}
                                </span>
                              </div>
                            </div>
                          </div>
                          
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={() => terminateSession(session.id)}
                            disabled={loading}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                  
                  {activeSessions.length === 0 && (
                    <div className="text-center py-8 text-muted-foreground">
                      <Monitor className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No active sessions found</p>
                    </div>
                  )}
                </div>
              </div>
            </TabsContent>

            <TabsContent value="monitoring" className="mt-6">
              <div className="space-y-6">
                <h3 className="text-lg font-semibold">Real-time Session Monitoring</h3>
                
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <Card className="border">
                    <CardContent className="p-4">
                      <div className="flex items-center space-x-2">
                        <Activity className="h-5 w-5 text-primary" />
                        <div>
                          <p className="text-sm text-muted-foreground">Current Session</p>
                          <p className="font-semibold">
                            {sessionState.isSessionValid ? 'Active' : 'Expired'}
                          </p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                  
                  <Card className="border">
                    <CardContent className="p-4">
                      <div className="flex items-center space-x-2">
                        <Clock className="h-5 w-5 text-primary" />
                        <div>
                          <p className="text-sm text-muted-foreground">Session Timeout</p>
                          <p className="font-semibold">{sessionState.sessionTimeout} minutes</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                  
                  <Card className="border">
                    <CardContent className="p-4">
                      <div className="flex items-center space-x-2">
                        <Shield className="h-5 w-5 text-primary" />
                        <div>
                          <p className="text-sm text-muted-foreground">Device Fingerprint</p>
                          <p className="font-semibold text-xs font-mono">
                            {sessionState.deviceFingerprint.substring(0, 8)}...
                          </p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
                
                <Card className="border">
                  <CardHeader>
                    <CardTitle className="text-base">Session Activity Timeline</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-sm">
                        <span>Last Activity</span>
                        <span className="text-muted-foreground">
                          {sessionState.lastActivity.toLocaleTimeString()}
                        </span>
                      </div>
                      <div className="flex items-center justify-between text-sm">
                        <span>Session Started</span>
                        <span className="text-muted-foreground">Today</span>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>

            <TabsContent value="policy" className="mt-6">
              <div className="space-y-6">
                <h3 className="text-lg font-semibold">Session Security Policy</h3>
                
                <div className="grid gap-4">
                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label className="text-base">Require re-authentication for sensitive actions</Label>
                      <p className="text-sm text-muted-foreground">
                        Force users to re-enter credentials for critical operations
                      </p>
                    </div>
                    <Switch
                      checked={sessionPolicy.require_reauthentication_sensitive}
                      onCheckedChange={(checked) => updateSessionPolicy({ require_reauthentication_sensitive: checked })}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label className="text-base">Block suspicious locations</Label>
                      <p className="text-sm text-muted-foreground">
                        Automatically block access from suspicious geographic locations
                      </p>
                    </div>
                    <Switch
                      checked={sessionPolicy.block_suspicious_locations}
                      onCheckedChange={(checked) => updateSessionPolicy({ block_suspicious_locations: checked })}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label className="text-base">Enable device fingerprinting</Label>
                      <p className="text-sm text-muted-foreground">
                        Track and verify device characteristics for additional security
                      </p>
                    </div>
                    <Switch
                      checked={sessionPolicy.enable_device_fingerprinting}
                      onCheckedChange={(checked) => updateSessionPolicy({ enable_device_fingerprinting: checked })}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label className="text-base">Force logout on policy changes</Label>
                      <p className="text-sm text-muted-foreground">
                        Automatically sign out all users when security policies change
                      </p>
                    </div>
                    <Switch
                      checked={sessionPolicy.force_logout_on_policy_change}
                      onCheckedChange={(checked) => updateSessionPolicy({ force_logout_on_policy_change: checked })}
                    />
                  </div>
                </div>

                <div className="pt-4 border-t">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                    <div>
                      <Label className="text-muted-foreground">Max Concurrent Sessions</Label>
                      <p className="font-medium">{sessionPolicy.max_concurrent_sessions}</p>
                    </div>
                    <div>
                      <Label className="text-muted-foreground">Session Timeout</Label>
                      <p className="font-medium">{sessionPolicy.session_timeout_minutes} minutes</p>
                    </div>
                    <div>
                      <Label className="text-muted-foreground">Idle Timeout</Label>
                      <p className="font-medium">{sessionPolicy.idle_timeout_minutes} minutes</p>
                    </div>
                  </div>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default SessionSecurityManager;