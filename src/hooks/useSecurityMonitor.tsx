import { useState, useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';

export interface SecurityAlert {
  id: string;
  type: 'SUSPICIOUS_LOGIN' | 'MULTIPLE_FAILURES' | 'UNUSUAL_ACTIVITY' | 'PRIVILEGE_ESCALATION' | 'DATA_ACCESS';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  title: string;
  description: string;
  source_ip?: string;
  user_agent?: string;
  location?: string;
  timestamp: string;
  resolved: boolean;
}

export interface SessionInfo {
  id: string;
  ip_address: string;
  user_agent: string;
  location: string;
  last_activity: string;
  is_current: boolean;
}

export const useSecurityMonitor = () => {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [riskScore, setRiskScore] = useState(0);
  const [loading, setLoading] = useState(true);
  const { user } = useAuth();

  // Load security data from database
  const loadSecurityAlerts = async () => {
    if (!user) return;
    
    try {
      const { data, error } = await supabase
        .from('security_events')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(50);
      
      if (error) throw error;
      
        // Transform security events to alerts format
        const alertsData: SecurityAlert[] = (data || []).map(event => ({
          id: event.id,
          type: event.event_type as SecurityAlert['type'],
          severity: event.severity?.toUpperCase() as SecurityAlert['severity'] || 'LOW',
          title: event.event_type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
          description: (event.details as any)?.description || `${event.event_type} detected from ${event.source_system}`,
          source_ip: (event.details as any)?.source_ip,
          user_agent: (event.details as any)?.user_agent,
          location: (event.details as any)?.location,
          timestamp: event.created_at,
          resolved: event.resolved || false
        }));
      
      setAlerts(alertsData);
    } catch (error) {
      console.error('Error loading security alerts:', error);
    }
  };

  const loadActiveSessions = async () => {
    if (!user) return;
    
    try {
      // Get current session info from browser
      const currentSession: SessionInfo = {
        id: 'current_session',
        ip_address: 'Current IP', // Would be populated by real session tracking
        user_agent: navigator.userAgent.substring(0, 100),
        location: 'Current Location', // Would be populated by geolocation
        last_activity: new Date().toISOString(),
        is_current: true
      };
      
      // In a real implementation, you would load from a sessions table
      // For now, we'll show the current session plus any audit log sessions
      const { data: auditData } = await supabase
        .from('audit_logs')
        .select('*')
        .eq('user_id', user.id)
        .eq('action', 'session_created')
        .order('created_at', { ascending: false })
        .limit(10);
      
      const sessions: SessionInfo[] = [currentSession];
      
      // Add recent sessions from audit logs
      if (auditData) {
        auditData.forEach((log, index) => {
          if (index < 5) { // Limit to 5 recent sessions
            const details = log.details as { user_agent?: string; location?: string } | null;
            sessions.push({
              id: log.id,
              ip_address: log.ip_address?.toString() || 'Unknown',
              user_agent: details?.user_agent || 'Unknown Browser',
              location: details?.location || 'Unknown Location',
              last_activity: log.created_at,
              is_current: false
            });
          }
        });
      }
      
      setSessions(sessions);
    } catch (error) {
      console.error('Error loading active sessions:', error);
    }
  };

  // Calculate risk score based on alerts and activity
  const calculateRiskScore = (alertList: SecurityAlert[]) => {
    const activeAlerts = alertList.filter(alert => !alert.resolved);
    let score = 0;
    
    activeAlerts.forEach(alert => {
      switch (alert.severity) {
        case 'LOW': score += 10; break;
        case 'MEDIUM': score += 25; break;
        case 'HIGH': score += 50; break;
        case 'CRITICAL': score += 75; break;
      }
    });

    return Math.min(score, 100);
  };

  // Resolve security alert
  const resolveAlert = async (alertId: string) => {
    setAlerts(prev => prev.map(alert => 
      alert.id === alertId ? { ...alert, resolved: true } : alert
    ));

    // Log security action
    try {
      await supabase.rpc('log_user_action', {
        action_type: 'SECURITY_ALERT_RESOLVED',
        resource_type: 'security_alert',
        resource_id: alertId,
        details: { resolved_at: new Date().toISOString() }
      });
    } catch (error) {
      console.error('Failed to log security action:', error);
    }
  };

  // Terminate session
  const terminateSession = async (sessionId: string) => {
    setSessions(prev => prev.filter(session => session.id !== sessionId));
    
    try {
      await supabase.rpc('log_user_action', {
        action_type: 'SESSION_TERMINATED',
        resource_type: 'user_session',
        resource_id: sessionId,
        details: { terminated_at: new Date().toISOString() }
      });
    } catch (error) {
      console.error('Failed to log session termination:', error);
    }
  };

  useEffect(() => {
    if (!user) return;

    const loadData = async () => {
      setLoading(true);
      try {
        await Promise.all([
          loadSecurityAlerts(),
          loadActiveSessions()
        ]);
        
        // Calculate risk score based on active alerts
        const activeAlerts = alerts.filter(alert => !alert.resolved);
        const calculatedRisk = calculateRiskScore(activeAlerts);
        setRiskScore(calculatedRisk);
      } catch (error) {
        console.error('Error loading security data:', error);
      } finally {
        setLoading(false);
      }
    };

    loadData();

    // Set up real-time subscriptions for security events
    const securityEventsSubscription = supabase
      .channel('security_events_monitor')
      .on('postgres_changes', 
        { event: '*', schema: 'public', table: 'security_events' },
        () => {
          loadSecurityAlerts();
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(securityEventsSubscription);
    };
  }, [user]);

  return {
    alerts,
    sessions,
    riskScore,
    loading,
    resolveAlert,
    terminateSession
  };
};