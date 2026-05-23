import { useState, useEffect, useCallback } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

export interface Alert {
  id: string;
  title: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  alert_type: string;
  source_type: string;
  source_id?: string;
  status: 'OPEN' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'RESOLVED' | 'SUPPRESSED';
  assigned_to?: string;
  risk_score: number;
  confidence_score: number;
  metadata: any;
  tags: string[];
  escalated: boolean;
  escalation_level: number;
  sla_deadline: string;
  acknowledged_at?: string;
  acknowledged_by?: string;
  resolved_at?: string;
  resolved_by?: string;
  created_at: string;
  updated_at: string;
}

export interface AlertRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  rule_type: 'threshold' | 'pattern' | 'anomaly' | 'correlation';
  conditions: any;
  actions: any;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  cooldown_minutes: number;
  last_triggered?: string;
  trigger_count: number;
  created_at: string;
}

export interface NotificationChannel {
  type: 'email' | 'sms' | 'webhook' | 'in_app' | 'slack';
  name: string;
  config: any;
  enabled: boolean;
}

export const useAlertManager = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [rules, setRules] = useState<AlertRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [processing, setProcessing] = useState(false);
  const { toast } = useToast();

  const fetchAlerts = async () => {
    try {
      const { data, error } = await supabase
        .from('alerts')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(100);

      if (error) throw error;
      setAlerts((data as Alert[]) || []);
    } catch (error: any) {
      console.error('Error fetching alerts:', error);
      toast({
        title: "Error",
        description: "Failed to fetch alerts",
        variant: "destructive"
      });
    }
  };

  const fetchRules = async () => {
    try {
      const { data, error } = await supabase
        .from('alert_rules')
        .select('*')
        .order('created_at', { ascending: false });

      if (error) throw error;
      setRules((data as AlertRule[]) || []);
    } catch (error: any) {
      console.error('Error fetching alert rules:', error);
      toast({
        title: "Error",
        description: "Failed to fetch alert rules",
        variant: "destructive"
      });
    }
  };

  const createAlert = async (alertData: Partial<Alert>) => {
    try {
      const { data, error } = await supabase.functions.invoke('alert-engine', {
        body: {
          action: 'create_alert',
          data: alertData
        }
      });

      if (error) throw error;

      toast({
        title: "Alert Created",
        description: `Alert created with ${alertData.severity} severity`,
        variant: alertData.severity === 'CRITICAL' ? 'destructive' : 'default'
      });

      await fetchAlerts();
      return data;
    } catch (error: any) {
      console.error('Error creating alert:', error);
      toast({
        title: "Error",
        description: "Failed to create alert",
        variant: "destructive"
      });
      throw error;
    }
  };

  const updateAlertStatus = async (alertId: string, status: Alert['status'], assignedTo?: string) => {
    try {
      const updateData: any = {
        status,
        updated_at: new Date().toISOString()
      };

      if (status === 'ACKNOWLEDGED') {
        updateData.acknowledged_at = new Date().toISOString();
        updateData.acknowledged_by = supabase.auth.getUser().then(u => u.data.user?.id);
      }

      if (status === 'RESOLVED') {
        updateData.resolved_at = new Date().toISOString();
        updateData.resolved_by = supabase.auth.getUser().then(u => u.data.user?.id);
      }

      if (assignedTo) {
        updateData.assigned_to = assignedTo;
      }

      const { error } = await supabase
        .from('alerts')
        .update(updateData)
        .eq('id', alertId);

      if (error) throw error;

      await fetchAlerts();
      
      toast({
        title: "Alert Updated",
        description: `Alert status changed to ${status}`
      });
    } catch (error: any) {
      console.error('Error updating alert:', error);
      toast({
        title: "Error",
        description: "Failed to update alert",
        variant: "destructive"
      });
    }
  };

  const processRules = async (triggerData?: any) => {
    try {
      setProcessing(true);
      
      const { data, error } = await supabase.functions.invoke('alert-engine', {
        body: {
          action: 'process_rules',
          data: triggerData
        }
      });

      if (error) throw error;

      toast({
        title: "Rules Processed",
        description: `${data.rules_triggered} of ${data.rules_processed} rules triggered`
      });

      await fetchAlerts();
      return data;
    } catch (error: any) {
      console.error('Error processing rules:', error);
      toast({
        title: "Error",
        description: "Failed to process alert rules",
        variant: "destructive"
      });
    } finally {
      setProcessing(false);
    }
  };

  const sendTestNotification = async (channel: string, recipient: string) => {
    try {
      const { data, error } = await supabase.functions.invoke('alert-engine', {
        body: {
          action: 'test_notification',
          data: { channel, recipient }
        }
      });

      if (error) throw error;

      toast({
        title: "Test Notification Sent",
        description: `Test ${channel} notification sent successfully`
      });

      return data;
    } catch (error: any) {
      console.error('Error sending test notification:', error);
      toast({
        title: "Error",
        description: "Failed to send test notification",
        variant: "destructive"
      });
    }
  };

  const createRule = async (ruleData: Omit<AlertRule, 'id' | 'created_at' | 'updated_at' | 'trigger_count' | 'last_triggered'>) => {
    try {
      const { data, error } = await supabase
        .from('alert_rules')
        .insert(ruleData as any)
        .select()
        .single();

      if (error) throw error;

      await fetchRules();
      
      toast({
        title: "Alert Rule Created",
        description: `Rule "${ruleData.name}" created successfully`
      });

      return data;
    } catch (error: any) {
      console.error('Error creating rule:', error);
      toast({
        title: "Error",
        description: "Failed to create alert rule",
        variant: "destructive"
      });
    }
  };

  const toggleRule = async (ruleId: string, enabled: boolean) => {
    try {
      const { error } = await supabase
        .from('alert_rules')
        .update({ enabled })
        .eq('id', ruleId);

      if (error) throw error;

      await fetchRules();
      
      toast({
        title: "Rule Updated",
        description: `Rule ${enabled ? 'enabled' : 'disabled'}`
      });
    } catch (error: any) {
      console.error('Error toggling rule:', error);
      toast({
        title: "Error",
        description: "Failed to update rule",
        variant: "destructive"
      });
    }
  };

  const escalateAlert = async (alertId: string) => {
    try {
      const { data, error } = await supabase.functions.invoke('alert-engine', {
        body: {
          action: 'escalate_alert',
          data: { alert_id: alertId }
        }
      });

      if (error) throw error;

      await fetchAlerts();
      
      toast({
        title: "Alert Escalated",
        description: `Alert escalated to level ${data.escalation_level}`,
        variant: "destructive"
      });

      return data;
    } catch (error: any) {
      console.error('Error escalating alert:', error);
      toast({
        title: "Error",
        description: "Failed to escalate alert",
        variant: "destructive"
      });
    }
  };

  const getAlertMetrics = useCallback(() => {
    const now = Date.now();
    const last24h = now - 24 * 60 * 60 * 1000;
    
    const recentAlerts = alerts.filter(alert => 
      new Date(alert.created_at).getTime() > last24h
    );

    const byStatus = alerts.reduce((acc, alert) => {
      acc[alert.status] = (acc[alert.status] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const bySeverity = alerts.reduce((acc, alert) => {
      acc[alert.severity] = (acc[alert.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const overdueAlerts = alerts.filter(alert => 
      alert.status === 'OPEN' && 
      new Date(alert.sla_deadline).getTime() < now
    );

    return {
      total: alerts.length,
      recent: recentAlerts.length,
      open: byStatus.OPEN || 0,
      acknowledged: byStatus.ACKNOWLEDGED || 0,
      investigating: byStatus.INVESTIGATING || 0,
      resolved: byStatus.RESOLVED || 0,
      critical: bySeverity.CRITICAL || 0,
      high: bySeverity.HIGH || 0,
      medium: bySeverity.MEDIUM || 0,
      low: bySeverity.LOW || 0,
      overdue: overdueAlerts.length,
      avgRiskScore: alerts.length > 0 ? 
        Math.round(alerts.reduce((sum, alert) => sum + alert.risk_score, 0) / alerts.length) : 0
    };
  }, [alerts]);

  // Set up real-time subscriptions
  useEffect(() => {
    const alertsChannel = supabase
      .channel('alerts_changes')
      .on(
        'postgres_changes',
        {
          event: '*',
          schema: 'public',
          table: 'alerts'
        },
        () => {
          fetchAlerts();
        }
      )
      .subscribe();

    const rulesChannel = supabase
      .channel('rules_changes')
      .on(
        'postgres_changes',
        {
          event: '*',
          schema: 'public',
          table: 'alert_rules'
        },
        () => {
          fetchRules();
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(alertsChannel);
      supabase.removeChannel(rulesChannel);
    };
  }, []);

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      await Promise.all([fetchAlerts(), fetchRules()]);
      setLoading(false);
    };

    loadData();
  }, []);

  return {
    alerts,
    rules,
    loading,
    processing,
    metrics: getAlertMetrics(),
    createAlert,
    updateAlertStatus,
    processRules,
    sendTestNotification,
    createRule,
    toggleRule,
    escalateAlert,
    refetch: () => Promise.all([fetchAlerts(), fetchRules()])
  };
};