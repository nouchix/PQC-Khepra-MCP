import { useState, useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';

export interface ThreatMetrics {
  timestamp: string;
  activeThreats: number;
  resolvedThreats: number;
  criticalAlerts: number;
  networkActivity: number;
  cpuUsage: number;
  memoryUsage: number;
  diskUsage: number;
}

export interface SecurityEvent {
  id: string;
  event_type: string;
  severity: 'INFO' | 'WARNING' | 'CRITICAL';
  source_system: string;
  details: any;
  resolved: boolean;
  created_at: string;
}

export const useRealTimeData = () => {
  const [metrics, setMetrics] = useState<ThreatMetrics[]>([]);
  const [securityEvents, setSecurityEvents] = useState<SecurityEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);

  // Placeholder for real-time data generation
  const generatePlaceholderMetrics = (): ThreatMetrics => {
    return {
      timestamp: new Date().toISOString(),
      activeThreats: 0,
      resolvedThreats: 0,
      criticalAlerts: 0,
      networkActivity: 0,
      cpuUsage: 0,
      memoryUsage: 0,
      diskUsage: 0,
    };
  };

  const generatePlaceholderEvent = (): SecurityEvent => {
    return {
      id: `placeholder_event_${Date.now()}`,
      event_type: 'No real-time data - Connect your security tools',
      severity: 'INFO',
      source_system: 'Demo System',
      details: {
        message: 'Connect your SIEM, firewall, or other security tools to see real events'
      },
      resolved: false,
      created_at: new Date().toISOString(),
    };
  };

  // Simulate real-time connection
  useEffect(() => {
    setIsConnected(true);
    
    // Initialize with placeholder data showing platform capabilities
    const placeholderMetrics = [generatePlaceholderMetrics()];
    const placeholderEvents = [generatePlaceholderEvent()];
    
    setMetrics(placeholderMetrics);
    setSecurityEvents(placeholderEvents);

    // Remove intervals - real data will come from integrations
    // const metricsInterval = null;
    // const eventsInterval = null;

    // Real Supabase subscription for actual security events
    const eventsSubscription = supabase
      .channel('security-events-realtime')
      .on(
        'postgres_changes',
        {
          event: 'INSERT',
          schema: 'public',
          table: 'security_events'
        },
        (payload) => {
          setSecurityEvents(prev => [payload.new as SecurityEvent, ...prev.slice(0, 49)]);
        }
      )
      .subscribe();

    return () => {
      eventsSubscription.unsubscribe();
      setIsConnected(false);
    };
  }, []);

  const currentMetrics = metrics.at(-1);

  return {
    metrics,
    securityEvents,
    currentMetrics,
    isConnected
  };
};