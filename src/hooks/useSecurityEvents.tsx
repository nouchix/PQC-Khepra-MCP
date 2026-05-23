import { useState, useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';

export interface SecurityEvent {
  id: string;
  event_type: string;
  severity: 'INFO' | 'WARNING' | 'CRITICAL';
  source_system: string;
  details: any;
  resolved: boolean;
  resolved_by?: string;
  resolved_at?: string;
  created_at: string;
  event_tags?: {
    environment?: string;
    type?: string;
    real_or_test?: string;
    [key: string]: any;
  };
  source_ip?: string;
  source_metadata?: any;
  archived?: boolean;
  archived_at?: string;
  archived_by?: string;
  organization_id?: string;
}

export const useSecurityEvents = () => {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { user } = useAuth();

  const fetchEvents = async () => {
    try {
      setLoading(true);
      const { data, error } = await supabase
        .from('security_events')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(100);

      if (error) throw error;
      setEvents((data as SecurityEvent[]) || []);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const resolveEvent = async (eventId: string) => {
    if (!user) return { error: 'User not authenticated' };

    try {
      const { error } = await supabase
        .from('security_events')
        .update({ 
          resolved: true, 
          resolved_by: user.id, 
          resolved_at: new Date().toISOString() 
        })
        .eq('id', eventId);

      if (error) throw error;
      
      setEvents(prev => prev.map(event => 
        event.id === eventId 
          ? { ...event, resolved: true, resolved_by: user.id, resolved_at: new Date().toISOString() }
          : event
      ));
      
      return { success: true };
    } catch (err: any) {
      return { error: err.message };
    }
  };

  const addEvent = async (event: Omit<SecurityEvent, 'id' | 'created_at' | 'resolved' | 'resolved_by' | 'resolved_at'>) => {
    try {
      const { data, error } = await supabase
        .from('security_events')
        .insert([event as any])
        .select()
        .single();

      if (error) throw error;
      setEvents(prev => [data as SecurityEvent, ...prev]);
      return { data };
    } catch (err: any) {
      return { error: err.message };
    }
  };

  useEffect(() => {
    fetchEvents();

    // Set up real-time subscription
    const channel = supabase
      .channel('security_events_changes')
      .on(
        'postgres_changes',
        {
          event: 'INSERT',
          schema: 'public',
          table: 'security_events'
        },
        (payload) => {
          setEvents(prev => [payload.new as SecurityEvent, ...prev]);
        }
      )
      .on(
        'postgres_changes',
        {
          event: 'UPDATE',
          schema: 'public',
          table: 'security_events'
        },
        (payload) => {
          setEvents(prev => prev.map(event => 
            event.id === payload.new.id ? payload.new as SecurityEvent : event
          ));
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, []);

  return {
    events,
    loading,
    error,
    resolveEvent,
    addEvent,
    refetch: fetchEvents
  };
};