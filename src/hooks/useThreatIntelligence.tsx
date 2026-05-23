import { useState, useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';

export interface ThreatIndicator {
  id: string;
  source: string;
  indicator_type: string;
  indicator_value: string;
  threat_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description?: string;
  created_at: string;
  updated_at: string;
}

export const useThreatIntelligence = () => {
  const [threats, setThreats] = useState<ThreatIndicator[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { user } = useAuth();

  const fetchThreats = async () => {
    try {
      setLoading(true);
      const { data, error } = await supabase
        .from('threat_intelligence')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(50);

      if (error) throw error;
      setThreats((data as ThreatIndicator[]) || []);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const addThreat = async (threat: Omit<ThreatIndicator, 'id' | 'created_at' | 'updated_at'>) => {
    if (!user) return { error: 'User not authenticated' };

    try {
      const { data, error } = await supabase
        .from('threat_intelligence')
        .insert([{ ...threat, created_by: user.id }])
        .select()
        .single();

      if (error) throw error;
      setThreats(prev => [data as ThreatIndicator, ...prev]);
      return { data };
    } catch (err: any) {
      return { error: err.message };
    }
  };

  useEffect(() => {
    fetchThreats();

    // Set up real-time subscription
    const channel = supabase
      .channel('threat_intelligence_changes')
      .on(
        'postgres_changes',
        {
          event: 'INSERT',
          schema: 'public',
          table: 'threat_intelligence'
        },
        (payload) => {
          setThreats(prev => [payload.new as ThreatIndicator, ...prev]);
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, []);

  return {
    threats,
    loading,
    error,
    addThreat,
    refetch: fetchThreats
  };
};