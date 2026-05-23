import { useState, useEffect, useCallback } from 'react';
import { useAuth } from '@/hooks/useAuth';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';

interface KipConnectionState {
  isConnected: boolean;
  connectionHealth: 'excellent' | 'good' | 'poor' | 'disconnected';
  lastSync: Date | null;
  culturalFingerprint: string | null;
  trustScore: number;
  kipUrl: string;
}

interface CulturalTransformation {
  id: string;
  symbol: string;
  transformation_type: string;
  input_vector: number[];
  output_vector: number[];
  timestamp: string;
  agent_id: string;
}

export const useKipConnection = () => {
  const { user } = useAuth();
  const { toast } = useToast();
  
  const [connection, setConnection] = useState<KipConnectionState>({
    isConnected: false,
    connectionHealth: 'disconnected',
    lastSync: null,
    culturalFingerprint: null,
    trustScore: 0,
    kipUrl: process.env.NODE_ENV === 'development' 
      ? 'http://localhost:3001/khepra/v1'
      : 'https://kip-project.lovable.app/khepra/v1'
  });

  const [platformId] = useState('souhimbou-ai');
  const [culturalContext] = useState('souhimbou:integration:bridge');

  const [recentTransformations, setRecentTransformations] = useState<CulturalTransformation[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  // Health check with cultural validation
  const checkConnectionHealth = useCallback(async () => {
    if (!user) return;

    try {
      const { data: { session } } = await supabase.auth.getSession();
      const response = await fetch(`${connection.kipUrl}/healthz`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${session?.access_token}`,
          'Content-Type': 'application/json',
          'KHEPRA-Platform-ID': platformId,
          'KHEPRA-Cultural-Context': culturalContext
        },
      });

      if (response.ok) {
        const healthData = await response.json();
        const latency = Date.now() - new Date(healthData.timestamp).getTime();
        
        setConnection(prev => ({
          ...prev,
          isConnected: true,
          connectionHealth: latency < 100 ? 'excellent' : latency < 500 ? 'good' : 'poor',
          lastSync: new Date()
        }));
      } else {
        throw new Error('Health check failed');
      }
    } catch (error) {
      setConnection(prev => ({
        ...prev,
        isConnected: false,
        connectionHealth: 'disconnected'
      }));
    }
  }, [connection.kipUrl, user]);

  // Initialize cultural DID and fingerprint
  const initializeCulturalAuth = useCallback(async () => {
    if (!user || !connection.isConnected) return;

    setIsLoading(true);
    try {
      const { data: { session } } = await supabase.auth.getSession();
      const response = await fetch(`${connection.kipUrl}/auth/cultural-fingerprint`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${session?.access_token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          user_id: user.id,
          organization_id: user.user_metadata?.organization_id,
          platform_context: culturalContext,
          adinkra_symbols: ['GYE_NYAME', 'SANKOFA', 'DWENNIMMEN']
        })
      });

      if (response.ok) {
        const authData = await response.json();
        setConnection(prev => ({
          ...prev,
          culturalFingerprint: authData.cultural_fingerprint,
          trustScore: authData.initial_trust_score || 75
        }));

        toast({
          title: "Cultural Authentication Established",
          description: `Trust Score: ${authData.initial_trust_score}%`
        });
      }
    } catch (error) {
      console.error('Cultural auth initialization failed:', error);
    } finally {
      setIsLoading(false);
    }
  }, [connection.kipUrl, connection.isConnected, user, toast]);

  // Sync cultural transformations from KIP
  const syncCulturalTransformations = useCallback(async () => {
    if (!user || !connection.isConnected) return;

    try {
      const { data: { session } } = await supabase.auth.getSession();
      const response = await fetch(`${connection.kipUrl}/cultural/transformations`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${session?.access_token}`,
          'KHEPRA-Cultural-Fingerprint': connection.culturalFingerprint || ''
        },
      });

      if (response.ok) {
        const transformations = await response.json();
        setRecentTransformations(transformations.items || []);
        setConnection(prev => ({ ...prev, lastSync: new Date() }));
      }
    } catch (error) {
      console.error('Transformation sync failed:', error);
    }
  }, [connection.kipUrl, connection.isConnected, connection.culturalFingerprint, user]);

  // Send cultural event to KIP
  const sendCulturalEvent = useCallback(async (event: {
    action: string;
    symbol: string;
    context: Record<string, any>;
  }) => {
    if (!connection.isConnected || !connection.culturalFingerprint) return null;

    try {
      const { data: { session } } = await supabase.auth.getSession();
      const response = await fetch(`${connection.kipUrl}/cultural/events`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${session?.access_token}`,
          'Content-Type': 'application/json',
          'KHEPRA-Cultural-Fingerprint': connection.culturalFingerprint
        },
        body: JSON.stringify(event)
      });

      return response.ok ? await response.json() : null;
    } catch (error) {
      console.error('Cultural event send failed:', error);
      return null;
    }
  }, [connection.isConnected, connection.culturalFingerprint, connection.kipUrl, user]);

  // Auto-sync and health monitoring
  useEffect(() => {
    if (user) {
      checkConnectionHealth();
      const healthInterval = setInterval(checkConnectionHealth, 30000); // Every 30s
      return () => clearInterval(healthInterval);
    }
  }, [user, checkConnectionHealth]);

  useEffect(() => {
    if (connection.isConnected && !connection.culturalFingerprint) {
      initializeCulturalAuth();
    }
  }, [connection.isConnected, connection.culturalFingerprint, initializeCulturalAuth]);

  useEffect(() => {
    if (connection.isConnected && connection.culturalFingerprint) {
      syncCulturalTransformations();
      const syncInterval = setInterval(syncCulturalTransformations, 60000); // Every minute
      return () => clearInterval(syncInterval);
    }
  }, [connection.isConnected, connection.culturalFingerprint, syncCulturalTransformations]);

  return {
    connection,
    recentTransformations,
    isLoading,
    checkConnectionHealth,
    initializeCulturalAuth,
    syncCulturalTransformations,
    sendCulturalEvent
  };
};