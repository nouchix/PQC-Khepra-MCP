import { useState, useEffect, useCallback } from 'react';
import { AdinkraAlgebraicEngine, AdinkraTransformation } from '../aae/AdinkraEngine';
import { AgentDAG } from '../dag/AgentDAG';
import { useAuth } from '@/hooks/useAuth';
import { supabase } from '@/integrations/supabase/client';

export interface KhepraAuthState {
  culturalFingerprint: string | null;
  trustScore: number;
  adinkraTransformations: AdinkraTransformation[];
  agentId: string | null;
  isAuthenticated: boolean;
  culturalContext: string;
  lastInteraction: Date | null;
}

export interface KhepraSecurityEvent {
  type: 'cultural_validation' | 'trust_degradation' | 'anomaly_detected' | 'transformation_success';
  severity: 'low' | 'medium' | 'high' | 'critical';
  details: Record<string, any>;
  timestamp: Date;
  agentId: string;
}

export const useKhepraAuth = () => {
  const { user } = useAuth();
  const [authState, setAuthState] = useState<KhepraAuthState>({
    culturalFingerprint: null,
    trustScore: 0,
    adinkraTransformations: [],
    agentId: null,
    isAuthenticated: false,
    culturalContext: 'security',
    lastInteraction: null
  });
  const [securityEvents, setSecurityEvents] = useState<KhepraSecurityEvent[]>([]);
  const [agentDAG] = useState(() => new AgentDAG());
  const [isMonitoring, setIsMonitoring] = useState(false);

  /**
   * Initialize Khepra authentication for the current user
   */
  const initializeKhepraAuth = useCallback(async () => {
    if (!user) return;

    try {
      // Generate agent ID based on user
      const agentId = `agent_${user.id}`;
      
      // Create cultural fingerprint
      const deviceData = `${navigator.userAgent}:${user.id}:${Date.now()}`;
      const culturalFingerprint = AdinkraAlgebraicEngine.generateFingerprint(
        deviceData, 
        ['Eban', 'Nyame'] // Protection + Authority
      );

      // Initialize with basic transformation
      const initialTransformation: AdinkraTransformation = {
        symbol: 'Eban',
        input: [1, 0],
        output: AdinkraAlgebraicEngine.transform('Eban', [1, 0]),
        timestamp: new Date(),
        context: 'initialization'
      };

      // Calculate initial trust score
      const trustScore = AdinkraAlgebraicEngine.calculateTrustScore([initialTransformation]);

      // Add initial action to DAG
      agentDAG.addAgentAction(agentId, 'initialize_session', 'security', {
        userAgent: navigator.userAgent,
        timestamp: Date.now()
      });

      setAuthState({
        culturalFingerprint,
        trustScore,
        adinkraTransformations: [initialTransformation],
        agentId,
        isAuthenticated: true,
        culturalContext: 'security',
        lastInteraction: new Date()
      });

      // Log security event
      await logSecurityEvent({
        type: 'cultural_validation',
        severity: 'low',
        details: {
          culturalFingerprint,
          trustScore,
          symbol: 'Eban',
          meaning: 'Fortress - Security and Protection'
        },
        timestamp: new Date(),
        agentId
      });

    } catch (error) {
      console.error('Failed to initialize Khepra auth:', error);
      await logSecurityEvent({
        type: 'anomaly_detected',
        severity: 'high',
        details: { error: error.message, phase: 'initialization' },
        timestamp: new Date(),
        agentId: `agent_${user.id}`
      });
    }
  }, [user, agentDAG]);

  /**
   * Validate user action using Khepra cultural context
   */
  const validateAction = useCallback(async (action: string, context: string = 'security'): Promise<boolean> => {
    if (!authState.agentId || !authState.isAuthenticated) {
      return false;
    }

    try {
      // Get appropriate symbol for context
      const symbol = AdinkraAlgebraicEngine.getSymbolByContext(
        context as 'security' | 'trust' | 'transformation' | 'unity'
      );

      // Create transformation for this action
      const actionData = `${action}:${authState.agentId}:${Date.now()}`;
      const inputVector = AdinkraAlgebraicEngine['stringToBinary'](actionData).slice(0, symbol.matrix[0].length);
      const outputVector = AdinkraAlgebraicEngine.transform(symbol.name, inputVector);

      const transformation: AdinkraTransformation = {
        symbol: symbol.name,
        input: inputVector,
        output: outputVector,
        timestamp: new Date(),
        context: action
      };

      // Update transformations and recalculate trust
      const newTransformations = [...authState.adinkraTransformations, transformation];
      const newTrustScore = AdinkraAlgebraicEngine.calculateTrustScore(newTransformations);

      // Add action to DAG and validate authorization
      const nodeId = agentDAG.addAgentAction(authState.agentId, action, context);
      const isAuthorized = agentDAG.validateAgentAuthorization(authState.agentId, action);

      // Update state
      setAuthState(prev => ({
        ...prev,
        adinkraTransformations: newTransformations,
        trustScore: newTrustScore,
        culturalContext: context,
        lastInteraction: new Date()
      }));

      // Log the validation event
      await logSecurityEvent({
        type: isAuthorized ? 'transformation_success' : 'anomaly_detected',
        severity: isAuthorized ? 'low' : 'medium',
        details: {
          action,
          context,
          symbol: symbol.name,
          symbolMeaning: symbol.meaning,
          trustScore: newTrustScore,
          nodeId,
          authorized: isAuthorized
        },
        timestamp: new Date(),
        agentId: authState.agentId
      });

      return isAuthorized;

    } catch (error) {
      console.error('Action validation failed:', error);
      await logSecurityEvent({
        type: 'anomaly_detected',
        severity: 'high',
        details: { 
          error: error.message, 
          action, 
          context,
          phase: 'validation'
        },
        timestamp: new Date(),
        agentId: authState.agentId
      });
      return false;
    }
  }, [authState, agentDAG]);

  /**
   * Record interaction between agents
   */
  const recordAgentInteraction = useCallback(async (
    targetAgentId: string, 
    action: string, 
    success: boolean = true
  ) => {
    if (!authState.agentId) return;

    try {
      // Record in DAG
      agentDAG.recordInteraction(authState.agentId, targetAgentId, action, success);

      // Log security event
      await logSecurityEvent({
        type: success ? 'transformation_success' : 'anomaly_detected',
        severity: success ? 'low' : 'medium',
        details: {
          sourceAgent: authState.agentId,
          targetAgent: targetAgentId,
          action,
          success,
          interactionType: 'agent_to_agent'
        },
        timestamp: new Date(),
        agentId: authState.agentId
      });

    } catch (error) {
      console.error('Failed to record agent interaction:', error);
    }
  }, [authState.agentId, agentDAG]);

  /**
   * Monitor for security anomalies
   */
  const startMonitoring = useCallback(() => {
    if (!authState.agentId || isMonitoring) return;

    setIsMonitoring(true);

    const monitoringInterval = setInterval(async () => {
      if (!authState.agentId) return;

      try {
        // Detect anomalies in agent behavior
        const anomalies = agentDAG.detectAnomalies(authState.agentId);

        for (const anomaly of anomalies) {
          await logSecurityEvent({
            type: 'anomaly_detected',
            severity: anomaly.severity as 'low' | 'medium' | 'high',
            details: anomaly,
            timestamp: new Date(),
            agentId: authState.agentId
          });
        }

        // Check for trust score degradation
        if (authState.trustScore < 50) {
          await logSecurityEvent({
            type: 'trust_degradation',
            severity: 'high',
            details: {
              currentTrustScore: authState.trustScore,
              threshold: 50,
              recommendedAction: 'reauthentication_required'
            },
            timestamp: new Date(),
            agentId: authState.agentId
          });
        }

      } catch (error) {
        console.error('Monitoring error:', error);
      }
    }, 30000); // Check every 30 seconds

    return () => {
      clearInterval(monitoringInterval);
      setIsMonitoring(false);
    };
  }, [authState.agentId, authState.trustScore, agentDAG, isMonitoring]);

  /**
   * Generate Khepra audit trail
   */
  const generateAuditTrail = useCallback(() => {
    if (!authState.agentId) return [];
    
    return agentDAG.generateAuditTrail(authState.agentId);
  }, [authState.agentId, agentDAG]);

  /**
   * Log security event to Supabase
   */
  const logSecurityEvent = useCallback(async (event: KhepraSecurityEvent) => {
    try {
      await supabase.from('security_events').insert({
        event_type: `khepra_${event.type}`,
        severity: event.severity.toUpperCase(),
        source_system: 'khepra_protocol',
        details: {
          ...event.details,
          khepra_version: '1.0.0',
          cultural_protocol: true
        },
        created_at: event.timestamp.toISOString()
      } as any);

      setSecurityEvents(prev => [event, ...prev.slice(0, 99)]); // Keep last 100 events
    } catch (error) {
      console.error('Failed to log Khepra security event:', error);
    }
  }, []);

  /**
   * Reset Khepra authentication
   */
  const resetAuth = useCallback(() => {
    setAuthState({
      culturalFingerprint: null,
      trustScore: 0,
      adinkraTransformations: [],
      agentId: null,
      isAuthenticated: false,
      culturalContext: 'security',
      lastInteraction: null
    });
    setSecurityEvents([]);
    setIsMonitoring(false);
  }, []);

  // Initialize when user changes
  useEffect(() => {
    if (user) {
      initializeKhepraAuth();
    } else {
      resetAuth();
    }
  }, [user, initializeKhepraAuth, resetAuth]);

  // Auto-start monitoring
  useEffect(() => {
    if (authState.isAuthenticated && !isMonitoring) {
      const cleanup = startMonitoring();
      return cleanup;
    }
  }, [authState.isAuthenticated, isMonitoring, startMonitoring]);

  return {
    authState,
    securityEvents,
    validateAction,
    recordAgentInteraction,
    generateAuditTrail,
    startMonitoring,
    resetAuth,
    isMonitoring
  };
};