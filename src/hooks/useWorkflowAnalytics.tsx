import { useState, useCallback, useEffect } from 'react';
import { useToast } from '@/hooks/use-toast';

interface WorkflowEvent {
  id: string;
  elementType: string;
  action: string;
  timestamp: number;
  coordinates: { x: number; y: number };
  context: string;
  sessionId: string;
  metadata: Record<string, any>;
}

interface WorkflowPattern {
  id: string;
  name: string;
  frequency: number;
  lastOccurrence: number;
  confidence: number;
  prediction: string;
  optimization: string;
}

interface HeuristicInsight {
  type: 'efficiency' | 'security' | 'automation' | 'learning';
  title: string;
  description: string;
  recommendation: string;
  confidence: number;
  timestamp: number;
}

export const useWorkflowAnalytics = () => {
  const { toast } = useToast();
  const [events, setEvents] = useState<WorkflowEvent[]>([]);
  const [patterns, setPatterns] = useState<WorkflowPattern[]>([]);
  const [insights, setInsights] = useState<HeuristicInsight[]>([]);
  const [sessionId] = useState(() => `session_${Date.now()}_${crypto.randomUUID().replace(/-/g, '').substr(0, 9)}`);

  // Track user interactions
  const trackEvent = useCallback((
    elementType: string,
    action: string,
    coordinates: { x: number; y: number },
    metadata: Record<string, any> = {}
  ) => {
    const event: WorkflowEvent = {
      id: `event_${Date.now()}_${crypto.randomUUID().replace(/-/g, '').substr(0, 9)}`,
      elementType,
      action,
      timestamp: Date.now(),
      coordinates,
      context: globalThis.location.pathname,
      sessionId,
      metadata
    };

    setEvents(prev => [...prev, event]);
    
    // Trigger pattern analysis
    analyzePatterns([...events, event]);
  }, [events, sessionId]);

  // ML-powered pattern analysis
  const analyzePatterns = useCallback((eventData: WorkflowEvent[]) => {
    if (eventData.length < 5) return;

    const recentEvents = eventData.slice(-20);
    const actionSequences = extractActionSequences(recentEvents);
    const spatialPatterns = analyzeSpatialBehavior(recentEvents);
    const temporalPatterns = analyzeTemporalBehavior(recentEvents);

    const newPatterns: WorkflowPattern[] = [];

    // Action sequence patterns
    actionSequences.forEach((sequence, index) => {
      if (sequence.frequency > 2) {
        newPatterns.push({
          id: `sequence_${index}`,
          name: `${sequence.actions.join(' → ')}`,
          frequency: sequence.frequency,
          lastOccurrence: sequence.lastTimestamp,
          confidence: Math.min(0.95, sequence.frequency / 10),
          prediction: `User likely to continue with ${sequence.nextAction || 'related action'}`,
          optimization: generateOptimizationSuggestion(sequence)
        });
      }
    });

    // Spatial patterns
    if (spatialPatterns.hotspots.length > 0) {
      newPatterns.push({
        id: 'spatial_hotspot',
        name: 'Interaction Hotspots',
        frequency: spatialPatterns.totalInteractions,
        lastOccurrence: Date.now(),
        confidence: 0.8,
        prediction: 'User focuses on specific UI regions',
        optimization: 'Consider reorganizing frequently used controls'
      });
    }

    setPatterns(newPatterns);
    generateHeuristicInsights(newPatterns, recentEvents);
  }, []);

  const extractActionSequences = (events: WorkflowEvent[]) => {
    const sequences: Map<string, { actions: string[], frequency: number, lastTimestamp: number, nextAction?: string }> = new Map();

    for (let i = 0; i < events.length - 2; i++) {
      const sequence = events.slice(i, i + 3).map(e => e.action);
      const key = sequence.slice(0, 2).join('→');
      
      if (sequences.has(key)) {
        const existing = sequences.get(key)!;
        existing.frequency++;
        existing.lastTimestamp = events[i + 2].timestamp;
        existing.nextAction = sequence[2];
      } else {
        sequences.set(key, {
          actions: sequence.slice(0, 2),
          frequency: 1,
          lastTimestamp: events[i + 2].timestamp,
          nextAction: sequence[2]
        });
      }
    }

    return Array.from(sequences.values());
  };

  const analyzeSpatialBehavior = (events: WorkflowEvent[]) => {
    const clusters = groupByProximity(events.map(e => e.coordinates), 50);
    
    return {
      hotspots: clusters.filter(c => c.points.length > 3),
      totalInteractions: events.length,
      averageDistance: calculateAverageDistance(events)
    };
  };

  const analyzeTemporalBehavior = (events: WorkflowEvent[]) => {
    const intervals = [];
    for (let i = 1; i < events.length; i++) {
      intervals.push(events[i].timestamp - events[i - 1].timestamp);
    }

    const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const fastActions = intervals.filter(i => i < 1000).length;
    
    return {
      averageInterval: avgInterval,
      rapidActionPercentage: (fastActions / intervals.length) * 100,
      sessionDuration: events.at(-1).timestamp - events[0].timestamp
    };
  };

  const generateHeuristicInsights = useCallback((patterns: WorkflowPattern[], events: WorkflowEvent[]) => {
    const newInsights: HeuristicInsight[] = [];

    // Efficiency insights
    const rapidPatterns = patterns.filter(p => p.name.includes('→') && p.frequency > 3);
    if (rapidPatterns.length > 0) {
      newInsights.push({
        type: 'efficiency',
        title: 'Workflow Automation Opportunity',
        description: `Detected ${rapidPatterns.length} repetitive action sequences`,
        recommendation: 'Consider creating custom shortcuts or automated workflows for these patterns',
        confidence: 0.85,
        timestamp: Date.now()
      });
    }

    // Security insights
    const securityEvents = events.filter(e => 
      e.elementType.includes('security') || 
      e.action.includes('security') ||
      e.context.includes('security')
    );

    if (securityEvents.length > events.length * 0.6) {
      newInsights.push({
        type: 'security',
        title: 'Security-Focused Workflow Detected',
        description: 'High concentration of security-related actions',
        recommendation: 'Enable advanced security monitoring and automated threat response',
        confidence: 0.9,
        timestamp: Date.now()
      });
    }

    // Learning insights
    const diversityScore = new Set(events.map(e => e.elementType)).size / events.length;
    if (diversityScore > 0.7) {
      newInsights.push({
        type: 'learning',
        title: 'Exploratory Learning Pattern',
        description: 'User demonstrates broad exploration of platform features',
        recommendation: 'Provide guided tours for advanced features and integration paths',
        confidence: 0.75,
        timestamp: Date.now()
      });
    }

    setInsights(prev => [...prev, ...newInsights]);

    // Show most confident insight as toast
    const bestInsight = newInsights.sort((a, b) => b.confidence - a.confidence)[0];
    if (bestInsight && bestInsight.confidence > 0.8) {
      toast({
        title: `Papyrus Insight: ${bestInsight.title}`,
        description: bestInsight.recommendation,
        duration: 8000,
      });
    }
  }, [toast]);

  const generateOptimizationSuggestion = (sequence: any): string => {
    if (sequence.frequency > 5) {
      return `Create macro for "${sequence.actions.join(' → ')}" sequence`;
    }
    if (sequence.actions.some((a: string) => a.includes('security'))) {
      return 'Add to security automation pipeline';
    }
    return 'Consider workflow optimization';
  };

  // Utility functions
  const groupByProximity = (points: { x: number; y: number }[], threshold: number) => {
    const clusters: { center: { x: number; y: number }; points: { x: number; y: number }[] }[] = [];
    
    points.forEach(point => {
      let assigned = false;
      for (const cluster of clusters) {
        const distance = Math.sqrt(
          Math.pow(point.x - cluster.center.x, 2) + 
          Math.pow(point.y - cluster.center.y, 2)
        );
        
        if (distance < threshold) {
          cluster.points.push(point);
          // Recalculate center
          cluster.center.x = cluster.points.reduce((sum, p) => sum + p.x, 0) / cluster.points.length;
          cluster.center.y = cluster.points.reduce((sum, p) => sum + p.y, 0) / cluster.points.length;
          assigned = true;
          break;
        }
      }
      
      if (!assigned) {
        clusters.push({
          center: { x: point.x, y: point.y },
          points: [point]
        });
      }
    });
    
    return clusters;
  };

  const calculateAverageDistance = (events: WorkflowEvent[]): number => {
    if (events.length < 2) return 0;
    
    let totalDistance = 0;
    for (let i = 1; i < events.length; i++) {
      const distance = Math.sqrt(
        Math.pow(events[i].coordinates.x - events[i - 1].coordinates.x, 2) +
        Math.pow(events[i].coordinates.y - events[i - 1].coordinates.y, 2)
      );
      totalDistance += distance;
    }
    
    return totalDistance / (events.length - 1);
  };

  // Auto-save analytics data periodically
  useEffect(() => {
    const interval = setInterval(() => {
      if (events.length > 0) {
        localStorage.setItem('papyrus_workflow_analytics', JSON.stringify({
          events: events.slice(-100), // Keep last 100 events
          patterns,
          insights: insights.slice(-20), // Keep last 20 insights
          sessionId
        }));
      }
    }, 30000); // Save every 30 seconds

    return () => clearInterval(interval);
  }, [events, patterns, insights, sessionId]);

  // Load previous analytics data
  useEffect(() => {
    const saved = localStorage.getItem('papyrus_workflow_analytics');
    if (saved) {
      try {
        const data = JSON.parse(saved);
        if (data.events) setEvents(data.events);
        if (data.patterns) setPatterns(data.patterns);
        if (data.insights) setInsights(data.insights);
      } catch (error) {
        console.warn('Failed to load workflow analytics:', error);
      }
    }
  }, []);

  return {
    trackEvent,
    events,
    patterns,
    insights,
    sessionId,
    analytics: {
      totalEvents: events.length,
      uniqueElements: new Set(events.map(e => e.elementType)).size,
      sessionDuration: events.length > 0 ? Date.now() - events[0].timestamp : 0,
      topActions: getTopActions(events),
      efficiency: calculateEfficiencyScore(patterns),
    }
  };
};

const getTopActions = (events: WorkflowEvent[]) => {
  const actionCounts = events.reduce((acc, event) => {
    acc[event.action] = (acc[event.action] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return Object.entries(actionCounts)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5)
    .map(([action, count]) => ({ action, count }));
};

const calculateEfficiencyScore = (patterns: WorkflowPattern[]): number => {
  if (patterns.length === 0) return 0;
  
  const avgConfidence = patterns.reduce((sum, p) => sum + p.confidence, 0) / patterns.length;
  const repetitionBonus = patterns.filter(p => p.frequency > 3).length / patterns.length;
  
  return Math.min(100, (avgConfidence * 70) + (repetitionBonus * 30));
};