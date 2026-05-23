import { useState, useMemo } from 'react';
import { SecurityEvent } from '@/hooks/useSecurityEvents';

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface RiskWeights {
  severity: Record<Severity, number>;
  sourceBoosts: Record<string, number>; // e.g., { falco: 1.2, "Threat Feed": 1.1 }
}

export interface ScoredEvent extends SecurityEvent {
  risk_score_weighted: number;
}

const defaultWeights: RiskWeights = {
  severity: {
    LOW: 0.2,
    MEDIUM: 0.5,
    HIGH: 0.8,
    CRITICAL: 1.0,
  },
  sourceBoosts: {
    falco: 1.15,
    'Threat Feed': 1.1,
  },
};

function baseSeverityScore(sev: SecurityEvent['severity']): number {
  switch (sev) {
    case 'CRITICAL': return 90;
    case 'WARNING': return 60;
    case 'INFO': return 30;
    default: return 30;
  }
}

export const useRiskScoring = (initial?: RiskWeights) => {
  const [weights, setWeights] = useState<RiskWeights>(initial || defaultWeights);

  const scoreEvent = (event: SecurityEvent): number => {
    const base = baseSeverityScore(event.severity);
    // Map security severity to threat severity domain
    const sevKey: Severity = event.severity === 'CRITICAL' ? 'CRITICAL' : event.severity === 'WARNING' ? 'HIGH' : 'MEDIUM';
    const sevWeight = weights.severity[sevKey] ?? 0.5;

    const source = (event.source_system || '').toLowerCase();
    let boost = 1;
    Object.entries(weights.sourceBoosts).forEach(([k, v]) => {
      if (source.includes(k.toLowerCase())) boost = Math.max(boost, v);
    });

    // Optional: add confidence or details.risk_score if present
    const detailScore = typeof (event.details?.risk_score) === 'number' ? event.details.risk_score : 0;

    const result = Math.min(100, Math.round((base * sevWeight * boost) + detailScore * 0.3));
    return result;
  };

  const applyScores = (events: SecurityEvent[]): ScoredEvent[] => {
    return events.map(e => ({ ...e, risk_score_weighted: scoreEvent(e) })).sort((a, b) => b.risk_score_weighted - a.risk_score_weighted);
  };

  return { weights, setWeights, scoreEvent, applyScores };
};
