/**
 * useConnectorLearning — Learning Mode hook for the Connector SDK
 *
 * Triggered when a connector test fails. Orchestrates:
 *  1. API cost gate (prevents runaway spend)
 *  2. mitochondrial-proxy call (action: 'learn') → PQC-OAuth session
 *  3. DAG write (connector.learn) for full audit chain
 *  4. ChatGPTCodexIntegration.updateLearningModel() for continuous improvement
 *
 * The hook intentionally has no autonomous execution side effects —
 * all remediation recommendations require explicit operator approval.
 */

import { useState, useCallback } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { apiCostTracker } from '@/services/ExternalApiCostTracker';
import { ChatGPTCodexIntegration } from '@/services/ChatGPTCodexIntegration';
import { writeDAGNode, logConnectorFailure } from '@/services/ConnectorDAG';

export type LearningStatus =
  | 'idle'
  | 'checking_cost'
  | 'analyzing'
  | 'updating_model'
  | 'complete'
  | 'error';

export interface LearningAnalysis {
  response: string;                      // Grok advisory text
  recommendations: ActionRecommendation[]; // Operator-approval items only
  rootCause: string;
  confidencePercent: number;
  dagNodeHash: string;
  patternId?: string;
}

export interface ActionRecommendation {
  type: string;
  text: string;
  riskLevel: string;
  requiresApproval: true;
  remediationType: string;
}

export interface UseConnectorLearningParams {
  connectorId: string;
  organizationId: string;
  provider: string;
  errorCode?: string;
  errorBody?: Record<string, unknown>;
  httpStatus?: number;
  /** Parent DAG node hash from the failed test, for chain linking */
  parentDagNodeHash?: string;
}

export function useConnectorLearning() {
  const [status, setStatus] = useState<LearningStatus>('idle');
  const [analysis, setAnalysis] = useState<LearningAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);

  const trigger = useCallback(async (params: UseConnectorLearningParams) => {
    setStatus('idle');
    setAnalysis(null);
    setError(null);

    // ── Step 1: API cost gate ─────────────────────────────────────────────
    setStatus('checking_cost');
    const { data: userData } = await supabase.auth.getUser();
    if (!userData?.user?.id) {
      setError('User must be authenticated to trigger Learning Mode');
      setStatus('error');
      return;
    }

    const costCheck = await apiCostTracker.preCallCheck({
      organizationId: params.organizationId,
      apiProvider: 'grok-ai',
      endpoint: 'connector-learning',
    });

    if (!costCheck.allowed) {
      setError(`Learning Mode blocked by cost gate: ${costCheck.reason}`);
      setStatus('error');
      return;
    }

    // ── Step 2: Write connector.learn DAG node ───────────────────────────
    setStatus('analyzing');
    const dagNodeHash = await writeDAGNode({
      action: 'connector.learn',
      symbol: 'mitochondrial-proxy',
      organizationId: params.organizationId,
      connectorId: params.connectorId,
      parentHashes: params.parentDagNodeHash ? [params.parentDagNodeHash] : [],
      pqcMetadata: {
        provider: params.provider,
        errorCode: params.errorCode,
        httpStatus: params.httpStatus,
        threatLevel: 'yellow',
      },
    });

    // ── Step 3: Call mitochondrial-proxy (action: learn) ─────────────────
    let proxyResponse: {
      response: string;
      actionableItems: ActionRecommendation[];
      pattern_id?: string;
      error?: string;
    };

    try {
      const { data, error: fnError } = await supabase.functions.invoke(
        'mitochondrial-proxy',
        {
          body: {
            action: 'learn',
            connector_id: params.connectorId,
            organization_id: params.organizationId,
            provider: params.provider,
            error_code: params.errorCode,
            error_body: params.errorBody ?? {},
            http_status: params.httpStatus,
            dag_node_hash: dagNodeHash,
          },
        }
      );

      if (fnError) throw new Error(fnError.message);
      if (data?.error) throw new Error(data.error);

      proxyResponse = data;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      // Log failure even if the proxy call itself fails
      await logConnectorFailure({
        organizationId: params.organizationId,
        connectorId: params.connectorId,
        provider: params.provider,
        errorCode: params.errorCode ?? 'learning_proxy_error',
        errorBody: { proxyError: msg },
        httpStatus: params.httpStatus,
        dagNodeHash,
      });
      setError(`Learning Mode analysis failed: ${msg}`);
      setStatus('error');
      return;
    }

    // ── Step 4: Update Codex learning model ──────────────────────────────
    setStatus('updating_model');
    try {
      await ChatGPTCodexIntegration.updateLearningModel({
        deployment_id: params.connectorId,
        performance_metrics: { http_status: params.httpStatus },
        user_feedback: null,
        error_patterns: [
          {
            provider: params.provider,
            error_code: params.errorCode,
            dag_node: dagNodeHash,
          },
        ],
        optimization_outcomes: [],
      });
    } catch (err) {
      // Non-fatal: model update failure does not block operator from seeing analysis
      console.warn('[useConnectorLearning] Learning model update failed:', err);
    }

    // ── Step 5: Extract root cause from advisory response ─────────────────
    const responseText = proxyResponse.response ?? '';
    const confidenceMatch = responseText.match(/confidence[:\s]+(\d{1,3})%/i);
    const confidencePercent = confidenceMatch ? parseInt(confidenceMatch[1], 10) : 60;

    const rootCauseMatch = responseText.match(
      /root cause[:\s]+([^\n.]+)/i
    );
    const rootCause = rootCauseMatch
      ? rootCauseMatch[1].trim()
      : `${params.provider} connector failure (${params.errorCode ?? 'unknown error'})`;

    // Filter to only requiresApproval items — enforces no-auto-exec contract
    const recommendations = (proxyResponse.actionableItems ?? []).filter(
      (item): item is ActionRecommendation => item.requiresApproval === true
    );

    setAnalysis({
      response: responseText,
      recommendations,
      rootCause,
      confidencePercent,
      dagNodeHash,
      patternId: proxyResponse.pattern_id,
    });
    setStatus('complete');
  }, []);

  const reset = useCallback(() => {
    setStatus('idle');
    setAnalysis(null);
    setError(null);
  }, []);

  return { status, analysis, error, trigger, reset };
}
