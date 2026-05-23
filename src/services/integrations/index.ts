/**
 * Enterprise Integration Connectors
 * ══════════════════════════════════
 *
 * Centralized exports for all external API integrations.
 * Each connector follows the same pattern:
 *   1. Retrieve API key via IntegrationKeyService
 *   2. Pre-flight rate limit check via ExternalApiCostTracker
 *   3. Make authenticated API call with typed response
 *   4. Persist results to open_controls_performance_metrics
 *   5. Return typed result or explicit failure state
 *
 * Active Connectors (Sprint 1–3 COMPLETE):
 *   - VirusTotal Enterprise        ✅  INT-005, INT-006, INT-017
 *   - Datadog Metrics API          ✅  INT-001, INT-003
 *   - STIGViewer API (via DMZ)     ✅  INT-002, INT-014
 *   - AWS Cost Explorer            ✅  INT-004
 *   - Microsoft Defender TI        ✅  INT-012, INT-021
 *   - HashiCorp Vault              ✅  INT-009
 */

// ─── Key Management ──────────────────────────────────────────────────────────
export { IntegrationKeyService } from './IntegrationKeyService';
export type { IntegrationProvider, IntegrationCredential } from './IntegrationKeyService';

// ─── Threat Intelligence ─────────────────────────────────────────────────────
export { VirusTotalConnector } from './VirusTotalConnector';
export type {
    VTFileReport,
    VTUrlReport,
    VTDomainReport,
    VTIPReport,
    VulnerabilityFeedResult,
} from './VirusTotalConnector';

// ─── Observability / Metrics ─────────────────────────────────────────────────
export { DatadogConnector } from './DatadogConnector';
export type {
    DatadogMetricPoint,
    DatadogTimeseriesResult,
    RealTimeMetricsResult,
    RequestVolumeResult,
} from './DatadogConnector';

// ─── Compliance / STIGs ──────────────────────────────────────────────────────
export { STIGViewerConnector } from './STIGViewerConnector';
export type {
    STIGViewerRule,
    STIGCatalogResult,
    ComplianceScoreResult,
    STIGQueryOptions,
} from './STIGViewerConnector';

// ─── Financial / Cost Analysis ───────────────────────────────────────────────
export { AWSCostExplorerConnector } from './AWSCostExplorerConnector';
export type {
    CostBreakdown,
    CostAnalysisResult,
    CostForecastResult,
} from './AWSCostExplorerConnector';

// ─── Advanced Threat Intelligence ────────────────────────────────────────────
export { MicrosoftDefenderTIConnector } from './MicrosoftDefenderTIConnector';
export type {
    ThreatIndicator,
    VulnerabilityArticle,
    ThreatArticle,
    ThreatIntelligenceResult,
    CVEEnrichmentResult,
} from './MicrosoftDefenderTIConnector';

// ─── Credential Management ──────────────────────────────────────────────────
export { HashiCorpVaultConnector } from './HashiCorpVaultConnector';
export type {
    VaultHealthStatus,
    CredentialTestResult,
    SecretMetadata,
    RotationResult,
} from './HashiCorpVaultConnector';
