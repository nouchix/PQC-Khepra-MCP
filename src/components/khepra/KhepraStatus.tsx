import { useKhepraAuth } from '@/khepra/hooks/useKhepraAuth';
import { useKhepraDeployment } from '@/hooks/useKhepraDeployment';
import { useKhepraAPI } from '@/hooks/useKhepraAPI';
import {
  CulturalTrustCard,
  EnvironmentHealthCard,
  AdinkraResilienceCard,
  MonitoringCard,
  LicenseQuotaCard
} from '@/components/khepra/StatusCards';

export const KhepraStatus = () => {
  const { authState, securityEvents, isMonitoring } = useKhepraAuth();
  const { config } = useKhepraDeployment();
  const { health, license } = useKhepraAPI(config?.deploymentUrl || '', config?.apiKey || '');

  // Usage Metering Logic
  const nodeQuota = license.data?.node_quota || 1; // Default to Scout (1 node)
  const nodeCount = license.data?.node_count || 0;
  const usagePercentage = Math.min((nodeCount / nodeQuota) * 100, 100);
  const isExhausted = usagePercentage >= 90;

  const isRemoteHealthy = health.data?.status === 'healthy';
  const recentEvents = securityEvents.slice(0, 3);
  const assetCriticality = license.data?.asset_criticality || 2;
  const arsScore = authState.trustScore * assetCriticality;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      {/* Cultural Trust Score */}
      <CulturalTrustCard trustScore={authState.trustScore} />

      {/* Environment Health */}
      <EnvironmentHealthCard
        isRemoteHealthy={isRemoteHealthy}
        statusText={health.data?.license_status || 'Connection Pending'}
        deploymentUrl={config?.deploymentUrl || 'No VPS configured'}
      />

      {/* Adinkra Resilience Score (ARS) */}
      <AdinkraResilienceCard
        arsScore={arsScore}
        assetCriticality={assetCriticality}
      />

      {/* Monitoring Status */}
      <MonitoringCard
        isMonitoring={isMonitoring}
        events={securityEvents.length}
        recentEvents={recentEvents}
      />

      {/* License Quota */}
      <LicenseQuotaCard
        nodeCount={nodeCount}
        nodeQuota={nodeQuota}
        tier={license.data?.tier}
        usagePercentage={usagePercentage}
        isExhausted={isExhausted}
      />
    </div>
  );
};
