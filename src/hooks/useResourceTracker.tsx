import { useUsageBilling } from './useUsageBilling';
import { useOrganization } from './useOrganization';

export const useResourceTracker = () => {
  const { trackUsage } = useUsageBilling();
  const { currentOrganization } = useOrganization();

  const trackCompute = async (cpuHours: number, metadata?: Record<string, any>) => {
    await trackUsage('compute', cpuHours, 'cpu_hours', metadata);
  };

  const trackStorage = async (gbHours: number, metadata?: Record<string, any>) => {
    await trackUsage('storage', gbHours, 'gb_hours', metadata);
  };

  const trackBandwidth = async (gbTransferred: number, metadata?: Record<string, any>) => {
    await trackUsage('bandwidth', gbTransferred, 'gb_transferred', metadata);
  };

  const trackApiCall = async (callCount: number = 1, metadata?: Record<string, any>) => {
    await trackUsage('api_calls', callCount, 'requests', metadata);
  };

  const trackThreatAnalysis = async (threatCount: number = 1, metadata?: Record<string, any>) => {
    await trackUsage('threats_analyzed', threatCount, 'threats', metadata);
  };

  const trackComplianceScan = async (scanCount: number = 1, metadata?: Record<string, any>) => {
    await trackUsage('compliance_scans', scanCount, 'scans', metadata);
  };

  const trackMondaySync = async (itemCount: number = 1, operation: string, metadata?: Record<string, any>) => {
    await trackUsage('monday_sync', itemCount, 'items', {
      operation,
      ...metadata
    });
  };

  // Convenience function to track any resource with automatic metadata
  const trackResource = async (
    resourceType: string, 
    quantity: number, 
    unit: string, 
    context?: string,
    additionalMetadata?: Record<string, any>
  ) => {
    const metadata = {
      tracked_at: new Date().toISOString(),
      context: context || 'automatic',
      organization_id: currentOrganization?.id,
      ...additionalMetadata
    };

    await trackUsage(resourceType, quantity, unit, metadata);
  };

  return {
    trackCompute,
    trackStorage,
    trackBandwidth,
    trackApiCall,
    trackThreatAnalysis,
    trackComplianceScan,
    trackMondaySync,
    trackResource
  };
};