import { useState, useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useOrganization } from '@/hooks/useOrganization';
import { useToast } from '@/hooks/use-toast';

interface ResourceUsage {
  id: string;
  resource_type: string;
  quantity: number;
  unit: string;
  cost_per_unit: number;
  total_cost: number;
  created_at: string;
  metadata?: any;
}

interface UsageSummary {
  resource_type: string;
  total_quantity: number;
  unit: string;
  avg_cost_per_unit: number;
  total_cost: number;
  usage_events: number;
}

interface BillingPeriod {
  id: string;
  period_start: string;
  period_end: string;
  status: string;
  total_usage_cost: number;
  base_subscription_cost: number;
  total_amount: number;
  stripe_invoice_id?: string;
}

interface UsageQuota {
  id: string;
  resource_type: string;
  quota_limit: number;
  quota_period: string;
  overage_rate: number;
}

export const useUsageBilling = () => {
  const [usageData, setUsageData] = useState<ResourceUsage[]>([]);
  const [usageSummary, setUsageSummary] = useState<UsageSummary[]>([]);
  const [currentBillingPeriod, setCurrentBillingPeriod] = useState<BillingPeriod | null>(null);
  const [quotas, setQuotas] = useState<UsageQuota[]>([]);
  const [loading, setLoading] = useState(false);
  const { currentOrganization } = useOrganization();
  const { toast } = useToast();

  // Track resource usage
  const trackUsage = async (
    resourceType: string,
    quantity: number,
    unit: string,
    metadata?: Record<string, any>
  ) => {
    if (!currentOrganization?.id) return;

    try {
      const { error } = await supabase.rpc('track_resource_usage', {
        p_organization_id: currentOrganization.id,
        p_resource_type: resourceType,
        p_quantity: quantity,
        p_unit: unit,
        p_metadata: metadata || {}
      });

      if (error) throw error;
      
      // Refresh usage data after tracking
      await fetchUsageData();
    } catch (error: any) {
      console.error('Error tracking usage:', error);
      toast({
        title: "Usage Tracking Error",
        description: error.message || "Failed to track resource usage",
        variant: "destructive"
      });
    }
  };

  // Fetch current usage data
  const fetchUsageData = async () => {
    if (!currentOrganization?.id) return;
    
    setLoading(true);
    try {
      // Fetch detailed usage records
      const { data: usage, error: usageError } = await supabase
        .from('resource_usage')
        .select('*')
        .eq('organization_id', currentOrganization.id)
        .order('created_at', { ascending: false })
        .limit(100);

      if (usageError) throw usageError;
      setUsageData(usage || []);

      // Fetch usage summary
      const { data: summary, error: summaryError } = await supabase
        .from('usage_costs_summary')
        .select('*')
        .eq('organization_id', currentOrganization.id)
        .eq('billing_period', new Date().toISOString().split('T')[0]);

      if (summaryError) throw summaryError;
      setUsageSummary(summary || []);

      // Fetch current billing period
      const currentMonth = new Date().toISOString().slice(0, 7) + '-01';
      const { data: billingPeriod, error: billingError } = await supabase
        .from('billing_periods')
        .select('*')
        .eq('organization_id', currentOrganization.id)
        .eq('period_start', currentMonth)
        .single();

      if (billingError && billingError.code !== 'PGRST116') throw billingError;
      setCurrentBillingPeriod(billingPeriod);

      // Fetch quotas
      const { data: quotaData, error: quotaError } = await supabase
        .from('usage_quotas')
        .select('*')
        .eq('organization_id', currentOrganization.id);

      if (quotaError) throw quotaError;
      setQuotas(quotaData || []);
      
    } catch (error: any) {
      console.error('Error fetching usage data:', error);
      toast({
        title: "Error",
        description: error.message || "Failed to fetch usage data",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  // Get usage for specific resource type
  const getResourceUsage = (resourceType: string): UsageSummary | null => {
    return usageSummary.find(s => s.resource_type === resourceType) || null;
  };

  // Check if quota is exceeded
  const isQuotaExceeded = (resourceType: string): boolean => {
    const usage = getResourceUsage(resourceType);
    const quota = quotas.find(q => q.resource_type === resourceType);
    
    if (!usage || !quota) return false;
    return usage.total_quantity > quota.quota_limit;
  };

  // Get quota utilization percentage
  const getQuotaUtilization = (resourceType: string): number => {
    const usage = getResourceUsage(resourceType);
    const quota = quotas.find(q => q.resource_type === resourceType);
    
    if (!usage || !quota) return 0;
    return Math.min((usage.total_quantity / quota.quota_limit) * 100, 100);
  };

  // Calculate estimated monthly cost
  const getEstimatedMonthlyCost = (): number => {
    if (!currentBillingPeriod) return 0;
    return currentBillingPeriod.total_amount;
  };

  // Get cost breakdown by resource type
  const getCostBreakdown = (): Array<{ resource_type: string; cost: number; percentage: number }> => {
    const totalCost = usageSummary.reduce((sum, item) => sum + item.total_cost, 0);
    
    return usageSummary.map(item => ({
      resource_type: item.resource_type,
      cost: item.total_cost,
      percentage: totalCost > 0 ? (item.total_cost / totalCost) * 100 : 0
    }));
  };

  useEffect(() => {
    if (currentOrganization?.id) {
      fetchUsageData();
    }
  }, [currentOrganization?.id]);

  return {
    usageData,
    usageSummary,
    currentBillingPeriod,
    quotas,
    loading,
    trackUsage,
    fetchUsageData,
    getResourceUsage,
    isQuotaExceeded,
    getQuotaUtilization,
    getEstimatedMonthlyCost,
    getCostBreakdown
  };
};