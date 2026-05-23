import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useUsageBilling } from "@/hooks/useUsageBilling";
import { 
  Cpu, 
  HardDrive, 
  Network, 
  Activity, 
  Shield, 
  FileSearch,
  RefreshCw,
  TrendingUp,
  AlertTriangle,
  CheckCircle
} from "lucide-react";
import { formatCurrency } from "@/lib/utils";

const resourceIcons = {
  compute: Cpu,
  storage: HardDrive,
  bandwidth: Network,
  api_calls: Activity,
  threats_analyzed: Shield,
  compliance_scans: FileSearch
};

const resourceLabels = {
  compute: 'Compute Hours',
  storage: 'Storage Usage',
  bandwidth: 'Bandwidth',
  api_calls: 'API Calls',
  threats_analyzed: 'Threats Analyzed',
  compliance_scans: 'Compliance Scans'
};

const resourceUnits = {
  compute: 'CPU hours',
  storage: 'GB·hours',
  bandwidth: 'GB transferred',
  api_calls: 'requests',
  threats_analyzed: 'threats',
  compliance_scans: 'scans'
};

export const UsageDashboard = () => {
  const {
    usageSummary,
    currentBillingPeriod,
    quotas,
    loading,
    fetchUsageData,
    getQuotaUtilization,
    isQuotaExceeded,
    getEstimatedMonthlyCost,
    getCostBreakdown
  } = useUsageBilling();

  const costBreakdown = getCostBreakdown();
  const estimatedCost = getEstimatedMonthlyCost();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-foreground">Usage & Billing</h2>
          <p className="text-muted-foreground">Monitor your resource consumption and costs</p>
        </div>
        <Button onClick={fetchUsageData} disabled={loading} variant="outline">
          <RefreshCw className={`mr-2 h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {/* Current Billing Period Overview */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <TrendingUp className="mr-2 h-5 w-5" />
            Current Billing Period
          </CardTitle>
          <CardDescription>
            {currentBillingPeriod && (
              <>
                {new Date(currentBillingPeriod.period_start).toLocaleDateString()} - {' '}
                {new Date(currentBillingPeriod.period_end).toLocaleDateString()}
              </>
            )}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">
                {formatCurrency(currentBillingPeriod?.total_usage_cost || 0)}
              </div>
              <p className="text-sm text-muted-foreground">Usage Costs</p>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-foreground">
                {formatCurrency(currentBillingPeriod?.base_subscription_cost || 0)}
              </div>
              <p className="text-sm text-muted-foreground">Base Subscription</p>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-accent">
                {formatCurrency(estimatedCost)}
              </div>
              <p className="text-sm text-muted-foreground">Total Estimated</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Resource Usage Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {Object.entries(resourceLabels).map(([resourceType, label]) => {
          const usage = usageSummary.find(s => s.resource_type === resourceType);
          const quota = quotas.find(q => q.resource_type === resourceType);
          const utilization = getQuotaUtilization(resourceType);
          const exceeded = isQuotaExceeded(resourceType);
          const Icon = resourceIcons[resourceType as keyof typeof resourceIcons];

          return (
            <Card key={resourceType} className={exceeded ? "border-destructive" : ""}>
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center justify-between text-base">
                  <div className="flex items-center">
                    <Icon className="mr-2 h-4 w-4" />
                    {label}
                  </div>
                  {exceeded && (
                    <Badge variant="destructive" className="text-xs">
                      <AlertTriangle className="mr-1 h-3 w-3" />
                      Over Quota
                    </Badge>
                  )}
                  {quota && !exceeded && utilization < 80 && (
                    <Badge variant="secondary" className="text-xs">
                      <CheckCircle className="mr-1 h-3 w-3" />
                      Within Limits
                    </Badge>
                  )}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div>
                    <div className="flex justify-between text-sm">
                      <span>Usage</span>
                      <span className="font-medium">
                        {usage?.total_quantity.toFixed(2) || '0'} {resourceUnits[resourceType as keyof typeof resourceUnits]}
                      </span>
                    </div>
                    {quota && (
                      <>
                        <Progress 
                          value={utilization} 
                          className={`mt-2 ${exceeded ? "[&>div]:bg-destructive" : utilization > 80 ? "[&>div]:bg-warning" : "[&>div]:bg-primary"}`}
                        />
                        <div className="flex justify-between text-xs text-muted-foreground mt-1">
                          <span>Limit: {quota.quota_limit}</span>
                          <span>{utilization.toFixed(1)}%</span>
                        </div>
                      </>
                    )}
                  </div>
                  
                  <div className="pt-2 border-t">
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-muted-foreground">Cost</span>
                      <span className="font-semibold text-foreground">
                        {formatCurrency(usage?.total_cost || 0)}
                      </span>
                    </div>
                    {usage && (
                      <div className="text-xs text-muted-foreground">
                        {formatCurrency(usage.avg_cost_per_unit)} per {resourceUnits[resourceType as keyof typeof resourceUnits].split(' ')[0]}
                      </div>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Cost Breakdown */}
      {costBreakdown.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Cost Breakdown</CardTitle>
            <CardDescription>Distribution of costs by resource type</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {costBreakdown.map((item) => (
                <div key={item.resource_type} className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div className="w-3 h-3 rounded bg-primary"></div>
                    <span className="text-sm font-medium">
                      {resourceLabels[item.resource_type as keyof typeof resourceLabels]}
                    </span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="text-sm text-muted-foreground">
                      {item.percentage.toFixed(1)}%
                    </span>
                    <span className="text-sm font-semibold">
                      {formatCurrency(item.cost)}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};