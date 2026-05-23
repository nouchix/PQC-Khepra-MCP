import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { 
  Cpu, 
  HardDrive, 
  Network, 
  Activity, 
  Shield, 
  FileSearch,
  DollarSign,
  AlertCircle,
  CheckCircle
} from 'lucide-react';
import { formatCurrency } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';

interface UsageBillingSetupProps {
  organizationId: string;
  onComplete: () => void;
  onSkip: () => void;
}

interface QuotaSettings {
  compute: number;
  storage: number;
  bandwidth: number;
  api_calls: number;
  threats_analyzed: number;
  compliance_scans: number;
}

const defaultQuotas: QuotaSettings = {
  compute: 100,        // 100 CPU hours/month
  storage: 500,        // 500 GB hours/month  
  bandwidth: 50,       // 50 GB/month
  api_calls: 10000,    // 10,000 API calls/month
  threats_analyzed: 1000, // 1,000 threats/month
  compliance_scans: 50    // 50 scans/month
};

const resourceConfig = {
  compute: { 
    icon: Cpu, 
    label: 'Compute Hours', 
    unit: 'CPU hours', 
    costPerUnit: 0.05,
    description: 'Processing power for AI analysis and automation'
  },
  storage: { 
    icon: HardDrive, 
    label: 'Storage Usage', 
    unit: 'GB·hours', 
    costPerUnit: 0.02,
    description: 'Data storage for logs, reports, and configurations'
  },
  bandwidth: { 
    icon: Network, 
    label: 'Bandwidth', 
    unit: 'GB transferred', 
    costPerUnit: 0.10,
    description: 'Data transfer for integrations and API calls'
  },
  api_calls: { 
    icon: Activity, 
    label: 'API Calls', 
    unit: 'requests', 
    costPerUnit: 0.001,
    description: 'Platform API requests and external integrations'
  },
  threats_analyzed: { 
    icon: Shield, 
    label: 'Threat Analysis', 
    unit: 'threats', 
    costPerUnit: 0.05,
    description: 'AI-powered threat detection and analysis'
  },
  compliance_scans: { 
    icon: FileSearch, 
    label: 'Compliance Scans', 
    unit: 'scans', 
    costPerUnit: 1.00,
    description: 'Automated compliance assessment scans'
  }
};

export const UsageBillingSetup = ({ organizationId, onComplete, onSkip }: UsageBillingSetupProps) => {
  const [quotas, setQuotas] = useState<QuotaSettings>(defaultQuotas);
  const [billingEmail, setBillingEmail] = useState('');
  const [autoScaling, setAutoScaling] = useState(true);
  const [billingAlerts, setBillingAlerts] = useState(true);
  const [alertThreshold, setAlertThreshold] = useState(80);
  const [loading, setLoading] = useState(false);
  const { toast } = useToast();

  const calculateEstimatedCost = (): number => {
    return Object.entries(quotas).reduce((total, [resourceType, quota]) => {
      const config = resourceConfig[resourceType as keyof typeof resourceConfig];
      return total + (quota * config.costPerUnit);
    }, 0);
  };

  const updateQuota = (resourceType: keyof QuotaSettings, value: number) => {
    setQuotas(prev => ({
      ...prev,
      [resourceType]: Math.max(0, value)
    }));
  };

  const setupBilling = async () => {
    setLoading(true);
    try {
      // Create usage quotas for each resource type
      const quotaPromises = Object.entries(quotas).map(([resourceType, quota]) => 
        supabase.from('usage_quotas').insert({
          organization_id: organizationId,
          resource_type: resourceType,
          quota_limit: quota,
          quota_period: 'monthly',
          overage_rate: resourceConfig[resourceType as keyof typeof resourceConfig].costPerUnit * 1.5 // 50% overage premium
        })
      );

      await Promise.all(quotaPromises);

      // Create initial billing period
      const currentMonth = new Date().toISOString().slice(0, 7) + '-01';
      const nextMonth = new Date(new Date().getFullYear(), new Date().getMonth() + 1, 1);
      const endOfMonth = new Date(nextMonth.getTime() - 1);

      await supabase.from('billing_periods').insert({
        organization_id: organizationId,
        period_start: currentMonth,
        period_end: endOfMonth.toISOString().split('T')[0],
        status: 'active',
        base_subscription_cost: 0, // Free tier initially
        total_usage_cost: 0
      });

      // Log the billing setup
      await supabase.from('audit_logs').insert({
        user_id: null, // System action
        action: 'billing_setup_completed',
        resource_type: 'organization',
        resource_id: organizationId,
        details: {
          quotas: JSON.parse(JSON.stringify(quotas)),
          billingEmail,
          autoScaling,
          billingAlerts,
          alertThreshold,
          estimatedMonthlyCost: calculateEstimatedCost()
        } as any
      });

      toast({
        title: "Usage & Billing Configured",
        description: "Your pay-as-you-go billing has been set up successfully!",
      });

      onComplete();
    } catch (error: any) {
      console.error('Error setting up billing:', error);
      toast({
        title: "Setup Error",
        description: error.message || "Failed to configure billing settings",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const estimatedCost = calculateEstimatedCost();

  return (
    <div className="space-y-6">
      <div className="text-center">
        <DollarSign className="h-12 w-12 text-primary mx-auto mb-4" />
        <h2 className="text-2xl font-bold">Usage-Based Billing Setup</h2>
        <p className="text-muted-foreground">
          Configure your pay-as-you-go resource limits and billing preferences
        </p>
      </div>

      {/* Pricing Model Explanation */}
      <Card className="border-primary/20 bg-primary/5">
        <CardHeader>
          <CardTitle className="text-lg">Pay-As-You-Go Model</CardTitle>
          <CardDescription>
            Only pay for the resources you actually use. Set quotas to control costs and get alerts before overages.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            <div className="flex items-center space-x-2">
              <CheckCircle className="h-4 w-4 text-green-500" />
              <span>No upfront costs or commitments</span>
            </div>
            <div className="flex items-center space-x-2">
              <CheckCircle className="h-4 w-4 text-green-500" />
              <span>Scale resources up or down anytime</span>
            </div>
            <div className="flex items-center space-x-2">
              <CheckCircle className="h-4 w-4 text-green-500" />
              <span>Real-time usage monitoring</span>
            </div>
            <div className="flex items-center space-x-2">
              <CheckCircle className="h-4 w-4 text-green-500" />
              <span>Billing alerts and controls</span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Resource Quotas */}
      <Card>
        <CardHeader>
          <CardTitle>Resource Quotas</CardTitle>
          <CardDescription>
            Set monthly limits for each resource type to control costs
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {Object.entries(resourceConfig).map(([resourceType, config]) => {
            const Icon = config.icon;
            const quota = quotas[resourceType as keyof QuotaSettings];
            const monthlyCost = quota * config.costPerUnit;
            
            return (
              <div key={resourceType} className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <Icon className="h-5 w-5 text-primary" />
                    <div>
                      <div className="font-medium">{config.label}</div>
                      <div className="text-sm text-muted-foreground">{config.description}</div>
                    </div>
                  </div>
                  <Badge variant="outline">
                    {formatCurrency(monthlyCost)}/month
                  </Badge>
                </div>
                
                <div className="flex items-center space-x-4">
                  <div className="flex-1">
                    <Label htmlFor={`${resourceType}-quota`} className="text-sm">
                      Monthly Limit ({config.unit})
                    </Label>
                    <Input
                      id={`${resourceType}-quota`}
                      type="number"
                      value={quota}
                      onChange={(e) => updateQuota(resourceType as keyof QuotaSettings, Number.parseInt(e.target.value) || 0)}
                      className="mt-1"
                      min="0"
                    />
                  </div>
                  <div className="text-right text-sm text-muted-foreground">
                    {formatCurrency(config.costPerUnit)} per {config.unit.split(' ')[0]}
                  </div>
                </div>
              </div>
            );
          })}
        </CardContent>
      </Card>

      {/* Billing Settings */}
      <Card>
        <CardHeader>
          <CardTitle>Billing Preferences</CardTitle>
          <CardDescription>
            Configure how you want to manage your billing and alerts
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="billing-email">Billing Email</Label>
            <Input
              id="billing-email"
              type="email"
              value={billingEmail}
              onChange={(e) => setBillingEmail(e.target.value)}
              placeholder="billing@yourcompany.com"
            />
            <p className="text-xs text-muted-foreground">
              Invoices and billing alerts will be sent to this email
            </p>
          </div>

          <div className="flex items-center justify-between">
            <div>
              <div className="font-medium">Auto-scaling</div>
              <div className="text-sm text-muted-foreground">
                Automatically increase quotas when limits are reached (with 50% overage premium)
              </div>
            </div>
            <Switch
              checked={autoScaling}
              onCheckedChange={setAutoScaling}
            />
          </div>

          <div className="flex items-center justify-between">
            <div>
              <div className="font-medium">Billing Alerts</div>
              <div className="text-sm text-muted-foreground">
                Get notified when approaching usage limits
              </div>
            </div>
            <Switch
              checked={billingAlerts}
              onCheckedChange={setBillingAlerts}
            />
          </div>

          {billingAlerts && (
            <div className="space-y-2">
              <Label htmlFor="alert-threshold">Alert Threshold (%)</Label>
              <div className="flex items-center space-x-4">
                <Input
                  id="alert-threshold"
                  type="number"
                  value={alertThreshold}
                  onChange={(e) => setAlertThreshold(Math.min(100, Math.max(0, Number.parseInt(e.target.value) || 0)))}
                  className="w-20"
                  min="0"
                  max="100"
                />
                <Progress value={alertThreshold} className="flex-1" />
              </div>
              <p className="text-xs text-muted-foreground">
                Get alerts when usage reaches this percentage of your quota
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Cost Summary */}
      <Card className="border-secondary/20 bg-secondary/5">
        <CardHeader>
          <CardTitle className="flex items-center">
            <DollarSign className="h-5 w-5 mr-2" />
            Estimated Monthly Cost
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-3xl font-bold text-center text-primary">
            {formatCurrency(estimatedCost)}
          </div>
          <p className="text-center text-sm text-muted-foreground mt-2">
            Based on your current quota settings
          </p>
          <div className="mt-4 p-3 bg-yellow-500/10 rounded-lg border border-yellow-500/20">
            <div className="flex items-start space-x-2">
              <AlertCircle className="h-4 w-4 text-yellow-500 mt-0.5" />
              <div className="text-sm">
                <div className="font-medium text-yellow-700 dark:text-yellow-300">
                  Actual costs may vary
                </div>
                <div className="text-yellow-600 dark:text-yellow-400">
                  You'll only pay for resources you actually use, up to your quota limits.
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Action Buttons */}
      <div className="flex justify-between">
        <Button variant="outline" onClick={onSkip}>
          Skip for Now
        </Button>
        <Button 
          onClick={setupBilling} 
          disabled={loading}
          className="min-w-[140px]"
        >
          {loading ? 'Setting up...' : 'Complete Setup'}
        </Button>
      </div>
    </div>
  );
};