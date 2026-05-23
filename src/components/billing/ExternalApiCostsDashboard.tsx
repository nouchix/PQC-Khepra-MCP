import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { useExternalApiTracking } from '@/hooks/useExternalApiTracking';
import { useToast } from '@/hooks/use-toast';
import { 
  DollarSign, 
  TrendingUp, 
  AlertTriangle, 
  Activity,
  Settings,
  BarChart3
} from 'lucide-react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell
} from 'recharts';

interface CostBreakdown {
  api_provider: string;
  total_cost: number;
  request_count: number;
  token_count: number;
  avg_cost_per_request: number;
}

interface UsageAlert {
  id: string;
  api_provider: string;
  alert_type: string;
  threshold_value: number;
  current_value: number;
  message: string;
  created_at: string;
}

export const ExternalApiCostsDashboard = () => {
  const [costData, setCostData] = useState<CostBreakdown[]>([]);
  const [usageStats, setUsageStats] = useState<any[]>([]);
  const [alerts, setAlerts] = useState<UsageAlert[]>([]);
  const [loading, setLoading] = useState(true);
  
  const { getCostBreakdown, getUsageStats } = useExternalApiTracking();
  const { toast } = useToast();

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    setLoading(true);
    try {
      const [costs, usage] = await Promise.all([
        getCostBreakdown(),
        getUsageStats()
      ]);

      setCostData(costs || []);
      setUsageStats(usage || []);

      // Derive live alerts from actual cost data: flag any provider consuming >90% of a $100 budget
      const liveAlerts: UsageAlert[] = (costs || [])
        .filter(c => c.total_cost >= 90)
        .map(c => ({
          id: c.api_provider,
          api_provider: c.api_provider,
          alert_type: 'cost_threshold',
          threshold_value: 100,
          current_value: c.total_cost,
          message: `${c.api_provider} costs approaching monthly budget limit ($${c.total_cost.toFixed(2)} / $100)`,
          created_at: new Date().toISOString()
        }));
      setAlerts(liveAlerts);
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
      toast({
        title: "Data Loading Error",
        description: "Failed to load cost dashboard data",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const totalMonthlyCost = costData.reduce((sum, item) => sum + item.total_cost, 0);
  
  const pieColors = ['#8b5cf6', '#06b6d4', '#10b981', '#f59e0b', '#ef4444'];

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 2
    }).format(amount);
  };

  if (loading) {
    return (
      <div className="p-6 space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Card key={i} className="animate-pulse">
              <CardContent className="p-6">
                <div className="h-20 bg-muted rounded"></div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">External API Costs</h2>
          <p className="text-muted-foreground">
            Monitor and manage your external API usage and costs
          </p>
        </div>
        <Button variant="outline" onClick={fetchDashboardData}>
          <Activity className="mr-2 h-4 w-4" />
          Refresh Data
        </Button>
      </div>

      {/* Alert Banner */}
      {alerts.length > 0 && (
        <Card className="border-destructive bg-destructive/5">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              <div className="flex-1">
                <h4 className="font-semibold text-destructive">Cost Alerts</h4>
                <p className="text-sm text-muted-foreground">
                  {alerts[0].message}
                </p>
              </div>
              <Badge variant="destructive">{alerts.length}</Badge>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Cost Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center">
              <div className="p-2 bg-primary/10 rounded-lg">
                <DollarSign className="h-6 w-6 text-primary" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-muted-foreground">Total Monthly Cost</p>
                <p className="text-2xl font-bold">{formatCurrency(totalMonthlyCost)}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center">
              <div className="p-2 bg-blue-500/10 rounded-lg">
                <TrendingUp className="h-6 w-6 text-blue-500" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-muted-foreground">API Requests</p>
                <p className="text-2xl font-bold">
                  {costData.reduce((sum, item) => sum + item.request_count, 0).toLocaleString()}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center">
              <div className="p-2 bg-green-500/10 rounded-lg">
                <BarChart3 className="h-6 w-6 text-green-500" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-muted-foreground">Tokens Used</p>
                <p className="text-2xl font-bold">
                  {costData.reduce((sum, item) => sum + item.token_count, 0).toLocaleString()}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center">
              <div className="p-2 bg-orange-500/10 rounded-lg">
                <Settings className="h-6 w-6 text-orange-500" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-muted-foreground">Active APIs</p>
                <p className="text-2xl font-bold">{costData.length}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="breakdown">Cost Breakdown</TabsTrigger>
          <TabsTrigger value="usage">Usage Trends</TabsTrigger>
          <TabsTrigger value="limits">Rate Limits</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Cost Distribution */}
            <Card>
              <CardHeader>
                <CardTitle>Cost Distribution by Provider</CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={costData}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ api_provider, total_cost }) => 
                        `${api_provider}: ${formatCurrency(total_cost)}`
                      }
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="total_cost"
                    >
                      {costData.map((entry, index) => (
                        <Cell 
                          key={`cell-${index}`} 
                          fill={pieColors[index % pieColors.length]} 
                        />
                      ))}
                    </Pie>
                    <Tooltip formatter={(value: number) => formatCurrency(value)} />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            {/* Provider Details */}
            <Card>
              <CardHeader>
                <CardTitle>Provider Details</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {costData.map((provider, index) => (
                  <div key={provider.api_provider} className="space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <div 
                          className="w-3 h-3 rounded-full" 
                          style={{ backgroundColor: pieColors[index % pieColors.length] }}
                        />
                        <span className="font-medium capitalize">{provider.api_provider}</span>
                      </div>
                      <span className="text-sm font-bold">{formatCurrency(provider.total_cost)}</span>
                    </div>
                    <Progress 
                      value={(provider.total_cost / totalMonthlyCost) * 100} 
                      className="h-2"
                    />
                    <div className="flex justify-between text-sm text-muted-foreground">
                      <span>{provider.request_count} requests</span>
                      <span>{provider.token_count?.toLocaleString()} tokens</span>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="breakdown" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Detailed Cost Breakdown</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {costData.map((provider) => (
                  <div key={provider.api_provider} className="p-4 border rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="font-semibold capitalize">{provider.api_provider}</h4>
                      <Badge variant="outline">{formatCurrency(provider.total_cost)}</Badge>
                    </div>
                    <div className="grid grid-cols-3 gap-4 text-sm">
                      <div>
                        <p className="text-muted-foreground">Requests</p>
                        <p className="font-medium">{provider.request_count.toLocaleString()}</p>
                      </div>
                      <div>
                        <p className="text-muted-foreground">Tokens</p>
                        <p className="font-medium">{provider.token_count?.toLocaleString() || 'N/A'}</p>
                      </div>
                      <div>
                        <p className="text-muted-foreground">Avg/Request</p>
                        <p className="font-medium">{formatCurrency(provider.avg_cost_per_request)}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="usage" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Usage Trends (Last 30 Days)</CardTitle>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={400}>
                <LineChart data={usageStats}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis 
                    dataKey="created_at" 
                    tickFormatter={(value) => new Date(value).toLocaleDateString()}
                  />
                  <YAxis />
                  <Tooltip 
                    labelFormatter={(value) => new Date(value).toLocaleDateString()}
                    formatter={(value: number, name: string) => [
                      name === 'estimated_cost' ? formatCurrency(value) : value,
                      name
                    ]}
                  />
                  <Line 
                    type="monotone" 
                    dataKey="estimated_cost" 
                    stroke="#8b5cf6" 
                    strokeWidth={2}
                    name="Cost"
                  />
                  <Line 
                    type="monotone" 
                    dataKey="tokens_used" 
                    stroke="#06b6d4" 
                    strokeWidth={2}
                    name="Tokens"
                  />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="limits" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Rate Limit Status</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                {/* This would be populated with real rate limit data */}
                <div className="text-center text-muted-foreground py-8">
                  Rate limit monitoring will be displayed here once usage data is available.
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};