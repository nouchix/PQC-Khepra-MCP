import { useState, useEffect } from 'react';
import { useOrganizationContext } from "@/components/OrganizationProvider";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { supabase } from "@/integrations/supabase/client";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line, PieChart, Pie, Cell } from 'recharts';
import { TrendingUp, TrendingDown, AlertTriangle, CheckCircle, Clock, Target, Activity, Shield } from 'lucide-react';

interface AnalyticsMetric {
  id: string;
  metric_type: string;
  metric_value: number;
  metric_unit: string;
  measurement_period_start: string;
  measurement_period_end: string;
  metadata: any;
}

interface ComplianceReport {
  id: string;
  report_name: string;
  report_type: string;
  compliance_percentage: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  generated_at: string;
  status: string;
}

export const STIGAnalyticsDashboard = () => {
  const [metrics, setMetrics] = useState<AnalyticsMetric[]>([]);
  const [reports, setReports] = useState<ComplianceReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedTimeframe, setSelectedTimeframe] = useState('7d');
  const [activeTab, setActiveTab] = useState('overview');
  const { currentOrganization } = useOrganizationContext();

  useEffect(() => {
    if (currentOrganization?.id) {
      fetchAnalyticsData();
    }
  }, [currentOrganization?.id, selectedTimeframe]);

  const fetchAnalyticsData = async () => {
    try {
      setLoading(true);
      
      // Calculate date range based on selected timeframe
      const endDate = new Date();
      const startDate = new Date();
      switch (selectedTimeframe) {
        case '24h':
          startDate.setDate(endDate.getDate() - 1);
          break;
        case '7d':
          startDate.setDate(endDate.getDate() - 7);
          break;
        case '30d':
          startDate.setDate(endDate.getDate() - 30);
          break;
        case '90d':
          startDate.setDate(endDate.getDate() - 90);
          break;
      }

      // Fetch metrics
      const { data: metricsData, error: metricsError } = await supabase
        .from('stig_analytics_metrics')
        .select('*')
        .eq('organization_id', currentOrganization.id)
        .gte('measurement_period_start', startDate.toISOString())
        .lte('measurement_period_end', endDate.toISOString())
        .order('measurement_period_start', { ascending: false });

      if (metricsError) throw metricsError;

      // Fetch reports
      const { data: reportsData, error: reportsError } = await supabase
        .from('stig_compliance_reports')
        .select('*')
        .eq('organization_id', currentOrganization.id)
        .order('generated_at', { ascending: false })
        .limit(10);

      if (reportsError) throw reportsError;

      setMetrics(metricsData || []);
      setReports(reportsData || []);
    } catch (error) {
      console.error('Error fetching analytics data:', error);
    } finally {
      setLoading(false);
    }
  };

  const generateReport = async (reportType: string) => {
    try {
      const { data, error } = await supabase.functions.invoke('stig-intelligence-orchestrator', {
        body: {
          action: 'generate_compliance_report',
          organization_id: currentOrganization?.id,
          report_type: reportType,
          scope: {
            timeframe: selectedTimeframe,
            include_trends: true,
            include_recommendations: true
          }
        }
      });

      if (error) throw error;
      
      // Refresh reports
      fetchAnalyticsData();
    } catch (error) {
      console.error('Error generating report:', error);
    }
  };

  // Calculate summary metrics
  const complianceScoreMetrics = metrics.filter(m => m.metric_type === 'compliance_score');
  const currentComplianceScore = complianceScoreMetrics.length > 0 ? 
    complianceScoreMetrics[0].metric_value : 0;

  const driftRateMetrics = metrics.filter(m => m.metric_type === 'drift_rate');
  const remediationTimeMetrics = metrics.filter(m => m.metric_type === 'remediation_time');

  // Prepare chart data
  const complianceTrendData = complianceScoreMetrics.map(metric => ({
    date: new Date(metric.measurement_period_start).toLocaleDateString(),
    score: metric.metric_value
  }));

  const findingsDistribution = [
    { name: 'Critical', value: reports.reduce((sum, r) => sum + r.critical_findings, 0), color: '#ef4444' },
    { name: 'High', value: reports.reduce((sum, r) => sum + r.high_findings, 0), color: '#f97316' },
    { name: 'Medium', value: reports.reduce((sum, r) => sum + r.medium_findings, 0), color: '#eab308' },
    { name: 'Low', value: reports.reduce((sum, r) => sum + r.low_findings, 0), color: '#22c55e' }
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="text-white">Loading analytics data...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">STIG Analytics Dashboard</h2>
          <p className="text-gray-300">Advanced compliance metrics and reporting</p>
        </div>
        <div className="flex items-center space-x-4">
          <Select value={selectedTimeframe} onValueChange={setSelectedTimeframe}>
            <SelectTrigger className="w-32">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="24h">Last 24h</SelectItem>
              <SelectItem value="7d">Last 7 days</SelectItem>
              <SelectItem value="30d">Last 30 days</SelectItem>
              <SelectItem value="90d">Last 90 days</SelectItem>
            </SelectContent>
          </Select>
          <Button onClick={() => generateReport('executive')}>
            Generate Report
          </Button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium text-gray-300">Compliance Score</CardTitle>
              <Shield className="h-4 w-4 text-blue-400" />
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">{currentComplianceScore.toFixed(1)}%</div>
            <div className="flex items-center space-x-1 text-xs">
              {currentComplianceScore >= 80 ? (
                <TrendingUp className="h-3 w-3 text-green-400" />
              ) : (
                <TrendingDown className="h-3 w-3 text-red-400" />
              )}
              <span className={currentComplianceScore >= 80 ? "text-green-400" : "text-red-400"}>
                {currentComplianceScore >= 80 ? "Above target" : "Below target"}
              </span>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium text-gray-300">Active Violations</CardTitle>
              <AlertTriangle className="h-4 w-4 text-orange-400" />
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">
              {reports.reduce((sum, r) => sum + r.critical_findings + r.high_findings, 0)}
            </div>
            <p className="text-xs text-gray-400">Critical & High severity</p>
          </CardContent>
        </Card>

        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium text-gray-300">Avg Remediation Time</CardTitle>
              <Clock className="h-4 w-4 text-purple-400" />
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">
              {remediationTimeMetrics.length > 0 ? 
                `${(remediationTimeMetrics.reduce((sum, m) => sum + m.metric_value, 0) / remediationTimeMetrics.length / 3600).toFixed(1)}h` :
                '0h'
              }
            </div>
            <p className="text-xs text-gray-400">Time to resolve</p>
          </CardContent>
        </Card>

        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium text-gray-300">Configuration Drift</CardTitle>
              <Activity className="h-4 w-4 text-cyan-400" />
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">
              {driftRateMetrics.length > 0 ? 
                `${driftRateMetrics[0].metric_value.toFixed(1)}%` :
                '0%'
              }
            </div>
            <p className="text-xs text-gray-400">Current drift rate</p>
          </CardContent>
        </Card>
      </div>

      {/* Analytics Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="bg-slate-800/50 border border-slate-700">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="trends">Trends</TabsTrigger>
          <TabsTrigger value="findings">Findings</TabsTrigger>
          <TabsTrigger value="reports">Reports</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white">Compliance Trend</CardTitle>
                <CardDescription>7-day compliance score trend</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={complianceTrendData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis dataKey="date" stroke="#9CA3AF" />
                    <YAxis stroke="#9CA3AF" />
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151' }}
                      labelStyle={{ color: '#F3F4F6' }}
                    />
                    <Line type="monotone" dataKey="score" stroke="#3B82F6" strokeWidth={2} />
                  </LineChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white">Findings Distribution</CardTitle>
                <CardDescription>Breakdown by severity level</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={findingsDistribution}
                      cx="50%"
                      cy="50%"
                      outerRadius={100}
                      fill="#8884d8"
                      dataKey="value"
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    >
                      {findingsDistribution.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151' }} />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="trends" className="space-y-4">
          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white">Historical Metrics</CardTitle>
              <CardDescription>Compliance metrics over time</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={400}>
                <LineChart data={complianceTrendData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="date" stroke="#9CA3AF" />
                  <YAxis stroke="#9CA3AF" />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151' }}
                    labelStyle={{ color: '#F3F4F6' }}
                  />
                  <Line type="monotone" dataKey="score" stroke="#3B82F6" strokeWidth={2} />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="findings" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {findingsDistribution.map((finding, index) => (
              <Card key={index} className="bg-slate-800/50 border-slate-700">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm font-medium text-gray-300">{finding.name} Severity</CardTitle>
                    <div className="w-3 h-3 rounded-full" style={{ backgroundColor: finding.color }}></div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-white">{finding.value}</div>
                  <p className="text-xs text-gray-400">Active findings</p>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="reports" className="space-y-4">
          <div className="grid gap-4">
            {reports.map((report) => (
              <Card key={report.id} className="bg-slate-800/50 border-slate-700">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="font-semibold text-white">{report.report_name}</h3>
                      <p className="text-sm text-gray-400">
                        Generated {new Date(report.generated_at).toLocaleDateString()}
                      </p>
                    </div>
                    <div className="flex items-center space-x-4">
                      <Badge variant="outline" className="text-white">
                        {report.compliance_percentage}% Compliant
                      </Badge>
                      <Badge variant={report.status === 'generated' ? 'default' : 'secondary'}>
                        {report.status}
                      </Badge>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};