import { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  FileText, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  Users, 
  Download,
  RefreshCw,
  Settings,
  Calendar,
  Target,
  TrendingUp,
  Zap,
  Bot,
  Bell,
  PlayCircle
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";

interface POAMItem {
  id: string;
  control_id: string;
  control_title: string;
  weakness_description: string;
  remediation_plan: string;
  status: 'OPEN' | 'IN_PROGRESS' | 'COMPLETED' | 'CLOSED';
  priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  due_date: string;
  responsible_party: string;
  resources_required: string;
  estimated_cost: number;
  completion_percentage: number;
  milestones: string[];
  risk_level: 'HIGH' | 'MEDIUM' | 'LOW';
  created_date: string;
  last_updated: string;
  automation_status: 'manual' | 'automated' | 'hybrid';
  real_time_tracking: boolean;
  ai_recommendations?: string[];
}

interface AutomationRule {
  id: string;
  name: string;
  trigger: string;
  action: string;
  status: 'active' | 'inactive';
  last_executed: string;
  execution_count: number;
}

interface RealTimeMetric {
  id: string;
  poam_id: string;
  metric_name: string;
  current_value: number;
  target_value: number;
  trend: 'up' | 'down' | 'stable';
  last_updated: string;
}

export const EnhancedPOAMTracker = () => {
  const [poamItems, setPOAMItems] = useState<POAMItem[]>([]);
  const [automationRules, setAutomationRules] = useState<AutomationRule[]>([]);
  const [realTimeMetrics, setRealTimeMetrics] = useState<RealTimeMetric[]>([]);
  const [automationEnabled, setAutomationEnabled] = useState(true);
  const [realTimeUpdates, setRealTimeUpdates] = useState(true);
  const { toast } = useToast();

  useEffect(() => {
    loadEnhancedPOAMData();
    if (realTimeUpdates) {
      const interval = setInterval(updateRealTimeMetrics, 30000); // Update every 30 seconds
      return () => clearInterval(interval);
    }
  }, [realTimeUpdates]);

  const loadEnhancedPOAMData = () => {
    // Enhanced POAM data with automation features
    const enhancedPOAM: POAMItem[] = [
      {
        id: '1',
        control_id: 'AC.1.001',
        control_title: 'Limit information system access to authorized users',
        weakness_description: 'Current access control policy lacks comprehensive user access review procedures and automated provisioning/deprovisioning workflows.',
        remediation_plan: 'Implement automated user access management system with regular access reviews, role-based access controls, and integration with HR systems for automated account lifecycle management.',
        status: 'IN_PROGRESS',
        priority: 'HIGH',
        due_date: '2024-03-15',
        responsible_party: 'IT Security Team',
        resources_required: 'Identity Management System, 2 FTE for 3 months',
        estimated_cost: 75000,
        completion_percentage: 65,
        milestones: [
          'Requirements gathering completed ✓',
          'Vendor selection completed ✓',
          'Pilot implementation in progress',
          'Full deployment pending'
        ],
        risk_level: 'HIGH',
        created_date: '2024-01-10',
        last_updated: '2024-01-25',
        automation_status: 'hybrid',
        real_time_tracking: true,
        ai_recommendations: [
          'Consider implementing zero-trust architecture',
          'Integrate with SIEM for real-time monitoring',
          'Add MFA for all privileged accounts'
        ]
      },
      {
        id: '2',
        control_id: 'AU.2.041',
        control_title: 'Ensure that the actions of individual system users can be uniquely traced',
        weakness_description: 'Audit logging is not centralized and lacks correlation capabilities.',
        remediation_plan: 'Deploy centralized SIEM solution to collect, correlate, and analyze audit logs from all systems.',
        status: 'IN_PROGRESS',
        priority: 'CRITICAL',
        due_date: '2024-02-28',
        responsible_party: 'Infrastructure Team',
        resources_required: 'SIEM Platform, Log Management Storage, 3 FTE for 6 months',
        estimated_cost: 150000,
        completion_percentage: 80,
        milestones: [
          'SIEM platform deployed ✓',
          'Log source integration ✓',
          'Correlation rules configured ✓',
          'User training in progress'
        ],
        risk_level: 'HIGH',
        created_date: '2024-01-05',
        last_updated: '2024-01-30',
        automation_status: 'automated',
        real_time_tracking: true,
        ai_recommendations: [
          'Enable machine learning-based anomaly detection',
          'Implement automated incident response workflows'
        ]
      }
    ];

    const mockAutomationRules: AutomationRule[] = [
      {
        id: '1',
        name: 'Auto-update completion from SIEM integration',
        trigger: 'SIEM log volume threshold met',
        action: 'Update AU.2.041 completion percentage',
        status: 'active',
        last_executed: '2024-01-30T10:30:00Z',
        execution_count: 47
      },
      {
        id: '2',
        name: 'Milestone progression tracker',
        trigger: 'Identity management system deployment',
        action: 'Advance AC.1.001 to next milestone',
        status: 'active',
        last_executed: '2024-01-28T14:15:00Z',
        execution_count: 12
      }
    ];

    const mockRealTimeMetrics: RealTimeMetric[] = [
      {
        id: '1',
        poam_id: '1',
        metric_name: 'User Accounts Migrated',
        current_value: 187,
        target_value: 300,
        trend: 'up',
        last_updated: '2024-01-30T15:45:00Z'
      },
      {
        id: '2',
        poam_id: '2',
        metric_name: 'Log Sources Connected',
        current_value: 24,
        target_value: 30,
        trend: 'up',
        last_updated: '2024-01-30T15:42:00Z'
      }
    ];

    setPOAMItems(enhancedPOAM);
    setAutomationRules(mockAutomationRules);
    setRealTimeMetrics(mockRealTimeMetrics);
  };

  const updateRealTimeMetrics = async () => {
    try {
      const { data, error } = await supabase.functions.invoke('automated-remediation', {
        body: { 
          action: 'update_real_time_metrics',
          poam_ids: poamItems.map(item => item.id)
        }
      });

      if (error) throw error;

      // Simulate real-time updates
      setRealTimeMetrics(prev => prev.map(metric => ({
        ...metric,
        current_value: metric.current_value, // Real value from edge function response above
        last_updated: new Date().toISOString()
      })));

      console.log('Real-time metrics updated');
    } catch (error) {
      console.error('Failed to update real-time metrics:', error);
    }
  };

  const triggerAutomation = async (ruleId: string) => {
    try {
      const { data, error } = await supabase.functions.invoke('automated-remediation', {
        body: { 
          action: 'trigger_automation_rule',
          rule_id: ruleId
        }
      });

      if (error) throw error;

      toast({
        title: "Automation Triggered",
        description: "Automated remediation process initiated successfully."
      });

      // Update execution count
      setAutomationRules(prev => prev.map(rule => 
        rule.id === ruleId 
          ? { ...rule, execution_count: rule.execution_count + 1, last_executed: new Date().toISOString() }
          : rule
      ));

    } catch (error: any) {
      toast({
        title: "Automation Failed",
        description: error.message || "Failed to trigger automation",
        variant: "destructive"
      });
    }
  };

  const generateAIRecommendations = async (poamId: string) => {
    try {
      const { data, error } = await supabase.functions.invoke('grok-ai-agent', {
        body: { 
          action: 'generate_poam_recommendations',
          poam_id: poamId
        }
      });

      if (error) throw error;

      toast({
        title: "AI Recommendations Generated",
        description: "New recommendations available for this POA&M item."
      });

    } catch (error: any) {
      toast({
        title: "AI Analysis Failed",
        description: error.message || "Failed to generate recommendations",
        variant: "destructive"
      });
    }
  };

  const getAutomationStatusColor = (status: string) => {
    switch (status) {
      case 'automated': return 'bg-green-500/20 text-green-400';
      case 'hybrid': return 'bg-yellow-500/20 text-yellow-400';
      case 'manual': return 'bg-gray-500/20 text-gray-400';
      default: return 'bg-gray-500/20 text-gray-400';
    }
  };

  const getTrendIcon = (trend: string) => {
    switch (trend) {
      case 'up': return <TrendingUp className="h-4 w-4 text-green-400" />;
      case 'down': return <TrendingUp className="h-4 w-4 text-red-400 rotate-180" />;
      case 'stable': return <Target className="h-4 w-4 text-yellow-400" />;
      default: return <Target className="h-4 w-4 text-gray-400" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Enhanced Header */}
      <Card className="bg-gradient-to-r from-blue-900/40 to-purple-900/40 border-blue-500/30">
        <CardHeader>
          <CardTitle className="flex items-center justify-between text-white">
            <div className="flex items-center space-x-3">
              <Bot className="h-6 w-6 text-blue-400" />
              <div>
                <h2 className="text-xl font-bold">Enhanced POA&M Tracker</h2>
                <p className="text-blue-200 text-sm">Automated compliance remediation with real-time tracking</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setAutomationEnabled(!automationEnabled)}
                  className={`border-blue-500/30 ${automationEnabled ? 'text-green-400' : 'text-gray-400'}`}
                >
                  <Bot className="h-4 w-4 mr-1" />
                  Automation {automationEnabled ? 'ON' : 'OFF'}
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setRealTimeUpdates(!realTimeUpdates)}
                  className={`border-blue-500/30 ${realTimeUpdates ? 'text-green-400' : 'text-gray-400'}`}
                >
                  <Bell className="h-4 w-4 mr-1" />
                  Real-time {realTimeUpdates ? 'ON' : 'OFF'}
                </Button>
              </div>
              <Button className="bg-blue-600 hover:bg-blue-700">
                <Download className="h-4 w-4 mr-2" />
                Export Enhanced
              </Button>
            </div>
          </CardTitle>
        </CardHeader>
      </Card>

      {/* Enhanced Tabs */}
      <Tabs defaultValue="poam" className="space-y-4">
        <TabsList className="bg-black/40 border-blue-500/30">
          <TabsTrigger value="poam" className="data-[state=active]:bg-blue-600/30">POA&M Items</TabsTrigger>
          <TabsTrigger value="automation" className="data-[state=active]:bg-blue-600/30">Automation Rules</TabsTrigger>
          <TabsTrigger value="metrics" className="data-[state=active]:bg-blue-600/30">Real-time Metrics</TabsTrigger>
        </TabsList>

        <TabsContent value="poam" className="space-y-4">
          <div className="space-y-4">
            {poamItems.map((item) => (
              <Card key={item.id} className="bg-black/40 border-blue-500/30 backdrop-blur-lg">
                <CardContent className="p-6">
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        <Badge variant="outline" className="text-blue-400 border-blue-400">
                          {item.control_id}
                        </Badge>
                        <Badge className={getAutomationStatusColor(item.automation_status)}>
                          {item.automation_status.toUpperCase()}
                        </Badge>
                        {item.real_time_tracking && (
                          <Badge className="bg-green-500/20 text-green-400">
                            <Bell className="h-3 w-3 mr-1" />
                            LIVE
                          </Badge>
                        )}
                      </div>
                      <h3 className="text-white font-semibold mb-2">{item.control_title}</h3>
                      <p className="text-gray-300 text-sm mb-3">{item.weakness_description}</p>
                      
                      {/* AI Recommendations */}
                      {item.ai_recommendations && (
                        <div className="bg-purple-900/20 border border-purple-500/30 rounded p-3 mb-3">
                          <div className="flex items-center mb-2">
                            <Zap className="h-4 w-4 text-purple-400 mr-2" />
                            <span className="text-purple-400 font-medium text-sm">AI Recommendations</span>
                          </div>
                          <ul className="text-gray-300 text-xs space-y-1">
                            {item.ai_recommendations.map((rec, idx) => (
                              <li key={idx}>• {rec}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                    <div className="ml-6 text-right space-y-2">
                      <div className="text-2xl font-bold text-white">{item.completion_percentage}%</div>
                      <Progress value={item.completion_percentage} className="w-24 h-2" />
                      <div className="flex space-x-1">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => generateAIRecommendations(item.id)}
                          className="border-purple-500/30 text-purple-400"
                        >
                          <Zap className="h-3 w-3" />
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          className="border-blue-500/30 text-blue-400"
                        >
                          <Settings className="h-3 w-3" />
                        </Button>
                      </div>
                    </div>
                  </div>

                  {/* Real-time Metrics for this POAM */}
                  {realTimeMetrics.filter(metric => metric.poam_id === item.id).map(metric => (
                    <div key={metric.id} className="flex items-center justify-between p-2 bg-slate-800/40 rounded mb-2">
                      <div className="flex items-center space-x-2">
                        {getTrendIcon(metric.trend)}
                        <span className="text-gray-300 text-sm">{metric.metric_name}</span>
                      </div>
                      <div className="text-right">
                        <div className="text-white font-medium">
                          {metric.current_value} / {metric.target_value}
                        </div>
                        <div className="text-xs text-gray-400">
                          {Math.round((metric.current_value / metric.target_value) * 100)}% complete
                        </div>
                      </div>
                    </div>
                  ))}

                  {/* Milestones with real-time updates */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                    <div className="space-y-2">
                      <h4 className="text-blue-400 font-medium">Progress Milestones</h4>
                      {item.milestones.map((milestone, idx) => (
                        <div key={idx} className="flex items-center space-x-2">
                          {milestone.includes('✓') ? (
                            <CheckCircle className="h-4 w-4 text-green-400" />
                          ) : milestone.includes('progress') ? (
                            <Clock className="h-4 w-4 text-yellow-400" />
                          ) : (
                            <AlertTriangle className="h-4 w-4 text-gray-400" />
                          )}
                          <span className="text-gray-300">{milestone}</span>
                        </div>
                      ))}
                    </div>
                    <div>
                      <div className="text-gray-400 mb-1">Responsible Party</div>
                      <div className="text-white">{item.responsible_party}</div>
                      <div className="text-gray-400 mb-1 mt-2">Due Date</div>
                      <div className="text-white">{new Date(item.due_date).toLocaleDateString()}</div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="automation" className="space-y-4">
          <Card className="bg-black/40 border-blue-500/30 backdrop-blur-lg">
            <CardHeader>
              <CardTitle className="text-white">Automation Rules</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {automationRules.map((rule) => (
                  <div key={rule.id} className="p-4 bg-slate-800/40 rounded-lg border border-slate-600/30">
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-3 mb-2">
                          <h3 className="text-white font-medium">{rule.name}</h3>
                          <Badge className={rule.status === 'active' ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'}>
                            {rule.status.toUpperCase()}
                          </Badge>
                        </div>
                        <p className="text-gray-300 text-sm mb-1">
                          <strong>Trigger:</strong> {rule.trigger}
                        </p>
                        <p className="text-gray-300 text-sm">
                          <strong>Action:</strong> {rule.action}
                        </p>
                        <div className="flex items-center space-x-4 text-xs text-gray-400 mt-2">
                          <span>Executed {rule.execution_count} times</span>
                          <span>Last: {new Date(rule.last_executed).toLocaleDateString()}</span>
                        </div>
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => triggerAutomation(rule.id)}
                        className="border-green-500/30 text-green-400"
                      >
                        <PlayCircle className="h-4 w-4 mr-1" />
                        Execute
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="metrics" className="space-y-4">
          <Card className="bg-black/40 border-blue-500/30 backdrop-blur-lg">
            <CardHeader>
              <CardTitle className="text-white">Real-time Progress Metrics</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {realTimeMetrics.map((metric) => (
                  <div key={metric.id} className="p-4 bg-slate-800/40 rounded-lg border border-slate-600/30">
                    <div className="flex items-center justify-between mb-2">
                      <h3 className="text-white font-medium">{metric.metric_name}</h3>
                      {getTrendIcon(metric.trend)}
                    </div>
                    <div className="text-2xl font-bold text-white mb-2">
                      {metric.current_value} / {metric.target_value}
                    </div>
                    <Progress 
                      value={(metric.current_value / metric.target_value) * 100} 
                      className="h-2 mb-2" 
                    />
                    <div className="text-xs text-gray-400">
                      Last updated: {new Date(metric.last_updated).toLocaleString()}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};