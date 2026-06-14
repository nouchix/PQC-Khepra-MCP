
import { useNavigate } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { useExecutiveAI } from '@/hooks/useExecutiveAI';
import { Shield, TrendingUp, AlertTriangle, CheckCircle, Users, Eye, BarChart3, Target } from 'lucide-react';

interface ExecutiveDashboardModeProps {
  isExecutiveMode: boolean;
  onToggle: (enabled: boolean) => void;
}

export const ExecutiveDashboardMode = ({ isExecutiveMode, onToggle }: ExecutiveDashboardModeProps) => {
  const navigate = useNavigate();
  const { getThreatAnalysis, getCMMCPlanning, getTeamPerformance, getSecurityReport, loading } = useExecutiveAI();
  const executiveMetrics = [
    {
      title: 'Security Posture',
      value: '87%',
      trend: '+5%',
      status: 'good',
      icon: Shield,
      description: 'Overall security health score'
    },
    {
      title: 'CMMC Progress',
      value: '73%',
      trend: '+12%',
      status: 'progress',
      icon: Target,
      description: 'Certification readiness'
    },
    {
      title: 'Active Threats',
      value: '3',
      trend: '-2',
      status: 'warning',
      icon: AlertTriangle,
      description: 'Threats requiring attention'
    },
    {
      title: 'Team Members',
      value: '24',
      trend: '+3',
      status: 'good',
      icon: Users,
      description: 'Active security team'
    }
  ];

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'good': return 'text-success';
      case 'warning': return 'text-warning';
      case 'danger': return 'text-destructive';
      default: return 'text-primary';
    }
  };

  const getStatusBg = (status: string) => {
    switch (status) {
      case 'good': return 'bg-success/10';
      case 'warning': return 'bg-warning/10';
      case 'danger': return 'bg-destructive/10';
      default: return 'bg-primary/10';
    }
  };

  if (!isExecutiveMode) {
    return (
      <Card className="border-primary/20">
        <CardContent className="p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Eye className="h-5 w-5 text-primary" />
              <div>
                <h3 className="font-medium">Executive Summary Mode</h3>
                <p className="text-sm text-muted-foreground">
                  Simplified view with high-level KPIs
                </p>
              </div>
            </div>
            <Switch
              checked={isExecutiveMode}
              onCheckedChange={onToggle}
            />
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Executive Mode Header */}
      <Card className="border-primary/20 bg-gradient-to-r from-primary/5 to-secondary/5">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-primary/10 rounded-lg">
                <BarChart3 className="h-6 w-6 text-primary" />
              </div>
              <div>
                <CardTitle className="text-xl">Executive Security Overview</CardTitle>
                <p className="text-sm text-muted-foreground">
                  High-level security metrics and organizational health
                </p>
              </div>
            </div>
            <div className="flex items-center space-x-2">
              <Badge variant="outline" className="text-primary border-primary/50">
                Executive Mode
              </Badge>
              <Switch
                checked={isExecutiveMode}
                onCheckedChange={onToggle}
              />
            </div>
          </div>
        </CardHeader>
      </Card>

      {/* Key Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {executiveMetrics.map((metric) => {
          const Icon = metric.icon;
          return (
            <Card key={metric.title} className="hover:shadow-md transition-shadow">
              <CardContent className="p-6">
                <div className="flex items-start justify-between">
                  <div className={`p-2 rounded-lg ${getStatusBg(metric.status)}`}>
                    <Icon className={`h-5 w-5 ${getStatusColor(metric.status)}`} />
                  </div>
                  <Badge 
                    variant="outline" 
                    className={`text-xs ${getStatusColor(metric.status)} border-current`}
                  >
                    {metric.trend}
                  </Badge>
                </div>
                <div className="mt-4">
                  <div className="text-2xl font-bold">{metric.value}</div>
                  <div className="text-sm font-medium text-foreground">{metric.title}</div>
                  <div className="text-xs text-muted-foreground mt-1">
                    {metric.description}
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Key Actions */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Target className="h-5 w-5" />
            <span>Priority Actions</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            <div className="flex items-center justify-between p-3 bg-warning/10 border border-warning/20 rounded-lg">
              <div className="flex items-center space-x-3">
                <AlertTriangle className="h-5 w-5 text-warning" />
                <div>
                  <div className="font-medium">Review 3 Active Threats</div>
                  <div className="text-sm text-muted-foreground">
                    Security team requires executive decision
                  </div>
                </div>
              </div>
              <Button 
                variant="outline" 
                size="sm"
                disabled={loading}
                onClick={async () => {
                  await getThreatAnalysis();
                  navigate('/security?tab=threats&view=executive');
                }}
              >
                {loading ? 'Analyzing...' : 'Review'}
              </Button>
            </div>

            <div className="flex items-center justify-between p-3 bg-primary/10 border border-primary/20 rounded-lg">
              <div className="flex items-center space-x-3">
                <Target className="h-5 w-5 text-primary" />
                <div>
                  <div className="font-medium">CMMC Certification Planning</div>
                  <div className="text-sm text-muted-foreground">
                    73% complete - review timeline and budget
                  </div>
                </div>
              </div>
              <Button 
                variant="outline" 
                size="sm"
                disabled={loading}
                onClick={async () => {
                  await getCMMCPlanning();
                  navigate('/compliance-automation?view=cmmc&mode=executive');
                }}
              >
                {loading ? 'Planning...' : 'Plan'}
              </Button>
            </div>

            <div className="flex items-center justify-between p-3 bg-success/10 border border-success/20 rounded-lg">
              <div className="flex items-center space-x-3">
                <CheckCircle className="h-5 w-5 text-success" />
                <div>
                  <div className="font-medium">Team Performance Review</div>
                  <div className="text-sm text-muted-foreground">
                    Security team exceeding KPIs this quarter
                  </div>
                </div>
              </div>
              <Button 
                variant="outline" 
                size="sm"
                disabled={loading}
                onClick={async () => {
                  await getTeamPerformance();
                  navigate('/admin?tab=performance&view=executive');
                }}
              >
                {loading ? 'Generating...' : 'View Report'}
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Quick Access */}
      <Card>
        <CardHeader>
          <CardTitle>Quick Access</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
            <Button 
              variant="outline" 
              className="h-20 flex-col space-y-2"
              disabled={loading}
              onClick={async () => {
                await getSecurityReport();
                navigate('/security?view=executive');
              }}
            >
              <Shield className="h-5 w-5" />
              <span className="text-xs">{loading ? 'Generating...' : 'Security Report'}</span>
            </Button>
            <Button 
              variant="outline" 
              className="h-20 flex-col space-y-2"
              onClick={() => navigate('/compliance-automation?view=cmmc')}
            >
              <Target className="h-5 w-5" />
              <span className="text-xs">CMMC Status</span>
            </Button>
            <Button 
              variant="outline" 
              className="h-20 flex-col space-y-2"
              onClick={() => navigate('/admin?tab=team')}
            >
              <Users className="h-5 w-5" />
              <span className="text-xs">Team Dashboard</span>
            </Button>
            <Button 
              variant="outline" 
              className="h-20 flex-col space-y-2"
              onClick={() => navigate('/billing?view=analytics')}
            >
              <TrendingUp className="h-5 w-5" />
              <span className="text-xs">Analytics</span>
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};