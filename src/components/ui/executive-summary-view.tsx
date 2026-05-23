
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Button } from '@/components/ui/button';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  TrendingUp,
  Activity,
  ArrowRight,
  ExternalLink
} from 'lucide-react';
import { useNavigate } from '@/lib/router-compat';
import { useExecutiveAI } from '@/hooks/useExecutiveAI';

interface ExecutiveSummaryViewProps {
  metrics: {
    systemHealth: number;
    activeThreats: number;
    blockedAttacks: number;
    complianceScore: number;
  };
}

export const ExecutiveSummaryView: React.FC<ExecutiveSummaryViewProps> = ({ metrics }) => {
  const navigate = useNavigate();
  const { getThreatAnalysis, getCMMCPlanning, getTeamPerformance, loading } = useExecutiveAI();

  const getOverallStatus = () => {
    const avgScore = (metrics.systemHealth + metrics.complianceScore) / 2;
    if (avgScore >= 90) return { status: 'Excellent', color: 'text-success', bg: 'bg-success/10' };
    if (avgScore >= 80) return { status: 'Good', color: 'text-primary', bg: 'bg-primary/10' };
    if (avgScore >= 70) return { status: 'Fair', color: 'text-warning', bg: 'bg-warning/10' };
    return { status: 'Needs Attention', color: 'text-destructive', bg: 'bg-destructive/10' };
  };

  const overallStatus = getOverallStatus();

  const priorityActions = [
    {
      title: 'Review Active Threats',
      description: `${metrics.activeThreats} threats require attention`,
      action: () => navigate('/security?tab=threats'),
      priority: metrics.activeThreats > 5 ? 'high' : 'medium'
    },
    {
      title: 'Compliance Review',
      description: `${metrics.complianceScore}% compliance score`,
      action: () => navigate('/compliance-automation'),
      priority: metrics.complianceScore < 90 ? 'high' : 'low'
    },
    {
      title: 'Deploy Security Agents',
      description: 'Expand protection coverage',
      action: () => navigate('/integration-guide'),
      priority: 'medium'
    }
  ];

  return (
    <div className="space-y-6">
      {/* Executive Overview */}
      <Card className="card-cyber border-2 border-primary/20">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-2xl font-bold">Security Posture Overview</CardTitle>
              <p className="text-muted-foreground">Executive summary of current security status</p>
            </div>
            <div className={`px-4 py-2 rounded-lg ${overallStatus.bg}`}>
              <div className={`text-lg font-bold ${overallStatus.color}`}>
                {overallStatus.status}
              </div>
            </div>
          </div>
        </CardHeader>
      </Card>

      {/* Key Metrics - Simplified */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="card-cyber">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm text-muted-foreground">System Health</CardTitle>
              <Activity className="h-5 w-5 text-success" />
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-success mb-2">{metrics.systemHealth}%</div>
            <Progress value={metrics.systemHealth} className="h-2" />
            <p className="text-xs text-muted-foreground mt-2">All systems operational</p>
          </CardContent>
        </Card>

        <Card className="card-cyber">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm text-muted-foreground">Threat Status</CardTitle>
              <AlertTriangle className={`h-5 w-5 ${metrics.activeThreats > 5 ? 'text-destructive' : 'text-warning'}`} />
            </div>
          </CardHeader>
          <CardContent>
            <div className={`text-3xl font-bold mb-2 ${metrics.activeThreats > 5 ? 'text-destructive' : 'text-warning'}`}>
              {metrics.activeThreats}
            </div>
            <div className="text-xs text-muted-foreground">
              {metrics.blockedAttacks} attacks blocked today
            </div>
            <Badge 
              variant={metrics.activeThreats > 5 ? "destructive" : "secondary"} 
              className="text-xs mt-2"
            >
              {metrics.activeThreats > 5 ? 'Action Required' : 'Monitoring'}
            </Badge>
          </CardContent>
        </Card>

        <Card className="card-cyber">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm text-muted-foreground">Compliance</CardTitle>
              <CheckCircle className="h-5 w-5 text-primary" />
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-primary mb-2">{metrics.complianceScore}%</div>
            <Progress value={metrics.complianceScore} className="h-2" />
            <p className="text-xs text-muted-foreground mt-2">CMMC Level 3 ready</p>
          </CardContent>
        </Card>
      </div>

      {/* Priority Actions */}
      <Card className="card-cyber">
        <CardHeader>
          <CardTitle className="text-lg flex items-center space-x-2">
            <TrendingUp className="h-5 w-5 text-accent" />
            <span>Priority Actions</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {priorityActions.map((action, index) => (
              <div 
                key={index}
                className={`flex items-center justify-between p-3 rounded-lg border ${
                  action.priority === 'high' 
                    ? 'border-destructive/30 bg-destructive/5' 
                    : action.priority === 'medium'
                    ? 'border-warning/30 bg-warning/5'
                    : 'border-border bg-muted/20'
                }`}
              >
                <div>
                  <div className="font-medium">{action.title}</div>
                  <div className="text-sm text-muted-foreground">{action.description}</div>
                </div>
                <div className="flex items-center space-x-2">
                  <Badge 
                    variant={action.priority === 'high' ? 'destructive' : action.priority === 'medium' ? 'secondary' : 'outline'}
                    className="text-xs"
                  >
                    {action.priority}
                  </Badge>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={loading}
                    onClick={async () => {
                      if (action.title.includes('Threat')) {
                        await getThreatAnalysis();
                        navigate('/security?tab=threats&view=executive');
                      } else if (action.title.includes('Compliance')) {
                        await getCMMCPlanning();
                        navigate('/compliance-automation?view=cmmc&mode=executive');
                      } else {
                        await getTeamPerformance();
                        navigate('/admin?tab=performance&view=executive');
                      }
                    }}
                    className="flex items-center space-x-1"
                  >
                    <span>{loading ? 'Processing...' : 'View'}</span>
                    <ArrowRight className="h-3 w-3" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Quick Access */}
      <Card className="card-cyber">
        <CardHeader>
          <CardTitle className="text-lg">Quick Access</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Button 
              variant="outline" 
              className="h-auto p-4 flex-col space-y-2"
              onClick={() => navigate('/security')}
            >
              <Shield className="h-5 w-5" />
              <span className="text-xs">Security Hub</span>
            </Button>
            <Button 
              variant="outline" 
              className="h-auto p-4 flex-col space-y-2"
              onClick={() => navigate('/khepra')}
            >
              <Activity className="h-5 w-5" />
              <span className="text-xs">KHEPRA Protocol</span>
            </Button>
            <Button 
              variant="outline" 
              className="h-auto p-4 flex-col space-y-2"
              onClick={() => navigate('/compliance-automation')}
            >
              <CheckCircle className="h-5 w-5" />
              <span className="text-xs">Compliance</span>
            </Button>
            <Button 
              variant="outline" 
              className="h-auto p-4 flex-col space-y-2"
              onClick={() => navigate('/billing')}
            >
              <ExternalLink className="h-5 w-5" />
              <span className="text-xs">Reports</span>
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};