import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Button } from '@/components/ui/button';
import { 
  Shield, 
  TrendingUp, 
  AlertTriangle, 
  CheckCircle2, 
  Clock,
  Target,
  Activity,
  Users
} from 'lucide-react';
import { AutomationLevel, DeploymentProfile } from '@/types/deployment';

interface TrustMetrics {
  currentScore: number;
  trend: 'up' | 'down' | 'stable';
  successfulActions: number;
  totalActions: number;
  averageResponseTime: number;
  riskMitigated: number;
  nextPromotionScore: number;
  timeToPromotion: string;
}

interface TrustScoreDashboardProps {
  organizationId: string;
  deploymentProfile: DeploymentProfile;
  trustMetrics: TrustMetrics;
  onUpgradeAutomation?: () => void;
  onViewDetails?: () => void;
}

export const TrustScoreDashboard: React.FC<TrustScoreDashboardProps> = ({
  organizationId,
  deploymentProfile,
  trustMetrics,
  onUpgradeAutomation,
  onViewDetails
}) => {
  const getTrustColor = (score: number) => {
    if (score >= 90) return 'text-success';
    if (score >= 75) return 'text-warning';
    return 'text-destructive';
  };

  const getTrustBgColor = (score: number) => {
    if (score >= 90) return 'bg-success/10 border-success/20';
    if (score >= 75) return 'bg-warning/10 border-warning/20';
    return 'bg-destructive/10 border-destructive/20';
  };

  const getAutomationLevelDisplay = (level: AutomationLevel) => {
    const levels = {
      monitor_only: { label: 'Monitor Only', color: 'secondary' },
      guided: { label: 'Guided', color: 'default' },
      semi_automated: { label: 'Semi-Automated', color: 'secondary' },
      fully_automated: { label: 'Fully Automated', color: 'default' }
    };
    return levels[level];
  };

  const canUpgrade = trustMetrics.currentScore >= trustMetrics.nextPromotionScore;
  const automationDisplay = getAutomationLevelDisplay(deploymentProfile.automationLevel);

  return (
    <div className="space-y-6">
      {/* Trust Score Overview */}
      <Card className={`${getTrustBgColor(trustMetrics.currentScore)}`}>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Shield className={`h-5 w-5 ${getTrustColor(trustMetrics.currentScore)}`} />
              <CardTitle className="text-lg">Organization Trust Score</CardTitle>
            </div>
            <Badge variant={automationDisplay.color as any}>
              {automationDisplay.label}
            </Badge>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between mb-4">
            <div className="text-3xl font-bold flex items-center space-x-2">
              <span className={getTrustColor(trustMetrics.currentScore)}>
                {trustMetrics.currentScore}%
              </span>
              {trustMetrics.trend === 'up' && (
                <TrendingUp className="h-5 w-5 text-success" />
              )}
              {trustMetrics.trend === 'down' && (
                <AlertTriangle className="h-5 w-5 text-destructive" />
              )}
            </div>
            <div className="text-right">
              <div className="text-sm text-muted-foreground">Next Level</div>
              <div className="font-semibold">{trustMetrics.nextPromotionScore}%</div>
            </div>
          </div>
          
          <Progress 
            value={trustMetrics.currentScore} 
            className="h-3 mb-4"
          />
          
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-muted-foreground">Success Rate:</span>
              <span className="ml-2 font-medium">
                {Math.round((trustMetrics.successfulActions / trustMetrics.totalActions) * 100)}%
              </span>
            </div>
            <div>
              <span className="text-muted-foreground">Time to Promotion:</span>
              <span className="ml-2 font-medium">{trustMetrics.timeToPromotion}</span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Performance Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-2xl font-bold text-primary">
                  {trustMetrics.successfulActions}
                </div>
                <div className="text-sm text-muted-foreground">
                  Successful Actions
                </div>
              </div>
              <CheckCircle2 className="h-8 w-8 text-success" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-2xl font-bold text-primary">
                  {trustMetrics.averageResponseTime}s
                </div>
                <div className="text-sm text-muted-foreground">
                  Avg Response Time
                </div>
              </div>
              <Clock className="h-8 w-8 text-primary" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-2xl font-bold text-primary">
                  {trustMetrics.riskMitigated}
                </div>
                <div className="text-sm text-muted-foreground">
                  Risks Mitigated
                </div>
              </div>
              <Target className="h-8 w-8 text-warning" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Deployment Profile */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Activity className="h-5 w-5" />
            <span>Current Deployment Profile</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <div>
                <label className="text-sm font-medium text-muted-foreground">Industry</label>
                <div className="text-base capitalize">{deploymentProfile.industry}</div>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">Risk Tolerance</label>
                <div className="text-base capitalize">{deploymentProfile.riskTolerance.replaceAll('_', ' ')}</div>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">Monitoring Level</label>
                <div className="text-base capitalize">{deploymentProfile.monitoringLevel}</div>
              </div>
            </div>
            
            <div className="space-y-4">
              <div>
                <label className="text-sm font-medium text-muted-foreground">Allowed Actions</label>
                <div className="flex flex-wrap gap-1 mt-1">
                  {deploymentProfile.allowedActions.map((action) => (
                    <Badge key={action} variant="outline" className="text-xs">
                      {action.replaceAll('_', ' ')}
                    </Badge>
                  ))}
                </div>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">Trust Thresholds</label>
                <div className="text-sm space-y-1 mt-1">
                  <div>Minimum: {deploymentProfile.trustThresholds.minimum}%</div>
                  <div>Promotion: {deploymentProfile.trustThresholds.promotion}%</div>
                  <div>Autonomous: {deploymentProfile.trustThresholds.autonomous}%</div>
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Action Buttons */}
      <div className="flex space-x-4">
        {canUpgrade && onUpgradeAutomation && (
          <Button onClick={onUpgradeAutomation} className="flex-1">
            <TrendingUp className="h-4 w-4 mr-2" />
            Upgrade Automation Level
          </Button>
        )}
        {onViewDetails && (
          <Button variant="outline" onClick={onViewDetails} className="flex-1">
            <Users className="h-4 w-4 mr-2" />
            View Detailed Analytics
          </Button>
        )}
      </div>
    </div>
  );
};