import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  Shield, 
  Zap,
  Settings,
  Users,
  Lock
} from 'lucide-react';
import { DeploymentProfile } from '@/types/deployment';

interface RemediationAction {
  id: string;
  stigRule: string;
  title: string;
  description: string;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  estimatedImpact: string;
  systemsAffected: string[];
  automationDecision: 'auto_execute' | 'requires_approval' | 'manual_only' | 'blocked';
  trustScoreRequired: number;
  reasoning: string;
  timeline: string;
}

interface RiskBasedAutomationEngineProps {
  organizationId: string;
  deploymentProfile: DeploymentProfile;
  currentTrustScore: number;
  pendingActions: RemediationAction[];
  onApproveAction: (actionId: string) => void;
  onDenyAction: (actionId: string) => void;
  onExecuteAction: (actionId: string) => void;
}

export const RiskBasedAutomationEngine: React.FC<RiskBasedAutomationEngineProps> = ({
  organizationId,
  deploymentProfile,
  currentTrustScore,
  pendingActions,
  onApproveAction,
  onDenyAction,
  onExecuteAction
}) => {
  const [selectedAction, setSelectedAction] = useState<string | null>(null);

  const getRiskColor = (risk: string) => {
    const colors = {
      critical: 'destructive',
      high: 'destructive',
      medium: 'warning',
      low: 'secondary'
    };
    return colors[risk as keyof typeof colors] || 'secondary';
  };

  const getAutomationIcon = (decision: string) => {
    switch (decision) {
      case 'auto_execute':
        return <Zap className="h-4 w-4 text-success" />;
      case 'requires_approval':
        return <Users className="h-4 w-4 text-warning" />;
      case 'manual_only':
        return <Settings className="h-4 w-4 text-primary" />;
      case 'blocked':
        return <Lock className="h-4 w-4 text-destructive" />;
      default:
        return <AlertTriangle className="h-4 w-4" />;
    }
  };

  const getAutomationLabel = (decision: string) => {
    const labels = {
      auto_execute: 'Auto Execute',
      requires_approval: 'Requires Approval',
      manual_only: 'Manual Only',
      blocked: 'Blocked'
    };
    return labels[decision as keyof typeof labels] || decision;
  };

  const canExecuteAutomatically = (action: RemediationAction) => {
    return action.automationDecision === 'auto_execute' && 
           currentTrustScore >= action.trustScoreRequired &&
           deploymentProfile.allowedActions.includes('auto_remediate_' + action.riskLevel);
  };

  const calculateAutomationDecision = (action: RemediationAction): RemediationAction => {
    // Risk-based automation logic
    let decision: RemediationAction['automationDecision'] = 'manual_only';
    let reasoning = '';

    // Check if action is blocked for this industry
    if (action.systemsAffected.some(system => 
      deploymentProfile.restrictedSystems.includes(system)
    )) {
      decision = 'blocked';
      reasoning = 'Action affects restricted systems for this industry profile';
    }
    // Check approval requirements based on risk level
    else if (deploymentProfile.approvalRequired[action.riskLevel]) {
      decision = 'requires_approval';
      reasoning = `${action.riskLevel} risk actions require approval per deployment policy`;
    }
    // Check if automation is allowed and trust score is sufficient
    else if (
      deploymentProfile.allowedActions.includes(`auto_remediate_${action.riskLevel}`) &&
      currentTrustScore >= deploymentProfile.trustThresholds.minimum
    ) {
      decision = 'auto_execute';
      reasoning = `Trust score (${currentTrustScore}%) meets threshold for ${action.riskLevel} risk automation`;
    }
    else {
      reasoning = `Insufficient trust score or automation not enabled for ${action.riskLevel} risk actions`;
    }

    return {
      ...action,
      automationDecision: decision,
      reasoning
    };
  };

  const processedActions = pendingActions.map(calculateAutomationDecision);
  const autoExecutableActions = processedActions.filter(action => 
    action.automationDecision === 'auto_execute'
  );
  const approvalRequiredActions = processedActions.filter(action => 
    action.automationDecision === 'requires_approval'
  );

  return (
    <div className="space-y-6">
      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-2xl font-bold text-success">
                  {autoExecutableActions.length}
                </div>
                <div className="text-sm text-muted-foreground">
                  Auto Execute
                </div>
              </div>
              <Zap className="h-8 w-8 text-success" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-2xl font-bold text-warning">
                  {approvalRequiredActions.length}
                </div>
                <div className="text-sm text-muted-foreground">
                  Need Approval
                </div>
              </div>
              <Users className="h-8 w-8 text-warning" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-2xl font-bold text-primary">
                  {currentTrustScore}%
                </div>
                <div className="text-sm text-muted-foreground">
                  Trust Score
                </div>
              </div>
              <Shield className="h-8 w-8 text-primary" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-2xl font-bold text-secondary">
                  {deploymentProfile.riskTolerance.replaceAll('_', ' ')}
                </div>
                <div className="text-sm text-muted-foreground">
                  Risk Profile
                </div>
              </div>
              <AlertTriangle className="h-8 w-8 text-secondary" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Pending Actions */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Settings className="h-5 w-5" />
            <span>Risk-Based Automation Decisions</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {processedActions.map((action) => (
              <div 
                key={action.id}
                className={`border rounded-lg p-4 transition-all ${
                  selectedAction === action.id ? 'border-primary bg-primary/5' : 'border-border'
                }`}
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-2">
                      <Badge variant={getRiskColor(action.riskLevel) as "success" | "default" | "secondary" | "destructive" | "outline" | "warning"}>
                        {action.riskLevel.toUpperCase()}
                      </Badge>
                      <Badge variant="outline" className="flex items-center space-x-1">
                        {getAutomationIcon(action.automationDecision)}
                        <span>{getAutomationLabel(action.automationDecision)}</span>
                      </Badge>
                      <span className="text-sm text-muted-foreground">
                        {action.stigRule}
                      </span>
                    </div>
                    <h4 className="font-semibold text-sm mb-1">{action.title}</h4>
                    <p className="text-sm text-muted-foreground mb-2">{action.description}</p>
                    <div className="text-xs text-muted-foreground">
                      <span className="font-medium">Systems:</span> {action.systemsAffected.join(', ')}
                    </div>
                  </div>
                  <div className="text-right text-sm">
                    <div className="font-medium">Trust Required: {action.trustScoreRequired}%</div>
                    <div className="text-muted-foreground">{action.timeline}</div>
                  </div>
                </div>

                <div className="bg-muted/50 rounded p-3 mb-3">
                  <div className="text-xs font-medium text-muted-foreground mb-1">
                    Automation Reasoning:
                  </div>
                  <div className="text-sm">{action.reasoning}</div>
                </div>

                <div className="flex justify-between items-center">
                  <div className="flex items-center space-x-2">
                    <Progress 
                      value={Math.min((currentTrustScore / action.trustScoreRequired) * 100, 100)} 
                      className="w-24 h-2"
                    />
                    <span className="text-xs text-muted-foreground">
                      Trust Match: {Math.min(Math.round((currentTrustScore / action.trustScoreRequired) * 100), 100)}%
                    </span>
                  </div>
                  
                  <div className="flex space-x-2">
                    {action.automationDecision === 'auto_execute' && canExecuteAutomatically(action) && (
                      <Button
                        size="sm"
                        onClick={() => onExecuteAction(action.id)}
                        className="bg-success hover:bg-success/90"
                      >
                        <Zap className="h-3 w-3 mr-1" />
                        Execute
                      </Button>
                    )}
                    {action.automationDecision === 'requires_approval' && (
                      <>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => onDenyAction(action.id)}
                        >
                          Deny
                        </Button>
                        <Button
                          size="sm"
                          onClick={() => onApproveAction(action.id)}
                        >
                          <CheckCircle className="h-3 w-3 mr-1" />
                          Approve
                        </Button>
                      </>
                    )}
                    {action.automationDecision === 'blocked' && (
                      <Badge variant="destructive" className="text-xs">
                        <Lock className="h-3 w-3 mr-1" />
                        Blocked by Policy
                      </Badge>
                    )}
                  </div>
                </div>
              </div>
            ))}
            
            {processedActions.length === 0 && (
              <div className="text-center py-8 text-muted-foreground">
                <Clock className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <div>No pending remediation actions</div>
                <div className="text-sm">All systems are compliant or actions are being processed</div>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};