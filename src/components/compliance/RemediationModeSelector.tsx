import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { AlertTriangle, Eye, UserCheck, Zap, Download, Play } from 'lucide-react';

export type RemediationMode = 'dry-run' | 'guided' | 'auto';

interface RemediationAction {
  id: string;
  stig_rule_id: string;
  description: string;
  command?: string;
  risk_level: 'low' | 'medium' | 'high';
  requires_approval: boolean;
  rollback_available: boolean;
  estimated_duration: string;
}

interface RemediationModeSelectorProps {
  stigRules: string[];
  onModeSelect: (mode: RemediationMode, actions: RemediationAction[]) => void;
  onExecute: (mode: RemediationMode, actionIds: string[]) => Promise<void>;
}

export const RemediationModeSelector: React.FC<RemediationModeSelectorProps> = ({
  stigRules,
  onModeSelect,
  onExecute
}) => {
  const [selectedMode, setSelectedMode] = useState<RemediationMode>('dry-run');
  const [selectedActions, setSelectedActions] = useState<string[]>([]);
  const [isExecuting, setIsExecuting] = useState(false);

  // Awaiting telemetry for real remediation actions
  const pendingActions: RemediationAction[] = [];

  const handleModeChange = (mode: RemediationMode) => {
    setSelectedMode(mode);
    onModeSelect(mode, pendingActions);
  };

  const handleExecute = async () => {
    setIsExecuting(true);
    try {
      await onExecute(selectedMode, selectedActions);
    } finally {
      setIsExecuting(false);
    }
  };

  const getRiskBadgeColor = (risk: string) => {
    switch (risk) {
      case 'low': return 'default';
      case 'medium': return 'secondary';
      case 'high': return 'destructive';
      default: return 'default';
    }
  };

  const getModeIcon = (mode: RemediationMode) => {
    switch (mode) {
      case 'dry-run': return <Eye className="w-4 h-4" />;
      case 'guided': return <UserCheck className="w-4 h-4" />;
      case 'auto': return <Zap className="w-4 h-4" />;
    }
  };

  const getModeDescription = (mode: RemediationMode) => {
    switch (mode) {
      case 'dry-run': return 'Preview changes without applying them. Safe for initial assessment.';
      case 'guided': return 'Generate scripts for manual review and application by administrators.';
      case 'auto': return 'Automatically apply changes with approval checkpoints and rollback capability.';
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-warning" />
            STIG Remediation Mode Selection
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Tabs value={selectedMode} onValueChange={(value) => handleModeChange(value as RemediationMode)}>
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="dry-run" className="flex items-center gap-2">
                {getModeIcon('dry-run')}
                Dry Run
              </TabsTrigger>
              <TabsTrigger value="guided" className="flex items-center gap-2">
                {getModeIcon('guided')}
                Guided
              </TabsTrigger>
              <TabsTrigger value="auto" className="flex items-center gap-2">
                {getModeIcon('auto')}
                Auto Apply
              </TabsTrigger>
            </TabsList>

            <TabsContent value="dry-run" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-muted rounded-lg">
                  <h4 className="font-medium mb-2">Dry Run Mode</h4>
                  <p className="text-sm text-muted-foreground">
                    {getModeDescription('dry-run')}
                  </p>
                </div>
                <div className="text-sm">
                  <strong>What happens:</strong>
                  <ul className="list-disc list-inside mt-2 space-y-1">
                    <li>Analyze current configuration state</li>
                    <li>Generate remediation preview</li>
                    <li>Show expected changes without applying</li>
                    <li>Export detailed impact report</li>
                  </ul>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="guided" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-muted rounded-lg">
                  <h4 className="font-medium mb-2">Guided Mode</h4>
                  <p className="text-sm text-muted-foreground">
                    {getModeDescription('guided')}
                  </p>
                </div>
                <div className="text-sm">
                  <strong>What happens:</strong>
                  <ul className="list-disc list-inside mt-2 space-y-1">
                    <li>Generate platform-specific scripts</li>
                    <li>Provide step-by-step instructions</li>
                    <li>Include rollback procedures</li>
                    <li>Generate validation checklists</li>
                  </ul>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="auto" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-muted rounded-lg border-l-4 border-warning">
                  <h4 className="font-medium mb-2">Auto Apply Mode</h4>
                  <p className="text-sm text-muted-foreground">
                    {getModeDescription('auto')}
                  </p>
                </div>
                <div className="text-sm">
                  <strong>What happens:</strong>
                  <ul className="list-disc list-inside mt-2 space-y-1">
                    <li>Apply changes automatically with approval gates</li>
                    <li>Real-time monitoring of changes</li>
                    <li>Automatic rollback on critical failures</li>
                    <li>Continuous compliance validation</li>
                  </ul>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Remediation Actions ({pendingActions.length})</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {pendingActions.map((action) => (
              <div key={action.id} className="p-4 border rounded-lg space-y-3">
                <div className="flex items-start justify-between">
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">{action.stig_rule_id}</Badge>
                      <Badge variant={getRiskBadgeColor(action.risk_level)}>
                        {action.risk_level.toUpperCase()}
                      </Badge>
                      {action.requires_approval && (
                        <Badge variant="secondary">Approval Required</Badge>
                      )}
                    </div>
                    <h4 className="font-medium">{action.description}</h4>
                    {selectedMode !== 'dry-run' && action.command && (
                      <code className="text-xs bg-muted p-2 rounded block">
                        {action.command}
                      </code>
                    )}
                    <div className="flex items-center gap-4 text-sm text-muted-foreground">
                      <span>Duration: {action.estimated_duration}</span>
                      <span>Rollback: {action.rollback_available ? 'Available' : 'Not Available'}</span>
                    </div>
                  </div>
                  <input
                    type="checkbox"
                    checked={selectedActions.includes(action.id)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setSelectedActions([...selectedActions, action.id]);
                      } else {
                        setSelectedActions(selectedActions.filter(id => id !== action.id));
                      }
                    }}
                    className="mt-2"
                  />
                </div>
              </div>
            ))}
          </div>

          <div className="flex items-center gap-4 mt-6 pt-4 border-t">
            <Button
              onClick={handleExecute}
              disabled={selectedActions.length === 0 || isExecuting}
              className="flex items-center gap-2"
            >
              {selectedMode === 'dry-run' ? (
                <>
                  <Eye className="w-4 h-4" />
                  Preview Changes
                </>
              ) : selectedMode === 'guided' ? (
                <>
                  <Download className="w-4 h-4" />
                  Generate Scripts
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  {isExecuting ? 'Applying...' : 'Apply Changes'}
                </>
              )}
            </Button>
            <div className="text-sm text-muted-foreground">
              {selectedActions.length} of {pendingActions.length} actions selected
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};