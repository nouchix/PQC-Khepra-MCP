import { useState } from 'react';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { useMondayIntegration } from '@/hooks/useMondayIntegration';
import { Calendar, Save } from 'lucide-react';

interface MondaySyncSettingsProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export const MondaySyncSettings: React.FC<MondaySyncSettingsProps> = ({ open, onOpenChange }) => {
  const { config, saveConfig, toggleIntegration } = useMondayIntegration();
  
  const [workspaceId, setWorkspaceId] = useState(config?.workspace_id || '');
  const [boardMappings, setBoardMappings] = useState({
    security_findings: config?.board_mappings?.security_findings || '',
    remediation_pipeline: config?.board_mappings?.remediation_pipeline || '',
    compliance_tracking: config?.board_mappings?.compliance_tracking || '',
    asset_inventory: config?.board_mappings?.asset_inventory || '',
    mvp_development: config?.board_mappings?.mvp_development || '',
    product_roadmap: config?.board_mappings?.product_roadmap || '',
    onboarding_journey: config?.board_mappings?.onboarding_journey || '',
  });
  
  const [autoCreate, setAutoCreate] = useState(config?.sync_preferences?.auto_create_items ?? true);
  const [bidirectional, setBidirectional] = useState(config?.sync_preferences?.bidirectional_sync ?? true);
  const [syncComments, setSyncComments] = useState(config?.sync_preferences?.sync_comments ?? true);
  const [isActive, setIsActive] = useState(config?.is_active ?? false);

  const handleSave = async () => {
    await saveConfig({
      workspace_id: workspaceId,
      board_mappings: boardMappings,
      sync_preferences: {
        sync_frequency: 'real-time',
        auto_create_items: autoCreate,
        bidirectional_sync: bidirectional,
        sync_comments: syncComments,
      },
      is_active: isActive,
    });
    onOpenChange(false);
  };

  const handleToggle = async (checked: boolean) => {
    setIsActive(checked);
    await toggleIntegration(checked);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <div className="flex items-center gap-2">
            <Calendar className="h-5 w-5 text-primary" />
            <DialogTitle>Monday.com Integration Settings</DialogTitle>
          </div>
          <DialogDescription>
            Configure Monday.com workspace and board mappings for automated sync
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6">
          {/* Integration Status */}
          <div className="flex items-center justify-between rounded-lg border p-4">
            <div className="space-y-0.5">
              <Label>Enable Integration</Label>
              <p className="text-sm text-muted-foreground">
                Activate Monday.com sync for this organization
              </p>
            </div>
            <Switch checked={isActive} onCheckedChange={handleToggle} />
          </div>

          {/* Workspace Configuration */}
          <div className="space-y-4">
            <h3 className="text-sm font-semibold">Workspace Configuration</h3>
            <div className="space-y-2">
              <Label htmlFor="workspace">Monday.com Workspace ID</Label>
              <Input
                id="workspace"
                placeholder="12345678"
                value={workspaceId}
                onChange={(e) => setWorkspaceId(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                Find your workspace ID in Monday.com settings
              </p>
            </div>
          </div>

          {/* Board Mappings */}
          <div className="space-y-4">
            <h3 className="text-sm font-semibold">Board Mappings</h3>
            <p className="text-xs text-muted-foreground">
              Map your entity types to Monday.com board IDs
            </p>
            
            <div className="grid gap-4">
              <div className="space-y-2">
                <Label htmlFor="security">Security Findings Board</Label>
                <Input
                  id="security"
                  placeholder="Board ID"
                  value={boardMappings.security_findings}
                  onChange={(e) => setBoardMappings({ ...boardMappings, security_findings: e.target.value })}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="remediation">Remediation Pipeline Board</Label>
                <Input
                  id="remediation"
                  placeholder="Board ID"
                  value={boardMappings.remediation_pipeline}
                  onChange={(e) => setBoardMappings({ ...boardMappings, remediation_pipeline: e.target.value })}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="compliance">Compliance Tracking Board</Label>
                <Input
                  id="compliance"
                  placeholder="Board ID"
                  value={boardMappings.compliance_tracking}
                  onChange={(e) => setBoardMappings({ ...boardMappings, compliance_tracking: e.target.value })}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="assets">Asset Inventory Board</Label>
                <Input
                  id="assets"
                  placeholder="Board ID"
                  value={boardMappings.asset_inventory}
                  onChange={(e) => setBoardMappings({ ...boardMappings, asset_inventory: e.target.value })}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="mvp">MVP Development Board</Label>
                <Input
                  id="mvp"
                  placeholder="Board ID"
                  value={boardMappings.mvp_development}
                  onChange={(e) => setBoardMappings({ ...boardMappings, mvp_development: e.target.value })}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="roadmap">Product Roadmap Board</Label>
                <Input
                  id="roadmap"
                  placeholder="Board ID"
                  value={boardMappings.product_roadmap}
                  onChange={(e) => setBoardMappings({ ...boardMappings, product_roadmap: e.target.value })}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="onboarding">Onboarding Journey Board</Label>
                <Input
                  id="onboarding"
                  placeholder="Board ID"
                  value={boardMappings.onboarding_journey}
                  onChange={(e) => setBoardMappings({ ...boardMappings, onboarding_journey: e.target.value })}
                />
              </div>
            </div>
          </div>

          {/* Sync Preferences */}
          <div className="space-y-4">
            <h3 className="text-sm font-semibold">Sync Preferences</h3>
            
            <div className="flex items-center justify-between rounded-lg border p-4">
              <div className="space-y-0.5">
                <Label>Auto-Create Items</Label>
                <p className="text-sm text-muted-foreground">
                  Automatically create Monday items when entities are created
                </p>
              </div>
              <Switch checked={autoCreate} onCheckedChange={setAutoCreate} />
            </div>

            <div className="flex items-center justify-between rounded-lg border p-4">
              <div className="space-y-0.5">
                <Label>Bidirectional Sync</Label>
                <p className="text-sm text-muted-foreground">
                  Sync changes from Monday.com back to IMOHTEP
                </p>
              </div>
              <Switch checked={bidirectional} onCheckedChange={setBidirectional} />
            </div>

            <div className="flex items-center justify-between rounded-lg border p-4">
              <div className="space-y-0.5">
                <Label>Sync Comments</Label>
                <p className="text-sm text-muted-foreground">
                  Include comments and updates in sync
                </p>
              </div>
              <Switch checked={syncComments} onCheckedChange={setSyncComments} />
            </div>
          </div>

          <div className="flex gap-2">
            <Button onClick={handleSave} className="flex-1">
              <Save className="mr-2 h-4 w-4" />
              Save Configuration
            </Button>
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};
