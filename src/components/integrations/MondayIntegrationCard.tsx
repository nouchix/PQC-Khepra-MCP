import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { useMondayIntegration } from '@/hooks/useMondayIntegration';
import { Calendar, RefreshCw, Settings, CheckCircle, XCircle } from 'lucide-react';
import { format } from 'date-fns';

interface MondayIntegrationCardProps {
  onConfigure: () => void;
}

export const MondayIntegrationCard: React.FC<MondayIntegrationCardProps> = ({ onConfigure }) => {
  const { config, syncHistory, isLoading, isSyncing, syncAll, isConfigured, isActive } = useMondayIntegration();

  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center justify-center">
            <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        </CardContent>
      </Card>
    );
  }

  const recentSyncs = syncHistory.slice(0, 5);
  const successRate = syncHistory.length > 0
    ? Math.round((syncHistory.filter(s => s.status === 'success').length / syncHistory.length) * 100)
    : 0;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10">
              <Calendar className="h-6 w-6 text-primary" />
            </div>
            <div>
              <CardTitle>Monday.com</CardTitle>
              <CardDescription>Project management integration</CardDescription>
            </div>
          </div>
          <Badge variant={isActive ? 'default' : 'secondary'}>
            {isActive ? 'Active' : 'Inactive'}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {!isConfigured ? (
          <div className="text-center py-6">
            <p className="text-sm text-muted-foreground mb-4">
              Connect Monday.com to track security findings, remediation tasks, and development progress
            </p>
            <Button onClick={onConfigure}>
              <Settings className="mr-2 h-4 w-4" />
              Configure Integration
            </Button>
          </div>
        ) : (
          <>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1">
                <p className="text-sm text-muted-foreground">Workspace ID</p>
                <p className="text-sm font-medium">{config?.workspace_id || 'Not set'}</p>
              </div>
              <div className="space-y-1">
                <p className="text-sm text-muted-foreground">Success Rate</p>
                <p className="text-sm font-medium">{successRate}%</p>
              </div>
              <div className="space-y-1">
                <p className="text-sm text-muted-foreground">Last Sync</p>
                <p className="text-sm font-medium">
                  {config?.last_sync_at ? format(new Date(config.last_sync_at), 'MMM d, h:mm a') : 'Never'}
                </p>
              </div>
              <div className="space-y-1">
                <p className="text-sm text-muted-foreground">Total Syncs</p>
                <p className="text-sm font-medium">{syncHistory.length}</p>
              </div>
            </div>

            {recentSyncs.length > 0 && (
              <div className="space-y-2">
                <p className="text-sm font-medium">Recent Syncs</p>
                <div className="space-y-2">
                  {recentSyncs.map((sync) => (
                    <div key={sync.id} className="flex items-center justify-between rounded-lg border p-3">
                      <div className="flex items-center gap-3">
                        {sync.status === 'success' ? (
                          <CheckCircle className="h-4 w-4 text-green-500" />
                        ) : (
                          <XCircle className="h-4 w-4 text-red-500" />
                        )}
                        <div>
                          <p className="text-sm font-medium capitalize">{sync.entity_type}</p>
                          <p className="text-xs text-muted-foreground">
                            {format(new Date(sync.created_at), 'MMM d, h:mm a')}
                          </p>
                        </div>
                      </div>
                      <Badge variant={sync.status === 'success' ? 'default' : 'destructive'}>
                        {sync.operation}
                      </Badge>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="flex gap-2">
              <Button onClick={syncAll} disabled={isSyncing || !isActive} className="flex-1">
                <RefreshCw className={`mr-2 h-4 w-4 ${isSyncing ? 'animate-spin' : ''}`} />
                Sync All
              </Button>
              <Button onClick={onConfigure} variant="outline">
                <Settings className="mr-2 h-4 w-4" />
                Settings
              </Button>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
};
