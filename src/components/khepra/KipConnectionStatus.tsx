import { useEffect, useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { useKipConnection } from '@/hooks/useKipConnection';
import { Activity, Zap, Shield, RefreshCw, ExternalLink } from 'lucide-react';

export const KipConnectionStatus = () => {
  const { 
    connection, 
    recentTransformations, 
    isLoading,
    checkConnectionHealth,
    syncCulturalTransformations 
  } = useKipConnection();

  const getHealthColor = (health: string) => {
    switch (health) {
      case 'excellent': return 'default';
      case 'good': return 'secondary';
      case 'poor': return 'outline';
      default: return 'destructive';
    }
  };

  const getHealthIcon = (health: string) => {
    switch (health) {
      case 'excellent': return <Zap className="h-4 w-4" />;
      case 'good': return <Activity className="h-4 w-4" />;
      case 'poor': return <Shield className="h-4 w-4" />;
      default: return <RefreshCw className="h-4 w-4" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Connection Status */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <div>
            <CardTitle className="text-sm font-medium">KIP Connection Status</CardTitle>
            <CardDescription>
              KHEPRA Integration Protocol • Cultural AI Engine
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant={getHealthColor(connection.connectionHealth)} className="flex items-center gap-1">
              {getHealthIcon(connection.connectionHealth)}
              {connection.connectionHealth.toUpperCase()}
            </Badge>
            <Button 
              variant="outline" 
              size="sm" 
              onClick={checkConnectionHealth}
              disabled={isLoading}
            >
              {isLoading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="space-y-2">
              <div className="text-sm text-muted-foreground">Cultural Trust Score</div>
              <div className="flex items-center gap-2">
                <Progress value={connection.trustScore} className="flex-1" />
                <span className="text-sm font-medium">{connection.trustScore}%</span>
              </div>
            </div>
            <div className="space-y-2">
              <div className="text-sm text-muted-foreground">Last Sync</div>
              <div className="text-sm">
                {connection.lastSync 
                  ? connection.lastSync.toLocaleTimeString()
                  : 'Never'
                }
              </div>
            </div>
            <div className="space-y-2">
              <div className="text-sm text-muted-foreground">Cultural Fingerprint</div>
              <div className="text-xs font-mono bg-muted px-2 py-1 rounded">
                {connection.culturalFingerprint 
                  ? `${connection.culturalFingerprint.slice(0, 12)}...`
                  : 'Not initialized'
                }
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Recent Cultural Transformations */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <div>
            <CardTitle className="text-sm font-medium">Recent Cultural Transformations</CardTitle>
            <CardDescription>
              Live feed from KIP cultural AI engine
            </CardDescription>
          </div>
          <Button 
            variant="outline" 
            size="sm" 
            onClick={syncCulturalTransformations}
            disabled={!connection.isConnected}
          >
            <RefreshCw className="h-4 w-4 mr-1" />
            Sync
          </Button>
        </CardHeader>
        <CardContent>
          {recentTransformations.length > 0 ? (
            <div className="space-y-3">
              {recentTransformations.slice(0, 5).map((transformation) => (
                <div key={transformation.id} className="flex items-center justify-between p-3 rounded-lg border">
                  <div className="flex items-center gap-3">
                    <Badge variant="outline" className="font-mono">
                      {transformation.symbol}
                    </Badge>
                    <div>
                      <div className="text-sm font-medium capitalize">
                        {transformation.transformation_type.replaceAll('_', ' ')}
                      </div>
                      <div className="text-xs text-muted-foreground">
                        Agent: {transformation.agent_id.slice(0, 8)}...
                      </div>
                    </div>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {new Date(transformation.timestamp).toLocaleTimeString()}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <Activity className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <div className="text-sm">No recent transformations</div>
              {!connection.isConnected && (
                <div className="text-xs mt-1">Connect to KIP to view cultural events</div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Quick Actions */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">KIP Integration Actions</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <Button 
            variant="outline" 
            size="sm"
            disabled={!connection.isConnected}
            onClick={() => globalThis.open(connection.kipUrl.replaceAll('/khepra/v1', ''), '_blank')}
          >
            <ExternalLink className="h-4 w-4 mr-1" />
            Open KIP Dashboard
          </Button>
          <Button 
            variant="outline" 
            size="sm"
            disabled={!connection.isConnected}
            onClick={syncCulturalTransformations}
          >
            <RefreshCw className="h-4 w-4 mr-1" />
            Force Sync
          </Button>
          <Button 
            variant="outline" 
            size="sm"
            disabled={!connection.culturalFingerprint}
          >
            <Shield className="h-4 w-4 mr-1" />
            Test Cultural Auth
          </Button>
        </CardContent>
      </Card>
    </div>
  );
};