import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Progress } from '@/components/ui/progress';
import { 
  Globe, RefreshCw, Play, Pause, Settings, TrendingUp, 
  AlertTriangle, CheckCircle, Clock, Activity, Zap,
  Database, Shield, Target
} from 'lucide-react';
import { useThreatFeedManager } from '@/hooks/useThreatFeedManager';
import { formatDistanceToNow } from 'date-fns';

export const ThreatFeedManager = () => {
  const { 
    feeds, 
    loading, 
    syncing, 
    lastSyncResults, 
    metrics,
    syncAllFeeds,
    syncSpecificFeed,
    startAutoSync,
    processIndicators
  } = useThreatFeedManager();

  const [selectedFeed, setSelectedFeed] = useState<string | null>(null);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'bg-success text-success-foreground';
      case 'inactive': return 'bg-muted text-muted-foreground';
      case 'error': return 'bg-destructive text-destructive-foreground';
      default: return 'bg-secondary text-secondary-foreground';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active': return <CheckCircle className="h-4 w-4" />;
      case 'inactive': return <Clock className="h-4 w-4" />;
      case 'error': return <AlertTriangle className="h-4 w-4" />;
      default: return <Activity className="h-4 w-4" />;
    }
  };

  const getSyncResultBadge = (result: any) => {
    if (result.success) {
      return (
        <Badge variant="outline" className="text-success border-success">
          {result.indicators_added} new
        </Badge>
      );
    } else {
      return (
        <Badge variant="destructive">
          Failed
        </Badge>
      );
    }
  };

  if (loading) {
    return (
      <div className="grid grid-cols-1 gap-6">
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-center">
              <RefreshCw className="h-6 w-6 animate-spin text-primary" />
              <span className="ml-2 text-foreground">Loading threat feed status...</span>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Metrics Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Active Feeds</p>
                <p className="text-2xl font-bold text-primary">{metrics.activeFeeds}/{metrics.totalFeeds}</p>
              </div>
              <Globe className="h-8 w-8 text-primary" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Indicators Today</p>
                <p className="text-2xl font-bold text-accent">{metrics.totalIndicators}</p>
              </div>
              <Database className="h-8 w-8 text-accent" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Feed Health</p>
                <p className="text-2xl font-bold text-success">
                  {Math.round((metrics.activeFeeds / metrics.totalFeeds) * 100)}%
                </p>
              </div>
              <Shield className="h-8 w-8 text-success" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Last Sync</p>
                <p className="text-sm font-bold text-info">
                  {metrics.lastSync ? 
                    formatDistanceToNow(new Date(metrics.lastSync), { addSuffix: true }) : 
                    'Never'
                  }
                </p>
              </div>
              <Clock className="h-8 w-8 text-info" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Control Panel */}
      <Card className="card-cyber">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center space-x-2">
                <Target className="h-5 w-5 text-primary" />
                <span>Threat Feed Management</span>
              </CardTitle>
              <CardDescription>
                Manage and synchronize external threat intelligence sources
              </CardDescription>
            </div>
            <div className="flex items-center space-x-2">
              <Button
                variant="outline"
                size="sm"
                onClick={processIndicators}
                disabled={syncing}
              >
                <Activity className="h-4 w-4 mr-2" />
                Process
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={startAutoSync}
                disabled={syncing}
              >
                <Zap className="h-4 w-4 mr-2" />
                Auto-Sync
              </Button>
              <Button
                onClick={syncAllFeeds}
                disabled={syncing}
                className="bg-primary hover:bg-primary/90"
              >
                {syncing ? (
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <RefreshCw className="h-4 w-4 mr-2" />
                )}
                Sync All
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="feeds" className="space-y-4">
            <TabsList className="bg-card border border-border">
              <TabsTrigger value="feeds">Feed Status</TabsTrigger>
              <TabsTrigger value="results">Sync Results</TabsTrigger>
              <TabsTrigger value="analytics">Analytics</TabsTrigger>
            </TabsList>

            <TabsContent value="feeds" className="space-y-4">
              <ScrollArea className="h-96">
                <div className="space-y-3">
                  {feeds.map((feed) => (
                    <div
                      key={feed.source}
                      className={`p-4 rounded-lg border transition-colors cursor-pointer ${
                        selectedFeed === feed.source 
                          ? 'border-primary bg-accent/50' 
                          : 'border-border bg-card hover:bg-accent/30'
                      }`}
                      onClick={() => setSelectedFeed(selectedFeed === feed.source ? null : feed.source)}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <div className="flex items-center space-x-2">
                            {getStatusIcon(feed.status)}
                            <Badge className={getStatusColor(feed.status)}>
                              {feed.status}
                            </Badge>
                          </div>
                          <div>
                            <h4 className="font-medium text-foreground">{feed.source}</h4>
                            <div className="flex items-center space-x-4 text-sm text-muted-foreground">
                              <span>{feed.indicators_today} indicators today</span>
                              {feed.last_sync && (
                                <span>
                                  Last sync: {formatDistanceToNow(new Date(feed.last_sync), { addSuffix: true })}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          {feed.enabled ? (
                            <Badge variant="outline" className="text-success border-success">
                              Enabled
                            </Badge>
                          ) : (
                            <Badge variant="outline" className="text-muted-foreground">
                              Disabled
                            </Badge>
                          )}
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={(e) => {
                              e.stopPropagation();
                              syncSpecificFeed(feed.source);
                            }}
                            disabled={syncing || !feed.enabled}
                            className="h-8 px-3"
                          >
                            <RefreshCw className={`h-3 w-3 mr-1 ${syncing ? 'animate-spin' : ''}`} />
                            Sync
                          </Button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </TabsContent>

            <TabsContent value="results" className="space-y-4">
              <ScrollArea className="h-96">
                <div className="space-y-3">
                  {lastSyncResults.length === 0 ? (
                    <div className="text-center text-muted-foreground py-8">
                      <RefreshCw className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No sync results available</p>
                      <p className="text-sm">Run a sync to see results</p>
                    </div>
                  ) : (
                    lastSyncResults.map((result, index) => (
                      <div
                        key={`${result.source}-${index}`}
                        className="p-4 rounded-lg border border-border bg-card"
                      >
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="font-medium text-foreground">{result.source}</h4>
                          {getSyncResultBadge(result)}
                        </div>
                        <div className="text-sm text-muted-foreground space-y-1">
                          <div className="flex justify-between">
                            <span>Indicators Fetched:</span>
                            <span className="font-medium">{result.indicators_fetched}</span>
                          </div>
                          <div className="flex justify-between">
                            <span>New Indicators:</span>
                            <span className="font-medium text-accent">{result.indicators_added}</span>
                          </div>
                          <div className="flex justify-between">
                            <span>Sync Time:</span>
                            <span className="font-medium">
                              {formatDistanceToNow(new Date(result.last_sync), { addSuffix: true })}
                            </span>
                          </div>
                          {result.note && (
                            <div className="text-xs text-info mt-2 p-2 bg-info/10 rounded">
                              {result.note}
                            </div>
                          )}
                          {result.error && (
                            <div className="text-xs text-destructive mt-2 p-2 bg-destructive/10 rounded">
                              Error: {result.error}
                            </div>
                          )}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </ScrollArea>
            </TabsContent>

            <TabsContent value="analytics" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Card className="card-cyber">
                  <CardHeader>
                    <CardTitle className="text-sm">Feed Performance</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {feeds.map((feed) => (
                        <div key={feed.source} className="space-y-2">
                          <div className="flex justify-between text-sm">
                            <span className="text-muted-foreground">{feed.source}</span>
                            <span className="text-foreground">{feed.indicators_today} indicators</span>
                          </div>
                          <Progress 
                            value={(feed.indicators_today / Math.max(metrics.totalIndicators, 1)) * 100}
                            className="h-2"
                          />
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>

                <Card className="card-cyber">
                  <CardHeader>
                    <CardTitle className="text-sm">System Health</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">Overall Health</span>
                        <Badge variant="outline" className="text-success border-success">
                          {Math.round((metrics.activeFeeds / metrics.totalFeeds) * 100)}% Healthy
                        </Badge>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">Data Freshness</span>
                        <Badge variant="outline" className="text-info border-info">
                          {metrics.lastSync ? 'Fresh' : 'Stale'}
                        </Badge>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">Error Rate</span>
                        <Badge 
                          variant="outline" 
                          className={metrics.errorFeeds > 0 ? 'text-warning border-warning' : 'text-success border-success'}
                        >
                          {Math.round((metrics.errorFeeds / metrics.totalFeeds) * 100)}%
                        </Badge>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};