import { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Activity, AlertTriangle, CheckCircle, Clock, Zap } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

interface WebhookActivity {
  id: string;
  source: string;
  source_ip: string | null;
  endpoint: string | null;
  payload_hash: string | null;
  validation_result: any;
  rate_limit_applied: boolean;
  processing_time_ms: number | null;
  user_agent: string | null;
  created_at: string;
}

interface SourceStats {
  source: string;
  total_requests: number;
  success_rate: number;
  avg_processing_time: number;
  rate_limited_count: number;
  last_activity: string;
}

export const WebhookActivityDashboard = () => {
  const [activity, setActivity] = useState<WebhookActivity[]>([]);
  const [sourceStats, setSourceStats] = useState<SourceStats[]>([]);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  useEffect(() => {
    loadWebhookActivity();
    // Refresh every 30 seconds
    const interval = setInterval(loadWebhookActivity, 30000);
    return () => clearInterval(interval);
  }, []);

  const loadWebhookActivity = async () => {
    setLoading(true);
    try {
      // Load recent webhook activity
      const { data: activityData, error: activityError } = await supabase
        .from('webhook_activity')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(50);

      if (activityError) throw activityError;

      setActivity((activityData as WebhookActivity[]) || []);

      // Calculate source statistics
      if (activityData && activityData.length > 0) {
        const stats = calculateSourceStats(activityData as WebhookActivity[]);
        setSourceStats(stats);
      }
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const calculateSourceStats = (activities: WebhookActivity[]): SourceStats[] => {
    const sourceMap = new Map<string, {
      requests: WebhookActivity[];
      successCount: number;
      rateLimitedCount: number;
    }>();

    activities.forEach(activity => {
      if (!sourceMap.has(activity.source)) {
        sourceMap.set(activity.source, {
          requests: [],
          successCount: 0,
          rateLimitedCount: 0
        });
      }

      const sourceData = sourceMap.get(activity.source)!;
      sourceData.requests.push(activity);
      
      if (!activity.rate_limit_applied && activity.validation_result?.isValid !== false) {
        sourceData.successCount++;
      }
      
      if (activity.rate_limit_applied) {
        sourceData.rateLimitedCount++;
      }
    });

    return Array.from(sourceMap.entries()).map(([source, data]) => {
      const avgProcessingTime = data.requests
        .filter(r => r.processing_time_ms !== null)
        .reduce((sum, r) => sum + (r.processing_time_ms || 0), 0) / data.requests.length;

      return {
        source,
        total_requests: data.requests.length,
        success_rate: (data.successCount / data.requests.length) * 100,
        avg_processing_time: Math.round(avgProcessingTime),
        rate_limited_count: data.rateLimitedCount,
        last_activity: data.requests[0].created_at
      };
    }).sort((a, b) => b.total_requests - a.total_requests);
  };

  const getStatusBadge = (activity: WebhookActivity) => {
    if (activity.rate_limit_applied) {
      return <Badge variant="destructive">Rate Limited</Badge>;
    }
    if (activity.validation_result?.isValid === false) {
      return <Badge variant="destructive">Validation Failed</Badge>;
    }
    return <Badge variant="default">Success</Badge>;
  };

  const getProcessingTimeColor = (timeMs: number | null) => {
    if (!timeMs) return 'text-gray-400';
    if (timeMs < 100) return 'text-green-400';
    if (timeMs < 500) return 'text-yellow-400';
    return 'text-red-400';
  };

  if (loading && activity.length === 0) {
    return (
      <Card className="bg-background/50 border-border">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5" />
            Webhook Activity Monitor
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center text-muted-foreground">Loading webhook activity...</div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <Card className="bg-background/50 border-border">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5" />
            Webhook Activity Monitor
          </CardTitle>
          <Button onClick={loadWebhookActivity} size="sm" variant="outline">
            Refresh
          </Button>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Source Statistics */}
          <div>
            <h3 className="text-lg font-semibold mb-4">Source Statistics</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {sourceStats.map((stat) => (
                <Card key={stat.source} className="bg-card border-border">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium text-foreground">{stat.source}</span>
                      <Badge variant={stat.success_rate > 90 ? 'default' : stat.success_rate > 70 ? 'secondary' : 'destructive'}>
                        {Math.round(stat.success_rate)}% success
                      </Badge>
                    </div>
                    <div className="space-y-1 text-sm text-muted-foreground">
                      <div className="flex justify-between">
                        <span>Requests:</span>
                        <span className="text-foreground">{stat.total_requests}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Avg Time:</span>
                        <span className={getProcessingTimeColor(stat.avg_processing_time)}>
                          {stat.avg_processing_time}ms
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span>Rate Limited:</span>
                        <span className={stat.rate_limited_count > 0 ? 'text-red-400' : 'text-green-400'}>
                          {stat.rate_limited_count}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span>Last Activity:</span>
                        <span className="text-foreground">
                          {new Date(stat.last_activity).toLocaleTimeString()}
                        </span>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>

          {/* Recent Activity */}
          <div>
            <h3 className="text-lg font-semibold mb-4">Recent Activity</h3>
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {activity.map((item) => (
                <div key={item.id} className="p-4 bg-card border border-border rounded">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-3">
                      <span className="font-medium text-foreground">{item.source}</span>
                      {getStatusBadge(item)}
                      {item.processing_time_ms && (
                        <Badge variant="outline" className={getProcessingTimeColor(item.processing_time_ms)}>
                          {item.processing_time_ms}ms
                        </Badge>
                      )}
                    </div>
                    <span className="text-sm text-muted-foreground">
                      {new Date(item.created_at).toLocaleTimeString()}
                    </span>
                  </div>
                  
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm text-muted-foreground">
                    <div>
                      <span className="block font-medium">Source IP</span>
                      <span className="text-foreground">{item.source_ip || 'Unknown'}</span>
                    </div>
                    <div>
                      <span className="block font-medium">Endpoint</span>
                      <span className="text-foreground">{item.endpoint || 'N/A'}</span>
                    </div>
                    <div>
                      <span className="block font-medium">Payload Hash</span>
                      <span className="text-foreground font-mono text-xs">
                        {item.payload_hash ? item.payload_hash.slice(0, 8) + '...' : 'N/A'}
                      </span>
                    </div>
                    <div>
                      <span className="block font-medium">User Agent</span>
                      <span className="text-foreground text-xs truncate">
                        {item.user_agent ? item.user_agent.slice(0, 30) + '...' : 'N/A'}
                      </span>
                    </div>
                  </div>

                  {item.validation_result && !item.validation_result.isValid && (
                    <div className="mt-2 p-2 bg-red-500/10 border border-red-500/30 rounded text-sm">
                      <span className="text-red-400 font-medium">Validation Errors:</span>
                      <ul className="mt-1 text-red-300">
                        {item.validation_result.errors?.map((error: string, index: number) => (
                          <li key={index}>• {error}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              ))}

              {activity.length === 0 && (
                <div className="text-center text-muted-foreground py-8">
                  <Activity className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No webhook activity recorded</p>
                  <p className="text-xs mt-1">Activity will appear here as webhooks are received</p>
                </div>
              )}
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};