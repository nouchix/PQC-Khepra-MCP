import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { 
  Activity, 
  AlertTriangle, 
  Clock, 
  Shield, 
  Zap,
  RefreshCw,
  TrendingUp
} from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';
import { formatDistanceToNow } from 'date-fns';

interface SplunkLog {
  timestamp: string;
  source: string;
  event_type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  src_ip?: string;
  dst_ip?: string;
  port?: number;
  domain?: string;
  url?: string;
}

export const SplunkDataFeed = () => {
  const [logs, setLogs] = useState<SplunkLog[]>([]);
  const [loading, setLoading] = useState(false);
  const [lastSync, setLastSync] = useState<string | null>(null);
  const { toast } = useToast();

  const fetchSplunkLogs = async () => {
    setLoading(true);
    try {
      const { data, error } = await supabase.functions.invoke('siem-integration', {
        body: {
          action: 'fetch_logs',
          config: {},
          organizationId: 'current'
        }
      });

      if (error) throw error;

      if (data?.results?.logs) {
        setLogs(data.results.logs);
        setLastSync(new Date().toISOString());
      }

      toast({
        title: "SIEM Data Refreshed",
        description: `Fetched ${data?.results?.logs?.length || 0} security events from Splunk`,
      });
    } catch (error: any) {
      toast({
        title: "SIEM Sync Failed",
        description: error.message || "Failed to fetch data from Splunk",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-900/30 text-red-400 border-red-500/30';
      case 'high': return 'bg-orange-900/30 text-orange-400 border-orange-500/30';
      case 'medium': return 'bg-yellow-900/30 text-yellow-400 border-yellow-500/30';
      case 'low': return 'bg-blue-900/30 text-blue-400 border-blue-500/30';
      default: return 'bg-gray-900/30 text-gray-400 border-gray-500/30';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical': return <AlertTriangle className="h-4 w-4 text-red-400" />;
      case 'high': return <AlertTriangle className="h-4 w-4 text-orange-400" />;
      case 'medium': return <Activity className="h-4 w-4 text-yellow-400" />;
      case 'low': return <Shield className="h-4 w-4 text-blue-400" />;
      default: return <Activity className="h-4 w-4 text-gray-400" />;
    }
  };

  useEffect(() => {
    fetchSplunkLogs();
  }, []);

  return (
    <Card className="bg-black/40 border-slate-500/30 backdrop-blur-lg">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Shield className="h-5 w-5 text-primary" />
            <CardTitle className="text-slate-200">Splunk SIEM Feed</CardTitle>
          </div>
          <div className="flex items-center space-x-2">
            {lastSync && (
              <Badge variant="outline" className="text-xs">
                <Clock className="h-3 w-3 mr-1" />
                {formatDistanceToNow(new Date(lastSync), { addSuffix: true })}
              </Badge>
            )}
            <Button 
              variant="outline" 
              size="sm"
              onClick={fetchSplunkLogs}
              disabled={loading}
            >
              <RefreshCw className={`h-4 w-4 mr-1 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {/* Statistics */}
          <div className="grid grid-cols-4 gap-4">
            <div className="text-center">
              <div className="text-lg font-semibold text-white">
                {logs.filter(log => log.severity === 'critical').length}
              </div>
              <div className="text-xs text-red-400">Critical</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-semibold text-white">
                {logs.filter(log => log.severity === 'high').length}
              </div>
              <div className="text-xs text-orange-400">High</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-semibold text-white">
                {logs.filter(log => log.severity === 'medium').length}
              </div>
              <div className="text-xs text-yellow-400">Medium</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-semibold text-white">
                {logs.filter(log => log.severity === 'low').length}
              </div>
              <div className="text-xs text-blue-400">Low</div>
            </div>
          </div>

          {/* Log Feed */}
          <ScrollArea className="h-64">
            <div className="space-y-2">
              {logs.length === 0 ? (
                <div className="text-center text-slate-400 py-8">
                  <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No security events</p>
                  <p className="text-sm">Click refresh to fetch from Splunk</p>
                </div>
              ) : (
                logs.map((log, index) => (
                  <div
                    key={index}
                    className={`p-3 rounded-lg border ${getSeverityColor(log.severity)} backdrop-blur-sm transition-all duration-300 hover:scale-[1.02]`}
                  >
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center space-x-2">
                        {getSeverityIcon(log.severity)}
                        <Badge variant="outline" className="text-xs">
                          {log.source}
                        </Badge>
                        <Badge variant="outline" className="text-xs capitalize">
                          {log.event_type.replace(/_/g, ' ')}
                        </Badge>
                      </div>
                      <div className="text-xs text-slate-400">
                        {formatDistanceToNow(new Date(log.timestamp), { addSuffix: true })}
                      </div>
                    </div>
                    
                    <p className="text-sm text-white mb-2">{log.message}</p>
                    
                    {(log.src_ip || log.dst_ip || log.domain || log.url) && (
                      <div className="flex flex-wrap gap-2 text-xs">
                        {log.src_ip && (
                          <span className="text-cyan-400">Source: {log.src_ip}</span>
                        )}
                        {log.dst_ip && (
                          <span className="text-cyan-400">Target: {log.dst_ip}</span>
                        )}
                        {log.port && (
                          <span className="text-cyan-400">Port: {log.port}</span>
                        )}
                        {log.domain && (
                          <span className="text-cyan-400">Domain: {log.domain}</span>
                        )}
                        {log.url && (
                          <span className="text-cyan-400 truncate max-w-xs">URL: {log.url}</span>
                        )}
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </ScrollArea>

          {logs.length > 0 && (
            <div className="flex items-center justify-between text-xs text-slate-400 pt-2 border-t border-slate-500/30">
              <span>Total Events: {logs.length}</span>
              <div className="flex items-center space-x-1">
                <TrendingUp className="h-3 w-3" />
                <span>Real-time feed from Splunk SIEM</span>
              </div>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};