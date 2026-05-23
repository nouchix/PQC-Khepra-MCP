import { useRealTimeData } from '@/hooks/useRealTimeData';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Button } from '@/components/ui/button';
import { AlertTriangle, Shield, Info, CheckCircle, ExternalLink, Filter } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { useState } from 'react';

export const LiveThreatFeed = () => {
  const { securityEvents } = useRealTimeData();
  const [filter, setFilter] = useState<'all' | 'critical' | 'warning' | 'info'>('all');

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return <AlertTriangle className="h-4 w-4 text-red-400" />;
      case 'WARNING':
        return <Shield className="h-4 w-4 text-orange-400" />;
      default:
        return <Info className="h-4 w-4 text-blue-400" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-500/10 text-red-400 border-red-500/20';
      case 'WARNING':
        return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
      default:
        return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
    }
  };

  const filteredEvents = securityEvents.filter(event => {
    if (filter === 'all') return true;
    return event.severity.toLowerCase() === filter;
  });

  const getStatusIcon = (resolved: boolean) => {
    return resolved ? (
      <CheckCircle className="h-4 w-4 text-green-400" />
    ) : (
      <div className="w-4 h-4 rounded-full bg-red-400 animate-pulse" />
    );
  };

  return (
    <Card className="bg-slate-800/50 border-slate-700 h-full">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="h-5 w-5 text-cyan-400" />
            <div>
              <CardTitle className="text-white">Live Threat Feed</CardTitle>
              <CardDescription className="text-slate-400">
                Real-time security events and alerts
              </CardDescription>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <Filter className="h-4 w-4 text-slate-400" />
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value as any)}
              className="bg-slate-700 border border-slate-600 rounded px-2 py-1 text-sm text-white"
            >
              <option value="all">All</option>
              <option value="critical">Critical</option>
              <option value="warning">Warning</option>
              <option value="info">Info</option>
            </select>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-[500px]">
          <div className="space-y-3">
            {filteredEvents.length === 0 ? (
              <div className="text-center text-slate-400 py-8">
                <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No security events to display</p>
                <p className="text-sm">System monitoring...</p>
              </div>
            ) : (
              filteredEvents.map((event) => (
                <div
                  key={event.id}
                  className="p-4 rounded-lg border border-slate-700 bg-slate-900/50 hover:bg-slate-900/70 transition-colors"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start space-x-3 flex-1">
                      <div className="flex flex-col items-center space-y-1">
                        {getSeverityIcon(event.severity)}
                        {getStatusIcon(event.resolved)}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center space-x-2 mb-1">
                          <h4 className="font-medium text-white truncate">
                            {event.event_type}
                          </h4>
                          <Badge className={getSeverityColor(event.severity)}>
                            {event.severity}
                          </Badge>
                          {event.resolved && (
                            <Badge variant="outline" className="text-green-400 border-green-400">
                              Resolved
                            </Badge>
                          )}
                        </div>
                        <p className="text-sm text-slate-400 mb-2">
                          Source: {event.source_system}
                        </p>
                        {event.details && (
                          <div className="text-xs text-slate-500 space-y-1">
                            {event.details.source_ip && (
                              <div>IP: {event.details.source_ip}</div>
                            )}
                            {event.details.target_port && (
                              <div>Port: {event.details.target_port}</div>
                            )}
                            {event.details.risk_score && (
                              <div className="flex items-center space-x-1">
                                <span>Risk Score:</span>
                                <Badge 
                                  variant={event.details.risk_score > 70 ? "destructive" : "outline"}
                                  className="text-xs"
                                >
                                  {event.details.risk_score}/100
                                </Badge>
                              </div>
                            )}
                          </div>
                        )}
                        <div className="flex items-center justify-between mt-2">
                          <span className="text-xs text-slate-500">
                            {formatDistanceToNow(new Date(event.created_at), { addSuffix: true })}
                          </span>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-cyan-400 hover:text-cyan-300 h-6 px-2"
                          >
                            <ExternalLink className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
};