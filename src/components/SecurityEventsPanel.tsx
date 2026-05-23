import { useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, CheckCircle, Clock, Shield, Plus } from "lucide-react";
import { useSecurityEvents } from "@/hooks/useSecurityEvents";
import { useToast } from "@/hooks/use-toast";

export const SecurityEventsPanel = () => {
  const { events, loading, resolveEvent } = useSecurityEvents();
  const { toast } = useToast();

  const handleResolve = async (eventId: string) => {
    const { error } = await resolveEvent(eventId);
    
    if (error) {
      toast({
        title: "Error",
        description: error,
        variant: "destructive"
      });
    } else {
      toast({
        title: "Event Resolved",
        description: "Security event has been marked as resolved."
      });
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'bg-red-600/20 text-red-400 border-red-500/30';
      case 'WARNING': return 'bg-yellow-600/20 text-yellow-400 border-yellow-500/30';
      case 'INFO': return 'bg-blue-600/20 text-blue-400 border-blue-500/30';
      default: return 'bg-gray-600/20 text-gray-400 border-gray-500/30';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return <AlertTriangle className="h-4 w-4 text-red-400" />;
      case 'WARNING': return <AlertTriangle className="h-4 w-4 text-yellow-400" />;
      case 'INFO': return <Shield className="h-4 w-4 text-blue-400" />;
      default: return <Clock className="h-4 w-4 text-gray-400" />;
    }
  };

  const unresolvedEvents = events.filter(event => !event.resolved);
  const criticalEvents = events.filter(event => event.severity === 'CRITICAL' && !event.resolved);

  if (loading) {
    return (
      <Card className="bg-black/40 border-blue-500/30 backdrop-blur-lg">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2 text-blue-400">
            <Shield className="h-5 w-5" />
            <span>Security Events</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center text-gray-400">Loading security events...</div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="bg-black/40 border-blue-500/30 backdrop-blur-lg">
      <CardHeader>
        <CardTitle className="flex items-center space-x-2 text-blue-400">
          <Shield className="h-5 w-5" />
          <span>Security Events</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Stats Overview */}
        <div className="grid grid-cols-3 gap-3">
          <div className="text-center p-2 bg-slate-800/40 rounded border border-slate-600/30">
            <div className="text-lg font-bold text-red-400">{criticalEvents.length}</div>
            <div className="text-xs text-gray-400">Critical</div>
          </div>
          <div className="text-center p-2 bg-slate-800/40 rounded border border-slate-600/30">
            <div className="text-lg font-bold text-yellow-400">{unresolvedEvents.length}</div>
            <div className="text-xs text-gray-400">Unresolved</div>
          </div>
          <div className="text-center p-2 bg-slate-800/40 rounded border border-slate-600/30">
            <div className="text-lg font-bold text-cyan-400">{events.length}</div>
            <div className="text-xs text-gray-400">Total</div>
          </div>
        </div>

        {/* Recent Events */}
        <div className="max-h-64 overflow-y-auto space-y-2">
          {events.slice(0, 15).map((event) => (
            <div key={event.id} className="p-3 bg-slate-800/40 rounded border border-slate-600/30">
              <div className="flex items-start justify-between mb-2">
                <div className="flex items-center space-x-2">
                  {getSeverityIcon(event.severity)}
                  <span className="text-sm font-medium text-white">{event.event_type}</span>
                  <Badge className={getSeverityColor(event.severity)}>
                    {event.severity}
                  </Badge>
                  {event.event_tags?.real_or_test && (
                    <Badge 
                      className={
                        event.event_tags.real_or_test === 'real' 
                          ? 'bg-red-600/20 text-red-400 border-red-500/30' 
                          : event.event_tags.real_or_test === 'test'
                          ? 'bg-blue-600/20 text-blue-400 border-blue-500/30'
                          : 'bg-gray-600/20 text-gray-400 border-gray-500/30'
                      }
                    >
                      {event.event_tags.real_or_test.toUpperCase()}
                    </Badge>
                  )}
                  {event.event_tags?.environment && event.event_tags.environment !== 'unknown' && (
                    <Badge className="bg-purple-600/20 text-purple-400 border-purple-500/30">
                      {event.event_tags.environment}
                    </Badge>
                  )}
                  {event.resolved && (
                    <Badge className="bg-green-600/20 text-green-400 border-green-500/30">
                      <CheckCircle className="h-3 w-3 mr-1" />
                      Resolved
                    </Badge>
                  )}
                </div>
                {!event.resolved && (
                  <Button
                    size="sm"
                    onClick={() => handleResolve(event.id)}
                    className="bg-green-600/20 border-green-500/30 text-green-400 hover:bg-green-600/40 text-xs"
                  >
                    Resolve
                  </Button>
                )}
              </div>
              
              <div className="text-xs text-gray-400 mb-1">
                Source: {event.source_system} • {new Date(event.created_at).toLocaleString()}
              </div>
              
              {event.details && (
                <div className="text-xs text-gray-300 bg-slate-700/40 p-2 rounded mt-2">
                  {typeof event.details === 'object' ? (
                    Object.entries(event.details).map(([key, value]) => (
                      <div key={key}>
                        <span className="text-cyan-400">{key}:</span> {String(value)}
                      </div>
                    ))
                  ) : (
                    event.details
                  )}
                </div>
              )}
            </div>
          ))}
          
          {events.length === 0 && (
            <div className="text-center text-gray-400 py-8">
              <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No security events detected</p>
              <p className="text-xs mt-1">System monitoring active</p>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};