import { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { AlertTriangle, Archive, Trash2, Filter, Download, Shield, Activity, Settings, Database } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';
import { SecurityEvent } from '@/hooks/useSecurityEvents';

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

interface EventSource {
  id: string;
  source_name: string;
  source_type: string;
  trusted: boolean;
  environment: string;
  auto_tag_rules: any;
  rate_limit_per_minute: number;
  enabled: boolean;
  last_activity: string;
  created_at: string;
}

export const SecurityEventsAdmin = () => {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [webhookActivity, setWebhookActivity] = useState<WebhookActivity[]>([]);
  const [eventSources, setEventSources] = useState<EventSource[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedEvents, setSelectedEvents] = useState<string[]>([]);
  const [filter, setFilter] = useState({
    severity: '',
    source: '',
    environment: '',
    realOrTest: '',
    dateRange: ''
  });
  const { toast } = useToast();

  useEffect(() => {
    loadAllData();
  }, []);

  const loadAllData = async () => {
    setLoading(true);
    try {
      const [eventsResult, webhookResult, sourcesResult] = await Promise.all([
        supabase.from('security_events').select('*').order('created_at', { ascending: false }),
        supabase.from('webhook_activity').select('*').order('created_at', { ascending: false }).limit(100),
        supabase.from('event_sources').select('*').order('source_name')
      ]);

      if (eventsResult.error) throw eventsResult.error;
      if (webhookResult.error) throw webhookResult.error;
      if (sourcesResult.error) throw sourcesResult.error;

      setEvents((eventsResult.data as SecurityEvent[]) || []);
      setWebhookActivity((webhookResult.data as WebhookActivity[]) || []);
      setEventSources((sourcesResult.data as EventSource[]) || []);
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

  const archiveSelectedEvents = async () => {
    if (selectedEvents.length === 0) return;

    try {
      const { error } = await supabase
        .from('security_events')
        .update({ 
          archived: true, 
          archived_at: new Date().toISOString() 
        })
        .in('id', selectedEvents);

      if (error) throw error;

      setEvents(prev => prev.map(event => 
        selectedEvents.includes(event.id) 
          ? { ...event, archived: true, archived_at: new Date().toISOString() }
          : event
      ));

      setSelectedEvents([]);
      toast({
        title: "Success",
        description: `${selectedEvents.length} events archived successfully.`
      });
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const deleteSelectedEvents = async () => {
    if (selectedEvents.length === 0) return;

    const confirmed = globalThis.confirm(`Are you sure you want to permanently delete ${selectedEvents.length} events? This action cannot be undone.`);
    if (!confirmed) return;

    try {
      const { error } = await supabase
        .from('security_events')
        .delete()
        .in('id', selectedEvents);

      if (error) throw error;

      setEvents(prev => prev.filter(event => !selectedEvents.includes(event.id)));
      setSelectedEvents([]);
      
      toast({
        title: "Success",
        description: `${selectedEvents.length} events deleted successfully.`
      });
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const exportEvents = async () => {
    try {
      const filteredEvents = applyFilters(events);
      const csvContent = generateCSV(filteredEvents);
      const blob = new Blob([csvContent], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `security-events-${new Date().toISOString().split('T')[0]}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (error: any) {
      toast({
        title: "Error",
        description: "Failed to export events",
        variant: "destructive"
      });
    }
  };

  const generateCSV = (events: SecurityEvent[]) => {
    const headers = ['ID', 'Event Type', 'Severity', 'Source', 'Environment', 'Real/Test', 'Created At', 'Resolved'];
    const rows = events.map(event => [
      event.id,
      event.event_type,
      event.severity,
      event.source_system,
      event.event_tags?.environment || 'unknown',
      event.event_tags?.real_or_test || 'unknown',
      event.created_at,
      event.resolved ? 'Yes' : 'No'
    ]);
    
    return [headers, ...rows].map(row => row.join(',')).join('\n');
  };

  const applyFilters = (eventList: SecurityEvent[]) => {
    return eventList.filter(event => {
      if (filter.severity && event.severity !== filter.severity) return false;
      if (filter.source && event.source_system !== filter.source) return false;
      if (filter.environment && event.event_tags?.environment !== filter.environment) return false;
      if (filter.realOrTest && event.event_tags?.real_or_test !== filter.realOrTest) return false;
      return true;
    });
  };

  const filteredEvents = applyFilters(events);
  const testEvents = events.filter(e => e.event_tags?.real_or_test === 'test');
  const realEvents = events.filter(e => e.event_tags?.real_or_test === 'real');

  if (loading) {
    return (
      <div className="p-6">
        <div className="text-center text-gray-400">Loading admin panel...</div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Shield className="h-6 w-6" />
          Security Events Administration
        </h1>
        <div className="flex items-center gap-2">
          <Button onClick={exportEvents} variant="outline" size="sm">
            <Download className="h-4 w-4 mr-2" />
            Export
          </Button>
          <Button onClick={loadAllData} variant="outline" size="sm">
            Refresh
          </Button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="bg-background/50 border-border">
          <CardContent className="p-4">
            <div className="text-sm text-muted-foreground">Total Events</div>
            <div className="text-2xl font-bold text-foreground">{events.length}</div>
          </CardContent>
        </Card>
        <Card className="bg-background/50 border-border">
          <CardContent className="p-4">
            <div className="text-sm text-muted-foreground">Real Events</div>
            <div className="text-2xl font-bold text-green-400">{realEvents.length}</div>
          </CardContent>
        </Card>
        <Card className="bg-background/50 border-border">
          <CardContent className="p-4">
            <div className="text-sm text-muted-foreground">Test Events</div>
            <div className="text-2xl font-bold text-blue-400">{testEvents.length}</div>
          </CardContent>
        </Card>
        <Card className="bg-background/50 border-border">
          <CardContent className="p-4">
            <div className="text-sm text-muted-foreground">Archived</div>
            <div className="text-2xl font-bold text-gray-400">{events.filter(e => e.archived).length}</div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="events" className="w-full">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="events" className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4" />
            Events Management
          </TabsTrigger>
          <TabsTrigger value="sources" className="flex items-center gap-2">
            <Database className="h-4 w-4" />
            Event Sources
          </TabsTrigger>
          <TabsTrigger value="webhook" className="flex items-center gap-2">
            <Activity className="h-4 w-4" />
            Webhook Activity
          </TabsTrigger>
        </TabsList>

        <TabsContent value="events" className="space-y-4">
          {/* Filters */}
          <Card className="bg-background/50 border-border">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Filter className="h-5 w-5" />
                Filters & Actions
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <Select value={filter.severity} onValueChange={(value) => setFilter(prev => ({ ...prev, severity: value }))}>
                  <SelectTrigger>
                    <SelectValue placeholder="Severity" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="">All Severities</SelectItem>
                    <SelectItem value="CRITICAL">Critical</SelectItem>
                    <SelectItem value="WARNING">Warning</SelectItem>
                    <SelectItem value="INFO">Info</SelectItem>
                  </SelectContent>
                </Select>

                <Select value={filter.source} onValueChange={(value) => setFilter(prev => ({ ...prev, source: value }))}>
                  <SelectTrigger>
                    <SelectValue placeholder="Source" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="">All Sources</SelectItem>
                    {[...new Set(events.map(e => e.source_system))].map(source => (
                      <SelectItem key={source} value={source}>{source}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>

                <Select value={filter.environment} onValueChange={(value) => setFilter(prev => ({ ...prev, environment: value }))}>
                  <SelectTrigger>
                    <SelectValue placeholder="Environment" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="">All Environments</SelectItem>
                    <SelectItem value="production">Production</SelectItem>
                    <SelectItem value="test">Test</SelectItem>
                    <SelectItem value="unknown">Unknown</SelectItem>
                  </SelectContent>
                </Select>

                <Select value={filter.realOrTest} onValueChange={(value) => setFilter(prev => ({ ...prev, realOrTest: value }))}>
                  <SelectTrigger>
                    <SelectValue placeholder="Type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="">All Types</SelectItem>
                    <SelectItem value="real">Real Events</SelectItem>
                    <SelectItem value="test">Test Events</SelectItem>
                    <SelectItem value="unknown">Unknown</SelectItem>
                  </SelectContent>
                </Select>

                <Button 
                  onClick={() => setFilter({ severity: '', source: '', environment: '', realOrTest: '', dateRange: '' })}
                  variant="outline"
                >
                  Clear Filters
                </Button>
              </div>

              {selectedEvents.length > 0 && (
                <div className="flex items-center gap-4 p-4 bg-blue-500/10 border border-blue-500/30 rounded">
                  <span className="text-blue-400">{selectedEvents.length} events selected</span>
                  <Button onClick={archiveSelectedEvents} size="sm" variant="outline">
                    <Archive className="h-4 w-4 mr-2" />
                    Archive
                  </Button>
                  <Button onClick={deleteSelectedEvents} size="sm" variant="destructive">
                    <Trash2 className="h-4 w-4 mr-2" />
                    Delete
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Events List */}
          <Card className="bg-background/50 border-border">
            <CardHeader>
              <CardTitle>Security Events ({filteredEvents.length})</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {filteredEvents.map((event) => (
                  <div key={event.id} className="p-3 bg-card border border-border rounded flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <input
                        type="checkbox"
                        checked={selectedEvents.includes(event.id)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedEvents(prev => [...prev, event.id]);
                          } else {
                            setSelectedEvents(prev => prev.filter(id => id !== event.id));
                          }
                        }}
                        className="rounded"
                      />
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-foreground">{event.event_type}</span>
                          <Badge variant={event.severity === 'CRITICAL' ? 'destructive' : event.severity === 'WARNING' ? 'secondary' : 'default'}>
                            {event.severity}
                          </Badge>
                          {event.event_tags?.real_or_test && (
                            <Badge variant={event.event_tags.real_or_test === 'real' ? 'default' : 'outline'}>
                              {event.event_tags.real_or_test}
                            </Badge>
                          )}
                          {event.archived && (
                            <Badge variant="secondary">Archived</Badge>
                          )}
                        </div>
                        <div className="text-sm text-muted-foreground">
                          {event.source_system} • {new Date(event.created_at).toLocaleString()}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="sources" className="space-y-4">
          <Card className="bg-background/50 border-border">
            <CardHeader>
              <CardTitle>Event Sources Configuration</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {eventSources.map((source) => (
                  <div key={source.id} className="p-4 bg-card border border-border rounded">
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-foreground">{source.source_name}</span>
                          <Badge variant={source.trusted ? 'default' : 'secondary'}>
                            {source.trusted ? 'Trusted' : 'Untrusted'}
                          </Badge>
                          <Badge variant={source.enabled ? 'default' : 'outline'}>
                            {source.enabled ? 'Enabled' : 'Disabled'}
                          </Badge>
                        </div>
                        <div className="text-sm text-muted-foreground">
                          Type: {source.source_type} | Environment: {source.environment} | Rate Limit: {source.rate_limit_per_minute}/min
                        </div>
                        {source.last_activity && (
                          <div className="text-xs text-muted-foreground">
                            Last Activity: {new Date(source.last_activity).toLocaleString()}
                          </div>
                        )}
                      </div>
                      <Button size="sm" variant="outline">
                        <Settings className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="webhook" className="space-y-4">
          <Card className="bg-background/50 border-border">
            <CardHeader>
              <CardTitle>Recent Webhook Activity</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {webhookActivity.map((activity) => (
                  <div key={activity.id} className="p-3 bg-card border border-border rounded">
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-foreground">{activity.source}</span>
                          {activity.rate_limit_applied && (
                            <Badge variant="destructive">Rate Limited</Badge>
                          )}
                          <Badge variant="outline">{activity.processing_time_ms}ms</Badge>
                        </div>
                        <div className="text-sm text-muted-foreground">
                          From: {activity.source_ip} | {activity.endpoint} | {new Date(activity.created_at).toLocaleString()}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};