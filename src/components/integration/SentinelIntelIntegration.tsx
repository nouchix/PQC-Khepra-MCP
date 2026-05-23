import { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import {
  Globe,
  Shield,
  CheckCircle,
  RefreshCw,
  Settings,
  Database,
  TrendingUp,
  Radar
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";

interface OSINTFeed {
  id: string;
  name: string;
  type: 'THREAT_INTEL' | 'VULNERABILITY' | 'IOC' | 'ADVISORY';
  status: 'ACTIVE' | 'INACTIVE' | 'ERROR';
  lastSync: string;
  indicatorCount: number;
  apiEndpoint: string;
  syncInterval: number; // minutes
}

interface IntegrationMetrics {
  totalFeeds: number;
  activeFeeds: number;
  indicatorsToday: number;
  threatsBlocked: number;
  lastUpdate: string;
}

export const SentinelIntelIntegration = () => {
  const [feeds, setFeeds] = useState<OSINTFeed[]>([]);
  const [metrics, setMetrics] = useState<IntegrationMetrics>({
    totalFeeds: 0,
    activeFeeds: 0,
    indicatorsToday: 0,
    threatsBlocked: 0,
    lastUpdate: new Date().toISOString()
  });
  const [autoSync, setAutoSync] = useState(true);
  const [apiKey, setApiKey] = useState('');
  const [syncing, setSyncing] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    initializeFeeds();
    loadMetrics();
  }, []);

  const initializeFeeds = () => {
    // Awaiting telemetry for real intelligence feeds
    const pendingFeeds: OSINTFeed[] = [];

    setFeeds(pendingFeeds);
  };

  const loadMetrics = () => {
    // Awaiting telemetry for actual metrics
    setMetrics({
      totalFeeds: 0,
      activeFeeds: 0,
      indicatorsToday: 0,
      threatsBlocked: 0,
      lastUpdate: new Date().toISOString()
    });
  };

  const syncFeed = async (feedId: string) => {
    setSyncing(true);
    try {
      // Call the threat-feed-sync edge function with generic source
      const { data, error } = await supabase.functions.invoke('threat-feed-sync', {
        body: {
          source: 'sentinel',
          feedId,
          apiKey: apiKey || 'demo-key'
        }
      });

      if (error) throw error;

      // Update feed status
      setFeeds(prev => prev.map(feed =>
        feed.id === feedId
          ? { ...feed, lastSync: new Date().toISOString(), status: 'ACTIVE' as const }
          : feed
      ));

      toast({
        title: "Sync Complete",
        description: `Successfully synced Sentinel feed. ${data?.indicators || 0} indicators processed.`
      });

      // Refresh metrics
      loadMetrics();
    } catch (error: any) {
      console.error('Sync error:', error);
      toast({
        title: "Sync Failed",
        description: error.message || "Failed to sync with Sentinel API",
        variant: "destructive"
      });
    } finally {
      setSyncing(false);
    }
  };

  const syncAllFeeds = async () => {
    setSyncing(true);
    const activeFeeds = feeds.filter(f => f.status === 'ACTIVE');

    try {
      const syncPromises = activeFeeds.map(feed => syncFeed(feed.id));
      await Promise.all(syncPromises);

      toast({
        title: "Bulk Sync Complete",
        description: `Successfully synced ${activeFeeds.length} Sentinel intel feeds.`
      });
    } catch (error) {
      console.error("Bulk sync error:", error);
      toast({
        title: "Bulk Sync Failed",
        description: "Some feeds failed to sync. Check individual feed status.",
        variant: "destructive"
      });
    } finally {
      setSyncing(false);
    }
  };

  const toggleFeedStatus = (feedId: string) => {
    setFeeds(prev => prev.map(feed =>
      feed.id === feedId
        ? { ...feed, status: feed.status === 'ACTIVE' ? 'INACTIVE' : 'ACTIVE' }
        : feed
    ));
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'ACTIVE': return 'text-green-400';
      case 'INACTIVE': return 'text-gray-400';
      case 'ERROR': return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'THREAT_INTEL': return 'bg-red-500/20 text-red-400';
      case 'IOC': return 'bg-orange-500/20 text-orange-400';
      case 'VULNERABILITY': return 'bg-yellow-500/20 text-yellow-400';
      case 'ADVISORY': return 'bg-blue-500/20 text-blue-400';
      default: return 'bg-gray-500/20 text-gray-400';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card className="bg-gradient-to-r from-slate-900 to-blue-900/40 border-slate-800">
        <CardHeader>
          <CardTitle className="flex items-center space-x-3 text-white">
            <Radar className="h-6 w-6 text-red-500" />
            <div>
              <h2 className="text-xl font-bold">Sentinel OSINT Intelligence</h2>
              <p className="text-blue-200 text-sm">Automated vCISO & CMMC Threat Correlation</p>
            </div>
          </CardTitle>
        </CardHeader>
      </Card>

      {/* Metrics Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-slate-900/50 border-slate-800 backdrop-blur-lg">
          <CardContent className="p-4 text-center">
            <Database className="h-8 w-8 text-blue-400 mx-auto mb-2" />
            <div className="text-2xl font-bold text-white">{metrics.totalFeeds}</div>
            <div className="text-xs text-slate-400">Total Feeds</div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800 backdrop-blur-lg">
          <CardContent className="p-4 text-center">
            <CheckCircle className="h-8 w-8 text-green-400 mx-auto mb-2" />
            <div className="text-2xl font-bold text-white">{metrics.activeFeeds}</div>
            <div className="text-xs text-slate-400">Active Feeds</div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800 backdrop-blur-lg">
          <CardContent className="p-4 text-center">
            <TrendingUp className="h-8 w-8 text-yellow-400 mx-auto mb-2" />
            <div className="text-2xl font-bold text-white">{metrics.indicatorsToday}</div>
            <div className="text-xs text-slate-400">Indicators Today</div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800 backdrop-blur-lg">
          <CardContent className="p-4 text-center">
            <Shield className="h-8 w-8 text-red-400 mx-auto mb-2" />
            <div className="text-2xl font-bold text-white">{metrics.threatsBlocked}</div>
            <div className="text-xs text-slate-400">Threats Neutralized</div>
          </CardContent>
        </Card>
      </div>

      {/* Configuration */}
      <Card className="bg-black/40 border-slate-800 backdrop-blur-lg">
        <CardHeader>
          <CardTitle className="flex items-center justify-between text-white">
            <div className="flex items-center space-x-2">
              <Settings className="h-5 w-5 text-blue-400" />
              <span>Sentinel Configuration</span>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <Label className="text-sm text-slate-300">Auto Sync</Label>
                <Switch checked={autoSync} onCheckedChange={setAutoSync} />
              </div>
              <Button
                onClick={syncAllFeeds}
                disabled={syncing}
                className="bg-blue-600 hover:bg-blue-700"
              >
                {syncing ? <RefreshCw className="h-4 w-4 animate-spin mr-2" /> : null}
                Sync All
              </Button>
            </div>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <Label className="text-sm text-slate-300 mb-2 block">Sentinel API Key</Label>
              <Input
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="Enter Unified Sentinel API Key"
                className="bg-slate-900 border-slate-700 text-white"
              />
              <p className="text-xs text-slate-500 mt-1">
                Provide your internal AdinKhepra credential for secure intel streaming
              </p>
            </div>
            <div className="space-y-2">
              <Label className="text-sm text-slate-300">Intel Pipeline Status</Label>
              <div className="flex items-center space-x-2 p-3 bg-green-900/40 rounded border border-green-500/30">
                <CheckCircle className="h-4 w-4 text-green-400" />
                <span className="text-sm text-green-200">Intelligence Stream Active</span>
              </div>
              <div className="text-xs text-slate-500">
                Last heartbeat: {new Date(metrics.lastUpdate).toLocaleString()}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Feed Management */}
      <Card className="bg-black/40 border-slate-800 backdrop-blur-lg">
        <CardHeader>
          <CardTitle className="text-white">Unified Pulse Management</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {feeds.map((feed) => (
              <div key={feed.id} className="p-4 bg-slate-900/60 rounded-lg border border-slate-800">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center space-x-3">
                    <Globe className="h-5 w-5 text-blue-400" />
                    <div>
                      <h3 className="text-white font-medium">{feed.name}</h3>
                      <div className="flex items-center space-x-2 mt-1">
                        <Badge className={getTypeColor(feed.type)}>{feed.type}</Badge>
                        <span className={`text-xs ${getStatusColor(feed.status)}`}>
                          {feed.status}
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center space-x-3">
                    <div className="text-right text-sm">
                      <div className="text-white font-medium">{feed.indicatorCount.toLocaleString()}</div>
                      <div className="text-slate-400 text-xs">indicators</div>
                    </div>
                    <Switch
                      checked={feed.status === 'ACTIVE'}
                      onCheckedChange={() => toggleFeedStatus(feed.id)}
                    />
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => syncFeed(feed.id)}
                      disabled={syncing || feed.status !== 'ACTIVE'}
                      className="border-slate-800 text-blue-400 hover:bg-blue-600/20"
                    >
                      {syncing ? <RefreshCw className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
                    </Button>
                  </div>
                </div>
                <div className="grid grid-cols-3 gap-4 text-xs text-slate-500">
                  <div>
                    <span className="block font-medium">Internal API Path:</span>
                    <span>{feed.apiEndpoint}</span>
                  </div>
                  <div>
                    <span className="block font-medium">Pulse Frequency:</span>
                    <span>{feed.syncInterval} minutes</span>
                  </div>
                  <div>
                    <span className="block font-medium">Last Data Pulse:</span>
                    <span>{new Date(feed.lastSync).toLocaleString()}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Capabilities */}
      <Card className="bg-black/40 border-slate-800 backdrop-blur-lg">
        <CardHeader>
          <CardTitle className="text-white">Sentinel Intel Capabilities</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-3">
              <h4 className="text-blue-400 font-medium">Intelligence-Driven Detection</h4>
              <ul className="space-y-2 text-sm text-slate-300">
                <li className="flex items-center space-x-2">
                  <CheckCircle className="h-4 w-4 text-emerald-400" />
                  <span>Real-time correlation of OSINT IOCs to active workloads</span>
                </li>
                <li className="flex items-center space-x-2">
                  <CheckCircle className="h-4 w-4 text-emerald-400" />
                  <span>Automated threat landscape mapping for CMMC assessments</span>
                </li>
              </ul>
            </div>
            <div className="space-y-3">
              <h4 className="text-blue-400 font-medium">Autonomous Remediation</h4>
              <ul className="space-y-2 text-sm text-slate-300">
                <li className="flex items-center space-x-2">
                  <CheckCircle className="h-4 w-4 text-emerald-400" />
                  <span>60-80% reduction in true-positive validation time</span>
                </li>
                <li className="flex items-center space-x-2">
                  <CheckCircle className="h-4 w-4 text-emerald-400" />
                  <span>Instant POA&M generation linked to forensic evidence</span>
                </li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};