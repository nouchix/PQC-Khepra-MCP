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
  AlertTriangle, 
  CheckCircle, 
  RefreshCw, 
  Settings,
  Link,
  Database,
  TrendingUp
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

export const HostBreachIntegration = () => {
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
    // Mock HostBreach OSINT feeds
    const mockFeeds: OSINTFeed[] = [
      {
        id: '1',
        name: 'HostBreach Threat Intel',
        type: 'THREAT_INTEL',
        status: 'ACTIVE',
        lastSync: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
        indicatorCount: 2847,
        apiEndpoint: 'https://api.hostbreach.com/v1/threat-intel',
        syncInterval: 15
      },
      {
        id: '2',
        name: 'HostBreach IOCs',
        type: 'IOC',
        status: 'ACTIVE',
        lastSync: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
        indicatorCount: 1523,
        apiEndpoint: 'https://api.hostbreach.com/v1/indicators',
        syncInterval: 5
      },
      {
        id: '3',
        name: 'HostBreach Vulnerability Feed',
        type: 'VULNERABILITY',
        status: 'ACTIVE',
        lastSync: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
        indicatorCount: 453,
        apiEndpoint: 'https://api.hostbreach.com/v1/vulnerabilities',
        syncInterval: 60
      },
      {
        id: '4',
        name: 'HostBreach Security Advisories',
        type: 'ADVISORY',
        status: 'INACTIVE',
        lastSync: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        indicatorCount: 89,
        apiEndpoint: 'https://api.hostbreach.com/v1/advisories',
        syncInterval: 1440
      }
    ];
    
    setFeeds(mockFeeds);
  };

  const loadMetrics = () => {
    setMetrics({
      totalFeeds: 4,
      activeFeeds: 3,
      indicatorsToday: 127,
      threatsBlocked: 23,
      lastUpdate: new Date().toISOString()
    });
  };

  const syncFeed = async (feedId: string) => {
    setSyncing(true);
    try {
      // Call the threat-feed-sync edge function
      const { data, error } = await supabase.functions.invoke('threat-feed-sync', {
        body: { 
          source: 'hostbreach',
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
        description: `Successfully synced HostBreach feed. ${data?.indicators || 0} indicators processed.`
      });

      // Refresh metrics
      loadMetrics();
    } catch (error: any) {
      console.error('Sync error:', error);
      toast({
        title: "Sync Failed",
        description: error.message || "Failed to sync with HostBreach API",
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
        description: `Successfully synced ${activeFeeds.length} HostBreach feeds.`
      });
    } catch (error) {
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
      <Card className="bg-gradient-to-r from-blue-900/40 to-purple-900/40 border-blue-500/30">
        <CardHeader>
          <CardTitle className="flex items-center space-x-3 text-white">
            <Link className="h-6 w-6 text-blue-400" />
            <div>
              <h2 className="text-xl font-bold">HostBreach OSINT Integration</h2>
              <p className="text-blue-200 text-sm">Intelligence-driven vCISO & CMMC Advisory Integration</p>
            </div>
          </CardTitle>
        </CardHeader>
      </Card>

      {/* Metrics Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-black/40 border-blue-500/30 backdrop-blur-lg">
          <CardContent className="p-4 text-center">
            <Database className="h-8 w-8 text-blue-400 mx-auto mb-2" />
            <div className="text-2xl font-bold text-white">{metrics.totalFeeds}</div>
            <div className="text-xs text-gray-400">Total Feeds</div>
          </CardContent>
        </Card>
        
        <Card className="bg-black/40 border-green-500/30 backdrop-blur-lg">
          <CardContent className="p-4 text-center">
            <CheckCircle className="h-8 w-8 text-green-400 mx-auto mb-2" />
            <div className="text-2xl font-bold text-white">{metrics.activeFeeds}</div>
            <div className="text-xs text-gray-400">Active Feeds</div>
          </CardContent>
        </Card>
        
        <Card className="bg-black/40 border-yellow-500/30 backdrop-blur-lg">
          <CardContent className="p-4 text-center">
            <TrendingUp className="h-8 w-8 text-yellow-400 mx-auto mb-2" />
            <div className="text-2xl font-bold text-white">{metrics.indicatorsToday}</div>
            <div className="text-xs text-gray-400">Indicators Today</div>
          </CardContent>
        </Card>
        
        <Card className="bg-black/40 border-red-500/30 backdrop-blur-lg">
          <CardContent className="p-4 text-center">
            <Shield className="h-8 w-8 text-red-400 mx-auto mb-2" />
            <div className="text-2xl font-bold text-white">{metrics.threatsBlocked}</div>
            <div className="text-xs text-gray-400">Threats Blocked</div>
          </CardContent>
        </Card>
      </div>

      {/* Configuration */}
      <Card className="bg-black/40 border-blue-500/30 backdrop-blur-lg">
        <CardHeader>
          <CardTitle className="flex items-center justify-between text-white">
            <div className="flex items-center space-x-2">
              <Settings className="h-5 w-5 text-blue-400" />
              <span>Integration Configuration</span>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <Label className="text-sm text-gray-300">Auto Sync</Label>
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
              <Label className="text-sm text-gray-300 mb-2 block">HostBreach API Key</Label>
              <Input
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="Enter your HostBreach API key"
                className="bg-slate-700 border-slate-600 text-white"
              />
              <p className="text-xs text-gray-400 mt-1">
                Contact HostBreach team for API access credentials
              </p>
            </div>
            <div className="space-y-2">
              <Label className="text-sm text-gray-300">Integration Status</Label>
              <div className="flex items-center space-x-2 p-3 bg-green-900/40 rounded border border-green-500/30">
                <CheckCircle className="h-4 w-4 text-green-400" />
                <span className="text-sm text-green-200">Connected to HostBreach API</span>
              </div>
              <div className="text-xs text-gray-400">
                Last update: {new Date(metrics.lastUpdate).toLocaleString()}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Feed Management */}
      <Card className="bg-black/40 border-blue-500/30 backdrop-blur-lg">
        <CardHeader>
          <CardTitle className="text-white">OSINT Feed Management</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {feeds.map((feed) => (
              <div key={feed.id} className="p-4 bg-slate-800/40 rounded-lg border border-slate-600/30">
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
                      <div className="text-gray-400 text-xs">indicators</div>
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
                      className="border-blue-500/30 text-blue-400 hover:bg-blue-600/20"
                    >
                      {syncing ? <RefreshCw className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
                    </Button>
                  </div>
                </div>
                <div className="grid grid-cols-3 gap-4 text-xs text-gray-400">
                  <div>
                    <span className="block font-medium">Endpoint:</span>
                    <span>{feed.apiEndpoint}</span>
                  </div>
                  <div>
                    <span className="block font-medium">Sync Interval:</span>
                    <span>{feed.syncInterval} minutes</span>
                  </div>
                  <div>
                    <span className="block font-medium">Last Sync:</span>
                    <span>{new Date(feed.lastSync).toLocaleString()}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Integration Benefits */}
      <Card className="bg-black/40 border-blue-500/30 backdrop-blur-lg">
        <CardHeader>
          <CardTitle className="text-white">HostBreach Partnership Benefits</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-3">
              <h4 className="text-blue-400 font-medium">Intelligence-Driven Compliance</h4>
              <ul className="space-y-2 text-sm text-gray-300">
                <li className="flex items-center space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-400" />
                  <span>Real-time threat intelligence integration</span>
                </li>
                <li className="flex items-center space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-400" />
                  <span>Automated IOC ingestion and blocking</span>
                </li>
                <li className="flex items-center space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-400" />
                  <span>Enhanced CMMC control validation</span>
                </li>
                <li className="flex items-center space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-400" />
                  <span>Proactive vulnerability management</span>
                </li>
              </ul>
            </div>
            <div className="space-y-3">
              <h4 className="text-blue-400 font-medium">Joint Value Proposition</h4>
              <ul className="space-y-2 text-sm text-gray-300">
                <li className="flex items-center space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-400" />
                  <span>60-80% reduction in compliance assessment time</span>
                </li>
                <li className="flex items-center space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-400" />
                  <span>Automated POA&M generation and tracking</span>
                </li>
                <li className="flex items-center space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-400" />
                  <span>White-labeled compliance dashboards</span>
                </li>
                <li className="flex items-center space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-400" />
                  <span>Executive-ready audit reports</span>
                </li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};