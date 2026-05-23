import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { 
  Globe, Database, Shield, Activity, AlertTriangle, 
  CheckCircle, Clock, Server, Network, Zap, Eye
} from 'lucide-react';
import { AdinkraAlgebraicEngine } from '@/khepra/aae/AdinkraEngine';

interface OSINTSource {
  id: string;
  name: string;
  type: 'vulnerability' | 'threat' | 'attack_pattern' | 'indicator';
  url: string;
  status: 'active' | 'inactive' | 'error' | 'syncing';
  lastSync: Date;
  records: number;
  khepraMapping: string;
  culturalContext: string;
  apiKey?: boolean;
}

interface OSINTFeed {
  source: string;
  indicators: any[];
  lastUpdate: Date;
  khepraFingerprint: string;
}

export const OSINTConnector = () => {
  const [sources, setSources] = useState<OSINTSource[]>([]);
  const [feeds, setFeeds] = useState<OSINTFeed[]>([]);
  const [syncingAll, setSyncingAll] = useState(false);

  useEffect(() => {
    initializeOSINTSources();
  }, []);

  const initializeOSINTSources = () => {
    const defaultSources: OSINTSource[] = [
      {
        id: 'nvd-cvss',
        name: 'NIST NVD CVSS',
        type: 'vulnerability',
        url: 'https://nvd.nist.gov/vuln/data-feeds',
        status: 'active',
        lastSync: new Date(),
        records: 23456,
        khepraMapping: 'Eban',
        culturalContext: 'security',
        apiKey: false
      },
      {
        id: 'mitre-attack',
        name: 'MITRE ATT&CK',
        type: 'attack_pattern',
        url: 'https://attack.mitre.org',
        status: 'active',
        lastSync: new Date(),
        records: 14789,
        khepraMapping: 'Nyame',
        culturalContext: 'trust',
        apiKey: false
      },
      {
        id: 'cisa-kev',
        name: 'CISA Known Exploited Vulnerabilities',
        type: 'vulnerability',
        url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
        status: 'active',
        lastSync: new Date(),
        records: 1247,
        khepraMapping: 'Eban',
        culturalContext: 'security',
        apiKey: false
      },
      {
        id: 'alienvault-otx',
        name: 'AlienVault OTX',
        type: 'threat',
        url: 'https://otx.alienvault.com',
        status: 'active',
        lastSync: new Date(),
        records: 45623,
        khepraMapping: 'Nkyinkyim',
        culturalContext: 'transformation',
        apiKey: true
      },
      {
        id: 'abuseipdb',
        name: 'AbuseIPDB',
        type: 'indicator',
        url: 'https://www.abuseipdb.com',
        status: 'active',
        lastSync: new Date(),
        records: 12890,
        khepraMapping: 'Fawohodie',
        culturalContext: 'transformation',
        apiKey: true
      },
      {
        id: 'virustotal',
        name: 'VirusTotal',
        type: 'indicator',
        url: 'https://www.virustotal.com',
        status: 'active',
        lastSync: new Date(),
        records: 67432,
        khepraMapping: 'Eban',
        culturalContext: 'security',
        apiKey: true
      },
      {
        id: 'tor-nodes',
        name: 'Tor Exit Nodes',
        type: 'indicator',
        url: 'https://check.torproject.org/exit-addresses',
        status: 'active',
        lastSync: new Date(),
        records: 1456,
        khepraMapping: 'Adwo',
        culturalContext: 'unity',
        apiKey: false
      },
      {
        id: 'malware-bazaar',
        name: 'Malware Bazaar',
        type: 'threat',
        url: 'https://bazaar.abuse.ch',
        status: 'active',
        lastSync: new Date(),
        records: 8934,
        khepraMapping: 'Nkyinkyim',
        culturalContext: 'transformation',
        apiKey: false
      },
      {
        id: 'urlhaus',
        name: 'URLhaus',
        type: 'indicator',
        url: 'https://urlhaus.abuse.ch',
        status: 'active',
        lastSync: new Date(),
        records: 15678,
        khepraMapping: 'Eban',
        culturalContext: 'security',
        apiKey: false
      },
      {
        id: 'feodo-tracker',
        name: 'Feodo Tracker',
        type: 'indicator',
        url: 'https://feodotracker.abuse.ch',
        status: 'active',
        lastSync: new Date(),
        records: 543,
        khepraMapping: 'Fawohodie',
        culturalContext: 'transformation',
        apiKey: false
      }
    ];

    setSources(defaultSources);
  };

  const handleSyncSource = async (sourceId: string) => {
    setSources(prev => prev.map(s => 
      s.id === sourceId ? { ...s, status: 'syncing' } : s
    ));

    // Simulate sync process with KHEPRA protocol
    await new Promise(resolve => setTimeout(resolve, 2000));

    const source = sources.find(s => s.id === sourceId);
    if (source) {
      // Generate KHEPRA fingerprint for the sync
      const fingerprint = AdinkraAlgebraicEngine.generateFingerprint(
        `${sourceId}-${Date.now()}`,
        [source.khepraMapping]
      );

      // Update feed data
      setFeeds(prev => [
        ...prev.filter(f => f.source !== sourceId),
        {
          source: sourceId,
          indicators: [], // Real indicators come from the OSINT feed response
          lastUpdate: new Date(),
          khepraFingerprint: fingerprint
        }
      ]);

      setSources(prev => prev.map(s => 
        s.id === sourceId ? { 
          ...s, 
          status: 'active', 
          lastSync: new Date(),
          records: s.records // Real record count requires feed response metadata
        } : s
      ));
    }
  };

  const handleSyncAll = async () => {
    setSyncingAll(true);
    
    for (const source of sources) {
      await handleSyncSource(source.id);
    }
    
    setSyncingAll(false);
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'syncing': return <Activity className="h-4 w-4 text-blue-500 animate-pulse" />;
      case 'error': return <AlertTriangle className="h-4 w-4 text-red-500" />;
      default: return <Clock className="h-4 w-4 text-gray-500" />;
    }
  };

  const getStatusBadgeVariant = (status: string) => {
    switch (status) {
      case 'active': return 'default';
      case 'syncing': return 'secondary';
      case 'error': return 'destructive';
      default: return 'outline';
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'vulnerability': return <Shield className="h-4 w-4 text-red-500" />;
      case 'threat': return <AlertTriangle className="h-4 w-4 text-orange-500" />;
      case 'attack_pattern': return <Network className="h-4 w-4 text-purple-500" />;
      case 'indicator': return <Eye className="h-4 w-4 text-blue-500" />;
      default: return <Database className="h-4 w-4 text-gray-500" />;
    }
  };

  const getCulturalContextColor = (context: string) => {
    const colors = {
      'security': 'bg-blue-500/20 text-blue-300 border-blue-500/30',
      'trust': 'bg-purple-500/20 text-purple-300 border-purple-500/30',
      'transformation': 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
      'unity': 'bg-green-500/20 text-green-300 border-green-500/30'
    };
    return colors[context] || 'bg-gray-500/20 text-gray-300 border-gray-500/30';
  };

  const totalRecords = sources.reduce((sum, source) => sum + source.records, 0);
  const activeSources = sources.filter(s => s.status === 'active').length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-primary">OSINT Source Connector</h2>
          <p className="text-muted-foreground">
            Automated intelligence gathering with KHEPRA cultural verification
          </p>
        </div>
        <Button 
          onClick={handleSyncAll} 
          disabled={syncingAll}
          className="bg-primary/20 hover:bg-primary/30 border border-primary/30"
        >
          {syncingAll ? (
            <>
              <Activity className="h-4 w-4 mr-2 animate-pulse" />
              Syncing All...
            </>
          ) : (
            <>
              <Zap className="h-4 w-4 mr-2" />
              Sync All Sources
            </>
          )}
        </Button>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Globe className="h-5 w-5 text-blue-400" />
              <div>
                <p className="text-sm text-muted-foreground">Total Sources</p>
                <p className="text-2xl font-bold">{sources.length}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <CheckCircle className="h-5 w-5 text-green-400" />
              <div>
                <p className="text-sm text-muted-foreground">Active Sources</p>
                <p className="text-2xl font-bold">{activeSources}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Database className="h-5 w-5 text-purple-400" />
              <div>
                <p className="text-sm text-muted-foreground">Total Records</p>
                <p className="text-2xl font-bold">{totalRecords.toLocaleString()}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Activity className="h-5 w-5 text-amber-400" />
              <div>
                <p className="text-sm text-muted-foreground">Last Sync</p>
                <p className="text-sm font-medium">
                  {Math.min(...sources.map(s => s.lastSync.getTime())) > Date.now() - 3600000 ? 
                    'Recent' : 'Outdated'}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Sources Grid */}
      <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Globe className="h-5 w-5" />
            <span>Intelligence Sources</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[600px]">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {sources.map((source) => (
                <Card key={source.id} className="border-border/50">
                  <CardContent className="p-4">
                    <div className="space-y-3">
                      {/* Header */}
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          {getTypeIcon(source.type)}
                          <h3 className="font-semibold">{source.name}</h3>
                        </div>
                        <Badge variant={getStatusBadgeVariant(source.status)}>
                          {getStatusIcon(source.status)}
                          <span className="ml-1">{source.status}</span>
                        </Badge>
                      </div>

                      {/* Source Details */}
                      <div className="grid grid-cols-2 gap-2 text-sm">
                        <div>
                          <p className="text-muted-foreground">Type</p>
                          <p className="capitalize">{source.type.replaceAll('_', ' ')}</p>
                        </div>
                        <div>
                          <p className="text-muted-foreground">Records</p>
                          <p className="font-medium">{source.records.toLocaleString()}</p>
                        </div>
                        <div>
                          <p className="text-muted-foreground">Last Sync</p>
                          <p className="text-xs">{source.lastSync.toLocaleString()}</p>
                        </div>
                        <div>
                          <p className="text-muted-foreground">API Key</p>
                          <p>{source.apiKey ? 'Required' : 'Not Required'}</p>
                        </div>
                      </div>

                      <Separator />

                      {/* KHEPRA Integration */}
                      <div className="space-y-2">
                        <h4 className="text-sm font-medium">KHEPRA Integration</h4>
                        <div className="flex items-center space-x-2">
                          <span className="text-xs text-muted-foreground">Symbol:</span>
                          <Badge variant="outline" className="text-xs">
                            {source.khepraMapping}
                          </Badge>
                        </div>
                        <div className="flex items-center space-x-2">
                          <span className="text-xs text-muted-foreground">Cultural Context:</span>
                          <Badge className={getCulturalContextColor(source.culturalContext)}>
                            {source.culturalContext}
                          </Badge>
                        </div>
                      </div>

                      {/* Actions */}
                      <div className="flex items-center space-x-2">
                        <Button 
                          size="sm" 
                          variant="outline" 
                          onClick={() => handleSyncSource(source.id)}
                          disabled={source.status === 'syncing'}
                          className="flex-1"
                        >
                          {source.status === 'syncing' ? (
                            <>
                              <Activity className="h-3 w-3 mr-1 animate-pulse" />
                              Syncing...
                            </>
                          ) : (
                            <>
                              <Zap className="h-3 w-3 mr-1" />
                              Sync Now
                            </>
                          )}
                        </Button>
                        <Button 
                          size="sm" 
                          variant="ghost"
                          onClick={() => globalThis.open(source.url, '_blank')}
                        >
                          <Globe className="h-3 w-3" />
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>

      {/* Recent Feeds */}
      {feeds.length > 0 && (
        <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Activity className="h-5 w-5" />
              <span>Recent Intelligence Feeds</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-48">
              <div className="space-y-2">
                {feeds.map((feed, index) => (
                  <div key={index} className="flex items-center justify-between p-2 border-l-2 border-primary">
                    <div>
                      <p className="font-medium">
                        {sources.find(s => s.id === feed.source)?.name}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {feed.indicators.length} indicators • {feed.lastUpdate.toLocaleString()}
                      </p>
                      <p className="text-xs font-mono text-muted-foreground">
                        KHEPRA: {feed.khepraFingerprint.substring(0, 24)}...
                      </p>
                    </div>
                    <Badge variant="outline" className="text-xs">
                      Fresh
                    </Badge>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      )}
    </div>
  );
};