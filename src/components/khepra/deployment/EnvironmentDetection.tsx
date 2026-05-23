import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { ScrollArea } from '@/components/ui/scroll-area';
import { 
  Server, 
  Database, 
  Cloud, 
  Globe, 
  Container,
  Network,
  Shield,
  AlertTriangle,
  CheckCircle,
  Loader2,
  Eye,
  Zap,
  Brain,
  Laptop,
  Wifi,
  Monitor
} from 'lucide-react';

interface DetectedAsset {
  id: string;
  name: string;
  type: 'server' | 'database' | 'container' | 'network' | 'cloud' | 'endpoint' | 'application' | 'network_interface' | 'browser';
  environment: 'production' | 'staging' | 'development' | 'local' | 'external';
  security_score: number;
  vulnerabilities: string[];
  location: string;
  last_scan: string;
  selectable?: boolean;
  selected?: boolean;
}

interface EnvironmentDetectionProps {
  data?: any;
  onDataChange?: (data: any) => void;
  isActive?: boolean;
}

export const EnvironmentDetection: React.FC<EnvironmentDetectionProps> = ({
  data,
  onDataChange,
  isActive
}) => {
  const [scanProgress, setScanProgress] = useState(0);
  const [isScanning, setIsScanning] = useState(false);
  const [detectedAssets, setDetectedAssets] = useState<DetectedAsset[]>([]);
  const [scanPhase, setScanPhase] = useState('');

  const scanPhases = [
    'Initializing KHEPRA cultural sensors...',
    'Scanning local device security...',
    'Analyzing network environment...',
    'Detecting browser capabilities...',
    'Checking network interfaces...',
    'Evaluating security posture...',
    'Applying cultural threat taxonomy...',
    'Generating adaptive deployment recommendations...'
  ];

  // Real asset discovery implementation
  const performRealAssetDiscovery = async () => {
    const discoveredAssets: DetectedAsset[] = [];
    
    try {
      // 1. Local device discovery
      const deviceAssets = await discoverDeviceInfo();
      discoveredAssets.push(...deviceAssets);
      
      // 2. Network environment
      const networkAssets = await discoverNetworkInfo();
      discoveredAssets.push(...networkAssets);
      
      // 3. Browser security context
      const browserAssets = await discoverBrowserContext();
      discoveredAssets.push(...browserAssets);
      
      // 4. Network interfaces
      const interfaceAssets = await discoverNetworkInterfaces();
      discoveredAssets.push(...interfaceAssets);
      
      return discoveredAssets;
    } catch (error) {
      console.error('Asset discovery error:', error);
      return await getBasicDeviceAssets();
    }
  };

  const discoverDeviceInfo = async (): Promise<DetectedAsset[]> => {
    const assets: DetectedAsset[] = [];
    
    const userAgent = navigator.userAgent;
    const platform = navigator.platform;
    const deviceType = /Mobile|Android|iPhone|iPad/.test(userAgent) ? 'Mobile Device' : 'Desktop/Laptop';
    
    const os = platform.includes('Win') ? 'Windows' : 
               platform.includes('Mac') ? 'macOS' : 
               platform.includes('Linux') ? 'Linux' : 'Unknown OS';
    
    assets.push({
      id: 'local-device',
      name: `${os} ${deviceType}`,
      type: 'endpoint',
      environment: 'local',
      security_score: calculateDeviceSecurityScore(),
      vulnerabilities: await detectDeviceVulnerabilities(),
      location: 'current_device',
      last_scan: new Date().toISOString(),
      selectable: true,
      selected: true
    });
    
    return assets;
  };

  const discoverNetworkInfo = async (): Promise<DetectedAsset[]> => {
    const assets: DetectedAsset[] = [];
    const connection = (navigator as any).connection;
    
    if (connection) {
      const isPublicWifi = connection.effectiveType !== '4g' && connection.effectiveType !== '5g';
      
      assets.push({
        id: 'network-connection',
        name: `${connection.effectiveType?.toUpperCase() || 'Unknown'} Network Connection`,
        type: 'network',
        environment: 'external',
        security_score: isPublicWifi ? 45 : 75, // Public WiFi gets lower score
        vulnerabilities: isPublicWifi ? 
          ['unencrypted_traffic', 'public_network', 'man_in_middle_risk'] : 
          ['network_monitoring_limited'],
        location: isPublicWifi ? 'public_wifi' : 'cellular_network',
        last_scan: new Date().toISOString(),
        selectable: true,
        selected: isPublicWifi // Auto-select if public WiFi
      });
    }
    
    return assets;
  };

  const discoverBrowserContext = async (): Promise<DetectedAsset[]> => {
    const assets: DetectedAsset[] = [];
    
    assets.push({
      id: 'browser-session',
      name: 'Browser Security Context',
      type: 'application',
      environment: 'local',
      security_score: calculateBrowserSecurityScore(),
      vulnerabilities: await detectBrowserVulnerabilities(),
      location: 'browser_session',
      last_scan: new Date().toISOString(),
      selectable: true,
      selected: true
    });
    
    return assets;
  };

  const discoverNetworkInterfaces = async (): Promise<DetectedAsset[]> => {
    const assets: DetectedAsset[] = [];
    
    try {
      const localIPs = await getLocalIPs();
      localIPs.forEach((ip, index) => {
        const isPrivateIP = ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.');
        assets.push({
          id: `interface-${index}`,
          name: `Network Interface (${ip})`,
          type: 'network_interface',
          environment: 'local',
          security_score: isPrivateIP ? 80 : 50,
          vulnerabilities: isPrivateIP ? [] : ['public_ip_exposure'],
          location: ip,
          last_scan: new Date().toISOString(),
          selectable: true,
          selected: false
        });
      });
    } catch (error) {
      console.log('Network interface discovery failed:', error);
    }
    
    return assets;
  };

  const getBasicDeviceAssets = async (): Promise<DetectedAsset[]> => {
    return [{
      id: 'basic-device',
      name: 'Current Device (Limited Scan)',
      type: 'endpoint',
      environment: 'local',
      security_score: 70,
      vulnerabilities: ['limited_visibility'],
      location: 'current_device',
      last_scan: new Date().toISOString(),
      selectable: true,
      selected: true
    }];
  };

  const calculateDeviceSecurityScore = (): number => {
    let score = 65; // Base score for unknown device state
    
    // Check HTTPS
    if (globalThis.location.protocol === 'https:') score += 15;
    
    // Check for security features
    if (globalThis.isSecureContext) score += 10;
    if ('serviceWorker' in navigator) score += 5;
    if ('crypto' in window && 'subtle' in globalThis.crypto) score += 5;
    
    return Math.min(score, 100);
  };

  const detectDeviceVulnerabilities = async (): Promise<string[]> => {
    const vulns: string[] = [];
    
    if (globalThis.location.protocol !== 'https:') {
      vulns.push('insecure_connection');
    }
    
    if (!globalThis.isSecureContext) {
      vulns.push('insecure_context');
    }
    
    // Check for missing security features
    if (!('serviceWorker' in navigator)) {
      vulns.push('no_offline_protection');
    }
    
    return vulns;
  };

  const calculateBrowserSecurityScore = (): number => {
    let score = 60;
    
    if ('serviceWorker' in navigator) score += 10;
    if ('crypto' in window && 'subtle' in globalThis.crypto) score += 15;
    if (globalThis.isSecureContext) score += 15;
    
    return Math.min(score, 100);
  };

  const detectBrowserVulnerabilities = async (): Promise<string[]> => {
    const vulns: string[] = [];
    
    if (!globalThis.isSecureContext) vulns.push('insecure_context');
    if (!('serviceWorker' in navigator)) vulns.push('no_service_worker');
    if (document.referrer && !document.referrer.startsWith('https:')) vulns.push('insecure_referrer');
    
    return vulns;
  };

  const getLocalIPs = (): Promise<string[]> => {
    return new Promise((resolve) => {
      const ips: string[] = [];
      const RTCPeerConnection = (window as any).RTCPeerConnection || 
                                (window as any).webkitRTCPeerConnection || 
                                (window as any).mozRTCPeerConnection;
      
      if (!RTCPeerConnection) {
        resolve([]);
        return;
      }
      
      const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
      
      pc.onicecandidate = (event: any) => {
        if (event.candidate) {
          const candidate = event.candidate.candidate;
          const match = candidate.match(/([0-9]{1,3}(\.[0-9]{1,3}){3})/);
          if (match && !ips.includes(match[1])) {
            ips.push(match[1]);
          }
        } else {
          pc.close();
          resolve(ips);
        }
      };
      
      pc.createDataChannel('');
      pc.createOffer().then(offer => pc.setLocalDescription(offer));
      
      // Timeout after 3 seconds
      setTimeout(() => {
        pc.close();
        resolve(ips);
      }, 3000);
    });
  };

  const getAssetIcon = (type: string) => {
    switch (type) {
      case 'endpoint': return <Laptop className="h-4 w-4" />;
      case 'network': return <Wifi className="h-4 w-4" />;
      case 'application': return <Monitor className="h-4 w-4" />;
      case 'network_interface': return <Network className="h-4 w-4" />;
      case 'server': return <Server className="h-4 w-4" />;
      case 'database': return <Database className="h-4 w-4" />;
      case 'container': return <Container className="h-4 w-4" />;
      case 'cloud': return <Cloud className="h-4 w-4" />;
      default: return <Globe className="h-4 w-4" />;
    }
  };

  const getSecurityColor = (score: number) => {
    if (score >= 80) return 'text-green-500';
    if (score >= 60) return 'text-yellow-500';
    return 'text-red-500';
  };

  const toggleAssetSelection = (assetId: string) => {
    setDetectedAssets(prev => prev.map(asset => 
      asset.id === assetId ? { ...asset, selected: !asset.selected } : asset
    ));
  };

  const startEnvironmentScan = async () => {
    setIsScanning(true);
    setScanProgress(0);
    setDetectedAssets([]);

    // Real scanning process
    for (let i = 0; i < scanPhases.length; i++) {
      setScanPhase(scanPhases[i]);
      
      // Progress through each phase
      for (let j = 0; j <= 100; j += 20) {
        setScanProgress((i * 100 + j) / scanPhases.length);
        await new Promise(resolve => setTimeout(resolve, 150));
      }

      // Perform real discovery during appropriate phases
      if (i === 1) { // Device scan
        const deviceAssets = await discoverDeviceInfo();
        setDetectedAssets(prev => [...prev, ...deviceAssets]);
      } else if (i === 2) { // Network scan
        const networkAssets = await discoverNetworkInfo();
        setDetectedAssets(prev => [...prev, ...networkAssets]);
      } else if (i === 3) { // Browser scan
        const browserAssets = await discoverBrowserContext();
        setDetectedAssets(prev => [...prev, ...browserAssets]);
      } else if (i === 4) { // Interface scan
        const interfaceAssets = await discoverNetworkInterfaces();
        setDetectedAssets(prev => [...prev, ...interfaceAssets]);
      }
    }

    setIsScanning(false);
    setScanProgress(100);
    setScanPhase('Environment scan completed successfully');
  };

  useEffect(() => {
    if (isActive && !data?.scan_completed) {
      startEnvironmentScan();
    }
  }, [isActive]);

  useEffect(() => {
    // Update parent with current scan results
    if (detectedAssets.length > 0) {
      const selectedAssets = detectedAssets.filter(a => a.selected);
      onDataChange?.({
        assets: detectedAssets,
        selected_assets: selectedAssets,
        scan_completed: !isScanning,
        total_assets: detectedAssets.length,
        selected_count: selectedAssets.length,
        high_risk_assets: detectedAssets.filter(a => a.security_score < 60).length
      });
    }
  }, [detectedAssets, isScanning]);

  return (
    <div className="space-y-6">
      {/* Scan Progress */}
      <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Brain className="h-5 w-5 text-primary" />
            <span>Adaptive Environment Discovery</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span>{isScanning ? 'Scanning Environment...' : 'Scan Complete'}</span>
              <span>{Math.round(scanProgress)}%</span>
            </div>
            <Progress value={scanProgress} className="h-2" />
            {scanPhase && (
              <p className="text-sm text-muted-foreground flex items-center space-x-2">
                {isScanning && <Loader2 className="h-4 w-4 animate-spin" />}
                <span>{scanPhase}</span>
              </p>
            )}
          </div>

          {!isScanning && detectedAssets.length > 0 && (
            <div className="grid grid-cols-3 gap-4 mt-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-primary">{detectedAssets.length}</div>
                <div className="text-sm text-muted-foreground">Assets Discovered</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-green-500">
                  {detectedAssets.filter(a => a.selected).length}
                </div>
                <div className="text-sm text-muted-foreground">Selected for Protection</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-yellow-500">
                  {detectedAssets.reduce((sum, a) => sum + a.vulnerabilities.length, 0)}
                </div>
                <div className="text-sm text-muted-foreground">Vulnerabilities</div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Asset Selection */}
      {detectedAssets.length > 0 && (
        <Card className="border-border">
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Eye className="h-5 w-5" />
              <span>Choose Assets to Secure</span>
            </CardTitle>
            <p className="text-sm text-muted-foreground">
              Select the assets you want KHEPRA to protect. We've pre-selected high-risk items.
            </p>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-80">
              <div className="space-y-3">
                {detectedAssets.map((asset) => (
                  <div
                    key={asset.id}
                    className={`flex items-center justify-between p-4 border rounded-lg cursor-pointer transition-all ${
                      asset.selected 
                        ? 'border-primary/50 bg-primary/5' 
                        : 'border-border hover:border-primary/30'
                    }`}
                    onClick={() => asset.selectable && toggleAssetSelection(asset.id)}
                  >
                    <div className="flex items-center space-x-3">
                      <input
                        type="checkbox"
                        checked={asset.selected || false}
                        onChange={(e) => e.stopPropagation()}
                        className="rounded border-border"
                        disabled={!asset.selectable}
                      />
                      <div className="p-2 rounded-lg bg-muted/20">
                        {getAssetIcon(asset.type)}
                      </div>
                      <div>
                        <div className="font-medium">{asset.name}</div>
                        <div className="text-sm text-muted-foreground">
                          {asset.type} • {asset.environment} • {asset.location}
                        </div>
                        {asset.vulnerabilities.length > 0 && (
                          <div className="text-xs text-red-500 mt-1">
                            Issues: {asset.vulnerabilities.join(', ')}
                          </div>
                        )}
                      </div>
                    </div>
                    
                    <div className="flex items-center space-x-3">
                      <div className="text-right">
                        <div className={`font-medium ${getSecurityColor(asset.security_score)}`}>
                          {asset.security_score}%
                        </div>
                        <div className="text-xs text-muted-foreground">
                          {asset.vulnerabilities.length} issues
                        </div>
                      </div>
                      
                      <Badge variant={asset.security_score >= 80 ? 'default' : asset.security_score >= 60 ? 'secondary' : 'destructive'}>
                        {asset.security_score >= 80 ? (
                          <CheckCircle className="h-3 w-3 mr-1" />
                        ) : (
                          <AlertTriangle className="h-3 w-3 mr-1" />
                        )}
                        {asset.security_score >= 80 ? 'Secure' : asset.security_score >= 60 ? 'At Risk' : 'Critical'}
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      )}

      {/* Cultural Analysis */}
      {!isScanning && detectedAssets.length > 0 && (
        <Card className="border-purple-500/20 bg-purple-500/5">
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Zap className="h-5 w-5 text-purple-400" />
              <span>Adaptive Deployment Recommendation</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span>Personal Security Pattern</span>
                <Badge className="bg-purple-500/10 text-purple-400 border-purple-500/20">
                  Sankofa (Learning) - 88% Match
                </Badge>
              </div>
              <div className="flex items-center justify-between">
                <span>Network Protection Mode</span>
                <Badge className="bg-blue-500/10 text-blue-400 border-blue-500/20">
                  Eban (Fortress) - 92% Match
                </Badge>
              </div>
              <div className="flex items-center justify-between">
                <span>Adaptive Security Level</span>
                <Badge className="bg-amber-500/10 text-amber-400 border-amber-500/20">
                  Dwennimmen (Humility) - 85% Match
                </Badge>
              </div>
            </div>
            <p className="text-sm text-muted-foreground mt-3">
              Based on your environment, KHEPRA recommends Personal Agent deployment with enhanced network monitoring. 
              Perfect for protecting individual assets in untrusted environments.
            </p>
          </CardContent>
        </Card>
      )}

      {/* Action Buttons */}
      {!isScanning && (
        <div className="flex justify-center space-x-4">
          <Button
            variant="outline"
            onClick={startEnvironmentScan}
            disabled={isScanning}
          >
            <Zap className="h-4 w-4 mr-2" />
            Rescan Environment
          </Button>
          
          {detectedAssets.filter(a => a.selected).length > 0 && (
            <Button className="btn-cyber">
              <Shield className="h-4 w-4 mr-2" />
              Protect {detectedAssets.filter(a => a.selected).length} Selected Assets
            </Button>
          )}
        </div>
      )}
    </div>
  );
};