import { useState, useEffect, useCallback } from 'react';
import { Node, Edge } from '@xyflow/react';
import { 
  Laptop, 
  Wifi, 
  Router, 
  Globe, 
  Database, 
  Server,
  Smartphone,
  Monitor,
  Printer,
  Shield
} from 'lucide-react';
import { productionSecurityService, SecurityAsset } from '@/services/ProductionSecurityService';

interface NetworkInfo {
  ssid?: string;
  ip?: string;
  gateway?: string;
  dns?: string[];
  isPublic?: boolean;
}

const useRealTimeAssetDiscovery = () => {
  const [discoveredAssets, setDiscoveredAssets] = useState<SecurityAsset[]>([]);
  const [networkInfo, setNetworkInfo] = useState<NetworkInfo>({});
  const [isScanning, setIsScanning] = useState(false);
  const [lastScanTime, setLastScanTime] = useState<Date | null>(null);

  // Real asset discovery using production service
  const discoverLocalAssets = useCallback(async () => {
    setIsScanning(true);
    try {
      const assets = await productionSecurityService.discoverAssets();
      setDiscoveredAssets(assets);
      setLastScanTime(new Date());
    } catch (error) {
      console.error('Production asset discovery failed:', error);
    } finally {
      setIsScanning(false);
    }
  }, []);

  // Convert SecurityAssets to ReactFlow nodes
  const generateNodes = useCallback((): Node[] => {
    return discoveredAssets.map((asset, index) => {
      const getIcon = (type: string) => {
        switch (type) {
          case 'device': return <Laptop className="h-5 w-5" />;
          case 'network': return <Router className="h-5 w-5" />;
          case 'storage': return <Database className="h-5 w-5" />;
          case 'application': return <Globe className="h-5 w-5" />;
          case 'api': return <Server className="h-5 w-5" />;
          default: return <Monitor className="h-5 w-5" />;
        }
      };

      return {
        id: asset.id,
        type: 'default',
        position: {
          x: (index % 3) * 300 + 100,
          y: Math.floor(index / 3) * 200 + 100
        },
        data: {
          id: asset.id,
          label: asset.name,
          type: asset.type,
          status: asset.status,
          environment: asset.type === 'device' ? 'Local' : 'Network',
          vulnerabilities: asset.vulnerabilities.length,
          isProtected: asset.protectionLevel !== 'none',
          icon: getIcon(asset.type),
          lastSeen: asset.lastScanned,
          details: asset.metadata
        }
      };
    });
  }, [discoveredAssets]);

  // Generate edges (connections between assets)
  const generateEdges = useCallback((): Edge[] => {
    const edges: Edge[] = [];
    
    // Connect device to network assets
    const deviceAsset = discoveredAssets.find(a => a.type === 'device');
    const networkAssets = discoveredAssets.filter(a => a.type === 'network');
    
    if (deviceAsset && networkAssets.length > 0) {
      networkAssets.forEach(networkAsset => {
        edges.push({
          id: `${deviceAsset.id}-to-${networkAsset.id}`,
          source: deviceAsset.id,
          target: networkAsset.id,
          type: 'default',
          style: { stroke: networkAsset.protectionLevel !== 'none' ? '#10b981' : '#f59e0b' }
        });
      });
    }

    // Connect applications to device
    const applicationAssets = discoveredAssets.filter(a => a.type === 'application');
    if (deviceAsset && applicationAssets.length > 0) {
      applicationAssets.forEach(appAsset => {
        edges.push({
          id: `${deviceAsset.id}-to-${appAsset.id}`,
          source: deviceAsset.id,
          target: appAsset.id,
          type: 'default',
          style: { stroke: appAsset.protectionLevel !== 'none' ? '#10b981' : '#f59e0b' }
        });
      });
    }

    return edges;
  }, [discoveredAssets]);

  // Protect an asset using production service
  const protectAsset = useCallback(async (assetId: string) => {
    try {
      const success = await productionSecurityService.protectAsset(assetId, 'khepra');
      if (success) {
        // Refresh assets to get updated status
        await discoverLocalAssets();
      }
      return success;
    } catch (error) {
      console.error('Asset protection failed:', error);
      return false;
    }
  }, [discoverLocalAssets]);

  // Scan asset for vulnerabilities
  const scanAsset = useCallback(async (assetId: string) => {
    try {
      const vulnerabilities = await productionSecurityService.scanForVulnerabilities(assetId);
      // Refresh assets to get updated vulnerabilities
      await discoverLocalAssets();
      return vulnerabilities;
    } catch (error) {
      console.error('Asset scanning failed:', error);
      return [];
    }
  }, [discoverLocalAssets]);

  // Auto-refresh every 30 seconds and discover immediately
  useEffect(() => {
    // Immediate discovery on mount
    const initialDiscovery = async () => {
      setIsScanning(true);
      try {
        const assets = await productionSecurityService.discoverAssets();
        setDiscoveredAssets(assets);
        setLastScanTime(new Date());
        console.log('Initial asset discovery complete:', assets);
      } catch (error) {
        console.error('Initial asset discovery failed:', error);
      } finally {
        setIsScanning(false);
      }
    };

    initialDiscovery();
    
    // Set up interval for periodic discovery
    const interval = setInterval(discoverLocalAssets, 30000);
    return () => clearInterval(interval);
  }, [discoverLocalAssets]); // Keep dependency but wrap discoverLocalAssets in useCallback

  return {
    discoveredAssets,
    networkInfo,
    isScanning,
    lastScanTime,
    nodes: generateNodes(),
    edges: generateEdges(),
    discoverLocalAssets,
    protectAsset,
    scanAsset
  };
};

export default useRealTimeAssetDiscovery;