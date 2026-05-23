
import { useState, useEffect } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Network, Server, CheckCircle, AlertTriangle, Globe } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useOrganization } from "@/hooks/useOrganization";

export const NetworkTopology = () => {
  const [networks, setNetworks] = useState<any[]>([]);
  const [devices, setDevices] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const { currentOrganization } = useOrganization();

  useEffect(() => {
    if (currentOrganization) {
      fetchRealNetworkData();
    }
  }, [currentOrganization]);

  const fetchRealNetworkData = async () => {
    if (!currentOrganization) return;
    
    try {
      // Fetch real infrastructure assets
      const { data: assets, error } = await supabase
        .from('infrastructure_assets')
        .select('*')
        .eq('organization_id', currentOrganization.id)
        .order('discovered_at', { ascending: false });

      if (error) throw error;

      // Categorize assets into networks and devices
      const networkAssets = assets?.filter(asset => 
        asset.asset_type === 'network' || asset.asset_type === 'cloud_service'
      ) || [];

      const deviceAssets = assets?.filter(asset => 
        asset.asset_type === 'server' || asset.asset_type === 'application'
      ) || [];

      // Add basic connectivity info (in a real system this would come from network monitoring)
      const networksWithStatus = networkAssets.map(asset => ({
        id: asset.id,
        name: asset.target,
        status: asset.compliance_status === 'COMPLIANT' ? 'connected' : 'disconnected',
        latency: 'N/A', // Requires network monitoring agent — not available from browser
        encryption: 'TLS 1.3',
        location: (asset.discovery_results as any)?.location || 'Unknown',
        last_seen: asset.last_updated
      }));

      const devicesWithStatus = deviceAssets.map(asset => ({
        id: asset.id,
        type: asset.asset_type,
        name: asset.target,
        status: asset.compliance_status === 'COMPLIANT' ? 'active' : 'offline',
        location: (asset.discovery_results as any)?.location || 'Unknown',
        last_seen: asset.last_updated
      }));

      setNetworks(networksWithStatus);
      setDevices(devicesWithStatus);

    } catch (error) {
      console.error('Error fetching network data:', error);
      setNetworks([]);
      setDevices([]);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <Card className="bg-black/40 border-cyan-500/30 backdrop-blur-lg">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2 text-cyan-400">
            <Network className="h-5 w-5" />
            <span>Network Topology</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center text-gray-400">Loading network topology...</div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="bg-black/40 border-cyan-500/30 backdrop-blur-lg">
      <CardHeader>
        <CardTitle className="flex items-center space-x-2 text-cyan-400">
          <Network className="h-5 w-5" />
          <span>Network Topology</span>
          <Badge variant="outline" className="ml-2 text-xs bg-blue-500/10 text-blue-400 border-blue-500/20">
            DEMO
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <h4 className="text-sm font-semibold text-blue-400 mb-2">Network Connections</h4>
            {networks.length > 0 ? (
              networks.map((network) => (
                <div key={network.id} className="flex items-center justify-between p-2 bg-slate-800/40 rounded border border-slate-600/30 mb-2">
                  <div className="flex items-center space-x-2">
                    <div className={`w-2 h-2 rounded-full ${
                      network.status === 'connected' ? 'bg-green-400' : 'bg-red-400'
                    } animate-pulse`}></div>
                    <span className="text-xs font-medium text-white">{network.name}</span>
                  </div>
                  <div className="text-right">
                    <div className="text-xs text-cyan-400">{network.latency}</div>
                    <div className="text-xs text-gray-400">{network.encryption}</div>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center text-gray-400 py-4">
                <Globe className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p className="text-xs">No network connections detected</p>
              </div>
            )}
          </div>
          
          <div>
            <h4 className="text-sm font-semibold text-blue-400 mb-2">Connected Devices</h4>
            {devices.length > 0 ? (
              devices.map((device) => (
                <div key={device.id} className="flex items-center justify-between p-2 bg-slate-800/40 rounded border border-slate-600/30 mb-2">
                  <div className="flex items-center space-x-2">
                    {device.status === 'active' ? 
                      <CheckCircle className="h-3 w-3 text-green-400" /> : 
                      <AlertTriangle className="h-3 w-3 text-red-400" />
                    }
                    <div>
                      <div className="text-xs font-medium text-white">{device.name}</div>
                      <div className="text-xs text-gray-400">{device.type}</div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-xs text-cyan-400">{device.location}</div>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center text-gray-400 py-4">
                <Server className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p className="text-xs">No devices detected</p>
              </div>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
