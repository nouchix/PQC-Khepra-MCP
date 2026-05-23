
import { useState, useEffect } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { AlertTriangle, Shield, Eye, Zap } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useOrganization } from "@/hooks/useOrganization";

export const ThreatOverview = () => {
  const [threats, setThreats] = useState({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  });
  const [blockedThreats, setBlockedThreats] = useState(0);
  const [recentThreats, setRecentThreats] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const { currentOrganization } = useOrganization();

  useEffect(() => {
    if (currentOrganization) {
      fetchRealThreatData();
    }
  }, [currentOrganization]);

  const fetchRealThreatData = async () => {
    if (!currentOrganization) return;
    
    try {
      // Fetch actual alerts from the database
      const { data: alerts, error: alertsError } = await supabase
        .from('alerts')
        .select('*')
        .eq('organization_id', currentOrganization.id)
        .order('created_at', { ascending: false });

      if (alertsError) throw alertsError;

      // Count threats by severity
      const threatCounts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      };

      alerts?.forEach(alert => {
        const severity = alert.severity.toLowerCase();
        if (severity in threatCounts) {
          threatCounts[severity as keyof typeof threatCounts]++;
        }
      });

      setThreats(threatCounts);

      // Get recent unresolved threats for the monitoring section
      const recentUnresolved = alerts?.filter(alert => 
        alert.status !== 'RESOLVED' && alert.status !== 'CLOSED'
      ).slice(0, 5) || [];

      setRecentThreats(recentUnresolved);

      // Calculate blocked threats (resolved alerts)
      const resolvedCount = alerts?.filter(alert => 
        alert.status === 'RESOLVED' || alert.status === 'CLOSED'
      ).length || 0;

      setBlockedThreats(resolvedCount);

    } catch (error) {
      console.error('Error fetching threat data:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[...new Array(4)].map((_, i) => (
            <Card key={i} className="bg-slate-900/20 border-slate-500/30 backdrop-blur-lg animate-pulse">
              <CardContent className="p-4">
                <div className="h-16 bg-slate-700/50 rounded"></div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Threat Level Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-red-900/20 border-red-500/30 backdrop-blur-lg">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-red-300 text-sm font-medium">Critical</p>
                <p className="text-2xl font-bold text-red-400">{threats.critical}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-red-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-orange-900/20 border-orange-500/30 backdrop-blur-lg">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-orange-300 text-sm font-medium">High</p>
                <p className="text-2xl font-bold text-orange-400">{threats.high}</p>
              </div>
              <Zap className="h-8 w-8 text-orange-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-yellow-900/20 border-yellow-500/30 backdrop-blur-lg">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-yellow-300 text-sm font-medium">Medium</p>
                <p className="text-2xl font-bold text-yellow-400">{threats.medium}</p>
              </div>
              <Eye className="h-8 w-8 text-yellow-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-green-900/20 border-green-500/30 backdrop-blur-lg">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-green-300 text-sm font-medium">Resolved</p>
                <p className="text-2xl font-bold text-green-400">{blockedThreats}</p>
              </div>
              <Shield className="h-8 w-8 text-green-400" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Real-time Threat Monitor */}
      <Card className="bg-black/40 border-cyan-500/30 backdrop-blur-lg">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2 text-cyan-400">
            <Shield className="h-5 w-5" />
            <span>Active Threat Monitoring</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {recentThreats.length > 0 ? (
              recentThreats.map((threat) => (
                <div key={threat.id} className={`flex justify-between items-center p-3 rounded-lg border ${
                  threat.severity === 'CRITICAL' ? 'bg-red-900/20 border-red-500/30' :
                  threat.severity === 'HIGH' ? 'bg-orange-900/20 border-orange-500/30' :
                  threat.severity === 'MEDIUM' ? 'bg-yellow-900/20 border-yellow-500/30' :
                  'bg-blue-900/20 border-blue-500/30'
                }`}>
                  <div className="flex items-center space-x-3">
                    <div className={`w-3 h-3 rounded-full animate-pulse ${
                      threat.severity === 'CRITICAL' ? 'bg-red-400' :
                      threat.severity === 'HIGH' ? 'bg-orange-400' :
                      threat.severity === 'MEDIUM' ? 'bg-yellow-400' :
                      'bg-blue-400'
                    }`}></div>
                    <div>
                      <p className={`text-sm font-medium ${
                        threat.severity === 'CRITICAL' ? 'text-red-300' :
                        threat.severity === 'HIGH' ? 'text-orange-300' :
                        threat.severity === 'MEDIUM' ? 'text-yellow-300' :
                        'text-blue-300'
                      }`}>{threat.title}</p>
                      <p className="text-xs text-gray-400">
                        Source: {threat.source_type} | {new Date(threat.created_at).toLocaleString()}
                      </p>
                    </div>
                  </div>
                  <span className={`text-xs px-2 py-1 rounded ${
                    threat.severity === 'CRITICAL' ? 'text-red-400 bg-red-900/30' :
                    threat.severity === 'HIGH' ? 'text-orange-400 bg-orange-900/30' :
                    threat.severity === 'MEDIUM' ? 'text-yellow-400 bg-yellow-900/30' :
                    'text-blue-400 bg-blue-900/30'
                  }`}>{threat.severity}</span>
                </div>
              ))
            ) : (
              <div className="text-center text-gray-400 py-8">
                <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No active threats detected</p>
                <p className="text-xs mt-1">System monitoring active</p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
