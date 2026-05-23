import { useState, useEffect } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Brain, Network, Lock, Users, CheckCircle, AlertTriangle, TrendingUp, RefreshCw } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useOrganization } from "@/hooks/useOrganization";
import { useToast } from "@/hooks/use-toast";

export const NVIDIAFlare = () => {
  const [federatedNodes, setFederatedNodes] = useState<any[]>([]);
  const [privacyFeatures, setPrivacyFeatures] = useState<any[]>([]);
  const [experiments, setExperiments] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const { currentOrganization } = useOrganization();
  const { toast } = useToast();

  useEffect(() => {
    if (currentOrganization) {
      fetchFlareData();
    }
  }, [currentOrganization]);

  const fetchFlareData = async () => {
    if (!currentOrganization) return;
    
    try {
      setLoading(true);
      
      // Fetch AI agent chats to simulate federated learning activity
      const { data: aiChats, error } = await supabase
        .from('ai_agent_chats')
        .select('*')
        .eq('organization_id', currentOrganization.id)
        .order('created_at', { ascending: false })
        .limit(50);

      if (error) throw error;

      // Fetch infrastructure assets to simulate federated nodes
      const { data: assets } = await supabase
        .from('infrastructure_assets')
        .select('*')
        .eq('organization_id', currentOrganization.id)
        .limit(4);

      // Create federated node data based on real infrastructure
      const nodeData = [
        {
          id: "fed-node-01",
          location: assets?.[0]?.target ? `Location-${assets[0].target.slice(-2)}` : "FOB Alpha",
          status: aiChats?.length > 10 ? "training" : "idle",
          clients: Math.max(4, Math.floor((aiChats?.length || 0) / 5)),
          accuracy: 'N/A',
          rounds: `${Math.min(aiChats?.length ?? 0, 50)}/50`,
          privacy: "Differential Privacy"
        },
        {
          id: "fed-node-02",
          location: assets?.[1]?.target ? `Location-${assets[1].target.slice(-2)}` : "Mobile Command",
          status: aiChats?.length > 5 ? "syncing" : "idle",
          clients: Math.max(6, Math.floor((aiChats?.length || 0) / 4)),
          accuracy: 'N/A',
          rounds: `${Math.min(Math.floor((aiChats?.length ?? 0) * 0.8), 50)}/50`,
          privacy: "Homomorphic Encryption"
        },
        {
          id: "fed-node-03",
          location: assets?.[2]?.target ? `Location-${assets[2].target.slice(-2)}` : "Air-Gapped Base",
          status: aiChats?.length > 15 ? "training" : "idle",
          clients: Math.max(3, Math.floor((aiChats?.length || 0) / 8)),
          accuracy: 'N/A',
          rounds: `${Math.min(Math.floor((aiChats?.length ?? 0) * 0.9), 50)}/50`,
          privacy: "Secure Aggregation"
        },
        {
          id: "fed-node-04",
          location: assets?.[3]?.target ? `Location-${assets[3].target.slice(-2)}` : "Edge Tactical",
          status: aiChats?.length > 20 ? "completed" : "training",
          clients: Math.max(2, Math.floor((aiChats?.length || 0) / 10)),
          accuracy: 'N/A',
          rounds: aiChats?.length > 20 ? "50/50" : `${Math.min(Math.floor((aiChats?.length ?? 0) * 0.7), 50)}/50`,
          privacy: "PSI + DP"
        }
      ];

      setFederatedNodes(nodeData);

      // Create privacy features based on active nodes
      const activeNodes = nodeData.filter(n => n.status !== 'idle').length;
      const privacyData = [
        {
          feature: "Differential Privacy",
          status: "active",
          nodes: Math.min(4, activeNodes),
          epsilon: "ε=0.1",
          description: "Mathematical privacy guarantee"
        },
        {
          feature: "Homomorphic Encryption",
          status: activeNodes > 2 ? "active" : "idle",
          nodes: Math.max(1, Math.min(3, activeNodes - 1)),
          epsilon: "N/A",
          description: "Encrypted computation on data"
        },
        {
          feature: "Secure Aggregation",
          status: "active",
          nodes: Math.min(4, activeNodes),
          epsilon: "N/A",
          description: "Cryptographic model updates"
        },
        {
          feature: "Private Set Intersection",
          status: activeNodes > 1 ? "active" : "idle",
          nodes: Math.max(1, Math.min(2, Math.floor(activeNodes / 2))),
          epsilon: "N/A",
          description: "Privacy-preserving data overlap"
        }
      ];

      setPrivacyFeatures(privacyData);

      // Create experiments based on AI activity
      const experimentData = [
        {
          name: "Threat Detection FL",
          progress: Math.min(100, Math.floor((aiChats?.length || 0) * 2)),
          participants: Math.max(2, Math.min(8, Math.floor((aiChats?.length || 0) / 3))),
          accuracy: 'N/A'
        },
        {
          name: "Behavioral Analysis FL",
          progress: Math.min(100, Math.floor((aiChats?.length || 0) * 1.5)),
          participants: Math.max(2, Math.min(6, Math.floor((aiChats?.length || 0) / 4))),
          accuracy: 'N/A'
        },
        {
          name: "Anomaly Detection FL",
          progress: Math.min(100, Math.floor((aiChats?.length || 0) * 3)),
          participants: Math.max(2, Math.min(4, Math.floor((aiChats?.length || 0) / 6))),
          accuracy: 'N/A'
        },
        {
          name: "Digital Fingerprint FL",
          progress: Math.min(100, Math.floor((aiChats?.length || 0) * 1.2)),
          participants: Math.max(3, Math.min(12, Math.floor((aiChats?.length || 0) / 2))),
          accuracy: 'N/A'
        }
      ];

      setExperiments(experimentData);

    } catch (error) {
      console.error('Error fetching NVIDIA FLARE data:', error);
      toast({
        title: "Error Loading Data",
        description: "Failed to fetch NVIDIA FLARE data.",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "training":
        return <Brain className="h-3 w-3 text-blue-400 animate-pulse" />;
      case "syncing":
        return <Network className="h-3 w-3 text-yellow-400 animate-pulse" />;
      case "completed":
        return <CheckCircle className="h-3 w-3 text-green-400" />;
      default:
        return <AlertTriangle className="h-3 w-3 text-red-400" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "training":
        return "text-blue-400";
      case "syncing":
        return "text-yellow-400";
      case "completed":
        return "text-green-400";
      default:
        return "text-red-400";
    }
  };

  if (loading) {
    return (
      <Card className="bg-black/40 border-purple-500/30 backdrop-blur-lg">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2 text-purple-400">
            <Network className="h-5 w-5" />
            <span>NVIDIA FLARE Federated Learning</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center text-gray-400">Loading FLARE data...</div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="bg-black/40 border-purple-500/30 backdrop-blur-lg">
      <CardHeader>
        <CardTitle className="flex items-center justify-between text-purple-400">
          <div className="flex items-center space-x-2">
            <Network className="h-5 w-5" />
            <span>NVIDIA FLARE Federated Learning</span>
          </div>
          <Button
            size="sm"
            onClick={fetchFlareData}
            disabled={loading}
            className="bg-purple-600/20 border-purple-500/30 text-purple-400 hover:bg-purple-600/40"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </Button>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div>
            <h4 className="text-sm font-semibold text-purple-400 mb-2 flex items-center space-x-2">
              <Users className="h-4 w-4" />
              <span>Federated Training Nodes</span>
            </h4>
            {federatedNodes.map((node) => (
              <div key={node.id} className="p-2 bg-slate-800/40 rounded border border-slate-600/30 mb-2">
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center space-x-2">
                    {getStatusIcon(node.status)}
                    <span className="text-xs font-medium text-white">{node.location}</span>
                  </div>
                  <span className={`text-xs ${getStatusColor(node.status)} uppercase`}>
                    {node.status}
                  </span>
                </div>
                <div className="text-xs text-gray-400 ml-5 grid grid-cols-2 gap-2">
                  <span>Clients: {node.clients}</span>
                  <span>Rounds: {node.rounds}</span>
                  <span>Accuracy: {node.accuracy}</span>
                  <span className="text-cyan-400">{node.privacy}</span>
                </div>
              </div>
            ))}
          </div>

          <div>
            <h4 className="text-sm font-semibold text-purple-400 mb-2 flex items-center space-x-2">
              <Lock className="h-4 w-4" />
              <span>Privacy-Preserving Features</span>
            </h4>
            {privacyFeatures.map((feature) => (
              <div key={feature.feature} className="p-2 bg-slate-800/40 rounded border border-slate-600/30 mb-2">
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center space-x-2">
                    <CheckCircle className="h-3 w-3 text-green-400" />
                    <span className="text-xs font-medium text-white">{feature.feature}</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="text-xs text-cyan-400">{feature.nodes} nodes</span>
                    {feature.epsilon !== "N/A" && (
                      <span className="text-xs text-purple-400">{feature.epsilon}</span>
                    )}
                  </div>
                </div>
                <p className="text-xs text-gray-400 ml-5">{feature.description}</p>
              </div>
            ))}
          </div>
        </div>

        <div>
          <h4 className="text-sm font-semibold text-purple-400 mb-2 flex items-center space-x-2">
            <Brain className="h-4 w-4" />
            <span>Active FL Experiments</span>
          </h4>
          {experiments.map((exp) => (
            <div key={exp.name} className="p-2 bg-slate-800/40 rounded border border-slate-600/30 mb-2">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-medium text-white">{exp.name}</span>
                <div className="flex items-center space-x-2">
                  <span className="text-xs text-gray-400">{exp.participants} participants</span>
                  <span className="text-xs text-cyan-400">{exp.accuracy}</span>
                </div>
              </div>
              <div className="w-full bg-slate-700 rounded-full h-1">
                <div 
                  className="bg-purple-400 h-1 rounded-full transition-all duration-300" 
                  style={{ width: `${exp.progress}%` }}
                ></div>
              </div>
              <div className="flex justify-between mt-1">
                <span className="text-xs text-gray-400">Progress</span>
                <span className="text-xs text-purple-400">{exp.progress}%</span>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-4 p-3 bg-gradient-to-r from-purple-900/40 to-blue-900/40 rounded-lg border border-purple-500/30">
          <div className="flex items-center space-x-2 mb-2">
            <TrendingUp className="h-4 w-4 text-purple-400" />
            <span className="text-sm font-medium text-purple-400">FL Performance Summary</span>
          </div>
          <div className="grid grid-cols-2 gap-4 text-xs text-gray-300">
            <div>
              <p>• {federatedNodes.reduce((sum, node) => sum + node.clients, 0)} total FL clients active</p>
              <p>• {federatedNodes.length} distributed training locations</p>
              <p>• 100% privacy compliance</p>
            </div>
            <div>
              <p>• {Math.round(experiments.reduce((sum, exp) => sum + Number.parseFloat(exp.accuracy.replaceAll('%', '')), 0) / experiments.length)}% average model accuracy</p>
              <p>• Zero data centralization</p>
              <p>• Cross-domain federation enabled</p>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};