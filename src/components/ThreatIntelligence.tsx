
import { useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Globe, TrendingUp, AlertCircle, CheckCircle, Plus, X } from "lucide-react";
import { useThreatIntelligence } from "@/hooks/useThreatIntelligence";
import { useToast } from "@/hooks/use-toast";

export const ThreatIntelligence = () => {
  const { threats, loading, addThreat } = useThreatIntelligence();
  const [showAddForm, setShowAddForm] = useState(false);
  const [newThreat, setNewThreat] = useState({
    source: '',
    indicator_type: '',
    indicator_value: '',
    threat_level: 'MEDIUM' as const,
    description: ''
  });
  const { toast } = useToast();

  // Mock feed status for display
  const feedStats = {
    total_indicators: threats.length,
    critical_threats: threats.filter(t => t.threat_level === 'CRITICAL').length,
    high_threats: threats.filter(t => t.threat_level === 'HIGH').length,
    last_update: threats.length > 0 ? new Date(threats[0].created_at) : new Date()
  };

  const handleAddThreat = async (e: React.FormEvent) => {
    e.preventDefault();
    const { error } = await addThreat(newThreat);
    
    if (error) {
      toast({
        title: "Error",
        description: error,
        variant: "destructive"
      });
    } else {
      toast({
        title: "Threat Added",
        description: "New threat indicator has been added successfully."
      });
      setNewThreat({
        source: '',
        indicator_type: '',
        indicator_value: '',
        threat_level: 'MEDIUM',
        description: ''
      });
      setShowAddForm(false);
    }
  };

  const getStatusIcon = (status: string) => {
    return status === "active" ? 
      <CheckCircle className="h-3 w-3 text-green-400" /> : 
      <AlertCircle className="h-3 w-3 text-yellow-400" />;
  };

  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case 'CRITICAL': return 'text-red-400';
      case 'HIGH': return 'text-orange-400';
      case 'MEDIUM': return 'text-yellow-400';
      case 'LOW': return 'text-green-400';
      default: return 'text-gray-400';
    }
  };

  if (loading) {
    return (
      <Card className="bg-black/40 border-blue-500/30 backdrop-blur-lg">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2 text-blue-400">
            <Globe className="h-5 w-5" />
            <span>Threat Intelligence</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center text-gray-400">Loading threat data...</div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="bg-black/40 border-blue-500/30 backdrop-blur-lg">
      <CardHeader>
        <CardTitle className="flex items-center justify-between text-blue-400">
          <div className="flex items-center space-x-2">
            <Globe className="h-5 w-5" />
            <span>Threat Intelligence</span>
          </div>
          <Button
            size="sm"
            onClick={() => setShowAddForm(!showAddForm)}
            className="bg-blue-600/20 border-blue-500/30 text-blue-400 hover:bg-blue-600/40"
          >
            {showAddForm ? <X className="h-4 w-4" /> : <Plus className="h-4 w-4" />}
          </Button>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {showAddForm && (
          <form onSubmit={handleAddThreat} className="p-3 bg-slate-800/40 rounded border border-blue-500/30 space-y-3">
            <div className="grid grid-cols-2 gap-2">
              <div>
                <Label className="text-xs text-gray-300">Source</Label>
                <Input
                  value={newThreat.source}
                  onChange={(e) => setNewThreat({...newThreat, source: e.target.value})}
                  placeholder="e.g., MISP, Internal"
                  className="h-8 bg-slate-700 border-slate-600 text-white text-xs"
                  required
                />
              </div>
              <div>
                <Label className="text-xs text-gray-300">Type</Label>
                <Input
                  value={newThreat.indicator_type}
                  onChange={(e) => setNewThreat({...newThreat, indicator_type: e.target.value})}
                  placeholder="e.g., IP, Hash, Domain"
                  className="h-8 bg-slate-700 border-slate-600 text-white text-xs"
                  required
                />
              </div>
            </div>
            <div>
              <Label className="text-xs text-gray-300">Indicator Value</Label>
              <Input
                value={newThreat.indicator_value}
                onChange={(e) => setNewThreat({...newThreat, indicator_value: e.target.value})}
                placeholder="e.g., 192.168.1.1, evil.com"
                className="h-8 bg-slate-700 border-slate-600 text-white text-xs"
                required
              />
            </div>
            <div className="flex gap-2">
              <div className="flex-1">
                <Label className="text-xs text-gray-300">Threat Level</Label>
                <select
                  value={newThreat.threat_level}
                  onChange={(e) => setNewThreat({...newThreat, threat_level: e.target.value as any})}
                  className="w-full h-8 rounded-md border border-slate-600 bg-slate-700 px-2 text-white text-xs"
                >
                  <option value="LOW">LOW</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="HIGH">HIGH</option>
                  <option value="CRITICAL">CRITICAL</option>
                </select>
              </div>
              <Button type="submit" size="sm" className="mt-4 bg-blue-600 hover:bg-blue-700 text-xs">
                Add
              </Button>
            </div>
          </form>
        )}

        {/* Recent Threats */}
        <div className="max-h-48 overflow-y-auto space-y-2">
          {threats.slice(0, 10).map((threat) => (
            <div key={threat.id} className="flex items-center justify-between p-2 bg-slate-800/40 rounded border border-slate-600/30">
              <div className="flex items-center space-x-2">
                <div className={`w-2 h-2 rounded-full ${getThreatLevelColor(threat.threat_level)}`} />
                <div>
                  <span className="text-sm font-medium text-white">{threat.source}</span>
                  <div className="text-xs text-gray-400">{threat.indicator_type}: {threat.indicator_value}</div>
                </div>
              </div>
              <div className="text-right">
                <div className={`text-xs font-medium ${getThreatLevelColor(threat.threat_level)}`}>
                  {threat.threat_level}
                </div>
                <div className="text-xs text-gray-400">
                  {new Date(threat.created_at).toLocaleTimeString()}
                </div>
              </div>
            </div>
          ))}
        </div>
        
        <div className="mt-4 p-3 bg-gradient-to-r from-blue-900/40 to-purple-900/40 rounded-lg border border-blue-500/30">
          <div className="flex items-center space-x-2 mb-2">
            <TrendingUp className="h-4 w-4 text-blue-400" />
            <span className="text-sm font-medium text-blue-400">Intelligence Summary</span>
          </div>
          <div className="text-xs text-gray-300">
            <p>• {feedStats.total_indicators} total indicators tracked</p>
            <p>• {feedStats.critical_threats} critical threats active</p>
            <p>• {feedStats.high_threats} high-priority threats monitored</p>
            <p>• Last update: {feedStats.last_update.toLocaleTimeString()}</p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
