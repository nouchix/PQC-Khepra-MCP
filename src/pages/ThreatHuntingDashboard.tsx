import { useState } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Shield,
  Globe,
  TrendingUp,
  Users,
  FileText,
  Link,
  AlertTriangle,
  Activity,
  Search,
  Radar
} from "lucide-react";
import { CMMCDashboard } from "@/components/compliance/CMMCDashboard";
import { SentinelIntelIntegration } from "@/components/integration/SentinelIntelIntegration";
import { POAMGenerator } from "@/components/automation/POAMGenerator";
import { ThreatIntelligence } from "@/components/ThreatIntelligence";
import { SecurityDashboard } from "@/pages/SecurityDashboard";
import { useWhiteLabel } from "@/components/branding/WhiteLabelProvider";
import { UsageTracker } from "@/components/UsageTracker";
import { ProcessBehaviorTimeline } from "@/components/forensics/ProcessBehaviorTimeline";

export const ThreatHuntingDashboard = () => {
  const [activeTab, setActiveTab] = useState("overview");
  useWhiteLabel();

  const platformStats = {
    active_monitors: 47,
    threat_confidence: 87,
    intel_feeds: 12,
    threats_neutralized: 156,
    remediation_savings: 2400000
  };

  return (
    <div className="min-h-screen bg-slate-950">
      <UsageTracker pageName="threat-hunting-dashboard" />

      {/* Header */}
      <div className="border-b border-slate-800 bg-black/40 backdrop-blur-md">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="p-2 bg-red-500/10 rounded-lg border border-red-500/20">
                <Radar className="h-6 w-6 text-red-500" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-white">
                  Sentinel Intelligence
                </h1>
                <p className="text-sm text-slate-400">
                  AdinKhepra Threat Hunting & Behavioral Analysis
                </p>
              </div>
            </div>

            <div className="flex items-center space-x-4">
              <Badge className="bg-red-500/10 text-red-500 border-red-500/20">
                Live Analysis
              </Badge>
              <Badge className="bg-blue-500/10 text-blue-500 border-blue-500/20">
                {platformStats.intel_feeds} Unified Feeds
              </Badge>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="container mx-auto px-6 py-6">
        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-8 bg-slate-900/50 border-slate-800">
            <TabsTrigger value="overview" className="data-[state=active]:bg-slate-800">
              <TrendingUp className="h-4 w-4 mr-2" />
              Overview
            </TabsTrigger>
            <TabsTrigger value="forensics" className="data-[state=active]:bg-red-600">
              <Activity className="h-4 w-4 mr-2" />
              Forensics
            </TabsTrigger>
            <TabsTrigger value="intelligence" className="data-[state=active]:bg-blue-600">
              <Globe className="h-4 w-4 mr-2" />
              Intel Feeds
            </TabsTrigger>
            <TabsTrigger value="cmmc" className="data-[state=active]:bg-slate-800">
              <Shield className="h-4 w-4 mr-2" />
              CMMC
            </TabsTrigger>
            <TabsTrigger value="poam" className="data-[state=active]:bg-slate-800">
              <FileText className="h-4 w-4 mr-2" />
              POA&M
            </TabsTrigger>
            <TabsTrigger value="threats" className="data-[state=active]:bg-slate-800">
              <AlertTriangle className="h-4 w-4 mr-2" />
              Threats
            </TabsTrigger>
            <TabsTrigger value="security" className="data-[state=active]:bg-slate-800">
              <Users className="h-4 w-4 mr-2" />
              Security
            </TabsTrigger>
            <TabsTrigger value="integration" className="data-[state=active]:bg-slate-800">
              <Link className="h-4 w-4 mr-2" />
              Connectors
            </TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-6 mt-6">
            {/* Performance Metrics */}
            <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
              <Card className="card-cyber">
                <CardContent className="p-4 text-center">
                  <Search className="h-8 w-8 text-blue-400 mx-auto mb-2" />
                  <div className="text-2xl font-bold text-white">{platformStats.active_monitors}</div>
                  <div className="text-xs text-slate-400">Active Monitors</div>
                </CardContent>
              </Card>

              <Card className="card-cyber">
                <CardContent className="p-4 text-center">
                  <Shield className="h-8 w-8 text-green-400 mx-auto mb-2" />
                  <div className="text-2xl font-bold text-white">{platformStats.threat_confidence}%</div>
                  <div className="text-xs text-slate-400">Intel Confidence</div>
                </CardContent>
              </Card>

              <Card className="card-cyber">
                <CardContent className="p-4 text-center">
                  <Globe className="h-8 w-8 text-purple-400 mx-auto mb-2" />
                  <div className="text-2xl font-bold text-white">{platformStats.intel_feeds}</div>
                  <div className="text-xs text-slate-400">Total Feeds</div>
                </CardContent>
              </Card>

              <Card className="card-cyber">
                <CardContent className="p-4 text-center">
                  <Activity className="h-8 w-8 text-red-400 mx-auto mb-2" />
                  <div className="text-2xl font-bold text-white">{platformStats.threats_neutralized}</div>
                  <div className="text-xs text-slate-400">Indicators Blocked</div>
                </CardContent>
              </Card>

              <Card className="card-cyber">
                <CardContent className="p-4 text-center">
                  <TrendingUp className="h-8 w-8 text-emerald-400 mx-auto mb-2" />
                  <div className="text-2xl font-bold text-white">${(platformStats.remediation_savings / 1000000).toFixed(1)}M</div>
                  <div className="text-xs text-slate-400">Cost Avoidance</div>
                </CardContent>
              </Card>
            </div>

            {/* Platform Analysis Summary */}
            <Card className="bg-gradient-to-r from-slate-900 to-blue-900/20 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white">
                  Sentinel Intelligence • Hybrid Analysis Engine
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-4">
                    <h3 className="text-blue-400 font-semibold">Forensics & Detection</h3>
                    <ul className="space-y-2 text-sm text-slate-300">
                      <li className="flex items-center space-x-2">
                        <div className="w-1.5 h-1.5 bg-red-500 rounded-full" />
                        <span>Real-time process behavioral mapping (Khepra Forensics)</span>
                      </li>
                      <li className="flex items-center space-x-2">
                        <div className="w-1.5 h-1.5 bg-red-500 rounded-full" />
                        <span>Cross-process correlation of I/O, Network, and Registry</span>
                      </li>
                      <li className="flex items-center space-x-2">
                        <div className="w-1.5 h-1.5 bg-red-500 rounded-full" />
                        <span>Instant lineage detection for parent-child execution logs</span>
                      </li>
                    </ul>
                  </div>
                  <div className="space-y-4">
                    <h3 className="text-emerald-400 font-semibold">Compliance Synergy</h3>
                    <ul className="space-y-2 text-sm text-slate-300">
                      <li className="flex items-center space-x-2">
                        <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full" />
                        <span>Automatic control mapping for incident response (CMMC IR.L2-3.6.1)</span>
                      </li>
                      <li className="flex items-center space-x-2">
                        <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full" />
                        <span>Forensic evidence collection with chain-of-custody logging</span>
                      </li>
                      <li className="flex items-center space-x-2">
                        <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full" />
                        <span>AI-assisted remediation prioritization and POA&M updates</span>
                      </li>
                    </ul>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Active Components */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <CMMCDashboard organizationId="default" />
              <ThreatIntelligence />
            </div>
          </TabsContent>

          <TabsContent value="forensics" className="mt-6">
            <ProcessBehaviorTimeline />
          </TabsContent>

          <TabsContent value="intelligence" className="mt-6">
            <SentinelIntelIntegration />
          </TabsContent>

          <TabsContent value="cmmc" className="mt-6">
            <CMMCDashboard organizationId="default" />
          </TabsContent>

          <TabsContent value="poam" className="mt-6">
            <POAMGenerator />
          </TabsContent>

          <TabsContent value="threats" className="mt-6">
            <ThreatIntelligence />
          </TabsContent>

          <TabsContent value="security" className="mt-6">
            <SecurityDashboard />
          </TabsContent>

          <TabsContent value="integration" className="mt-6">
            <SentinelIntelIntegration />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default ThreatHuntingDashboard;