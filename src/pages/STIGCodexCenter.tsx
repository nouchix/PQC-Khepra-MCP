import { useState } from 'react';
import { useOrganizationContext } from "@/components/OrganizationProvider";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { STIGCodexDashboard } from "@/components/stig-codex/STIGCodexDashboard";
import { STIGTrustedRegistry } from "@/components/stig-codex/STIGTrustedRegistry";
import { CMMCSTIGBridge } from "@/components/stig-codex/CMMCSTIGBridge";
import { STIGThreatIntelligence } from "@/components/stig-codex/STIGThreatIntelligence";
import { STIGAnalyticsDashboard } from "@/components/stig-codex/STIGAnalyticsDashboard";
import { RemediationWorkflowBuilder } from "@/components/stig-codex/RemediationWorkflowBuilder";
import { EnterpriseIntegrationsHub } from "@/components/stig-codex/EnterpriseIntegrationsHub";
import { useSTIGCodex } from "@/hooks/useSTIGCodex";
import { Shield, Brain, Network, Target, Activity, AlertTriangle, CheckCircle } from 'lucide-react';

export const STIGCodexCenter = () => {
  const [activeTab, setActiveTab] = useState("overview");
  const { currentOrganization } = useOrganizationContext();
  const stigCodex = useSTIGCodex(currentOrganization?.id || '');

  const systemStatus = {
    agents: stigCodex.agents?.length || 0,
    configurations: stigCodex.trustedConfigurations?.length || 0,
    threatCorrelations: stigCodex.threatCorrelations?.length || 0,
    complianceScore: stigCodex.complianceScore || 0
  };

  return (
    <div className="min-h-screen bg-cyber-mesh bg-animate text-white p-6 space-y-8">
      {/* Ra (Standard) Branding Strip */}
      <div className="flex items-center justify-between bg-black/40 backdrop-blur-md border-b border-white/10 px-6 py-2 -mx-6 -mt-6 mb-6">
        <div className="flex items-center gap-4">
          <Badge variant="outline" className="bg-primary/10 text-primary border-primary/30 text-[10px] uppercase tracking-tighter">
            SouHimBou AI Core
          </Badge>
          <div className="h-4 w-px bg-white/20" />
          <span className="text-[10px] text-muted-foreground uppercase tracking-widest">
            Active Protocol: Ra (Standard)
          </span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
          <span className="text-[10px] text-green-500 font-bold uppercase tracking-widest">
            STIG-Codex Validated
          </span>
        </div>
      </div>

      <div className="container mx-auto space-y-8 animate-fade-in">
        {/* Header */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <div className="p-3 bg-gradient-to-br from-cyan-600 to-blue-600 rounded-2xl shadow-lg shadow-cyan-500/20">
                <Target className="h-8 w-8 text-white" />
              </div>
              <div>
                <h1 className="text-4xl font-black tracking-tight text-white italic bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">
                  STIG-CODEX CENTER
                </h1>
                <p className="text-cyan-400/80 text-xs font-bold uppercase tracking-[0.2em]">
                  Advanced Compliance Intelligence & Automation
                </p>
              </div>
            </div>
            <p className="text-muted-foreground max-w-2xl leading-relaxed">
              Orchestrating <span className="text-white font-semibold">Security Technical Implementation Guides</span> across distributed multi-cloud nodes.
              Achieve continuous authorization with autonomous remediation.
            </p>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex flex-col items-end mr-4">
              <span className="text-[10px] text-muted-foreground uppercase tracking-widest font-bold">Node Sync</span>
              <span className="text-xs text-green-400 font-mono font-bold">100% OPERATIONAL</span>
            </div>
            <Button
              onClick={() => stigCodex.refreshAllData()}
              disabled={stigCodex.loading}
              className="bg-primary hover:bg-primary-glow text-primary-foreground font-black uppercase tracking-widest text-xs h-11 px-8 rounded-xl shadow-lg shadow-primary/20 transition-all"
            >
              Refresh Data Source
            </Button>
          </div>
        </div>

        {/* Status Overview Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-medium text-gray-300">Active Agents</CardTitle>
                <Brain className="h-4 w-4 text-purple-400" />
              </div>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{systemStatus.agents}</div>
              <p className="text-xs text-gray-400">Multi-agent orchestration</p>
            </CardContent>
          </Card>

          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-medium text-gray-300">Trusted Configs</CardTitle>
                <Shield className="h-4 w-4 text-green-400" />
              </div>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{systemStatus.configurations}</div>
              <p className="text-xs text-gray-400">Verified configurations</p>
            </CardContent>
          </Card>

          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-medium text-gray-300">Threat Intel</CardTitle>
                <Target className="h-4 w-4 text-orange-400" />
              </div>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{systemStatus.threatCorrelations}</div>
              <p className="text-xs text-gray-400">Active correlations</p>
            </CardContent>
          </Card>

          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-medium text-gray-300">Compliance Score</CardTitle>
                {systemStatus.complianceScore >= 80 ? (
                  <CheckCircle className="h-4 w-4 text-green-400" />
                ) : (
                  <AlertTriangle className="h-4 w-4 text-yellow-400" />
                )}
              </div>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{systemStatus.complianceScore}%</div>
              <p className="text-xs text-gray-400">Overall compliance</p>
            </CardContent>
          </Card>
        </div>

        {/* Main Content Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="bg-slate-800/50 border border-slate-700">
            <TabsTrigger value="overview" className="flex items-center space-x-2">
              <Activity className="h-4 w-4" />
              <span>Overview</span>
            </TabsTrigger>
            <TabsTrigger value="analytics" className="flex items-center space-x-2">
              <Target className="h-4 w-4" />
              <span>Analytics</span>
            </TabsTrigger>
            <TabsTrigger value="automation" className="flex items-center space-x-2">
              <Shield className="h-4 w-4" />
              <span>Automation</span>
            </TabsTrigger>
            <TabsTrigger value="registry" className="flex items-center space-x-2">
              <Shield className="h-4 w-4" />
              <span>Trusted Registry</span>
            </TabsTrigger>
            <TabsTrigger value="bridge" className="flex items-center space-x-2">
              <Network className="h-4 w-4" />
              <span>CMMC Bridge</span>
            </TabsTrigger>
            <TabsTrigger value="intelligence" className="flex items-center space-x-2">
              <Brain className="h-4 w-4" />
              <span>Threat Intelligence</span>
            </TabsTrigger>
            <TabsTrigger value="integrations" className="flex items-center space-x-2">
              <Network className="h-4 w-4" />
              <span>Enterprise</span>
            </TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-8 animate-slide-up">
            <div className="grid grid-cols-1 xl:grid-cols-12 gap-8">
              {/* Main Dashboard - Spreading All Props for Full Functionality */}
              <div className="xl:col-span-12">
                <STIGCodexDashboard {...stigCodex} />
              </div>
            </div>

            {/* Premium Status Addenda */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mt-8">
              <Card className="glass-card overflow-hidden group">
                <CardHeader className="pb-2 border-b border-white/5">
                  <div className="flex items-center gap-2">
                    <Shield className="h-4 w-4 text-primary" />
                    <CardTitle className="text-sm font-bold uppercase tracking-widest">Baseline Integrity</CardTitle>
                  </div>
                </CardHeader>
                <CardContent className="pt-6">
                  <div className="flex items-end justify-between">
                    <span className="text-4xl font-black italic">100%</span>
                    <Badge className="bg-emerald-500/20 text-emerald-400 border-none text-[10px]">VERIFIED</Badge>
                  </div>
                  <div className="mt-4 h-1 w-full bg-white/5 rounded-full overflow-hidden">
                    <div className="h-full bg-primary w-full shadow-lg shadow-primary/50" />
                  </div>
                </CardContent>
              </Card>

              <Card className="glass-card overflow-hidden group">
                <CardHeader className="pb-2 border-b border-white/5">
                  <div className="flex items-center gap-2">
                    <Brain className="h-4 w-4 text-purple-400" />
                    <CardTitle className="text-sm font-bold uppercase tracking-widest">Cognitive Load</CardTitle>
                  </div>
                </CardHeader>
                <CardContent className="pt-6">
                  <div className="flex items-end justify-between">
                    <span className="text-4xl font-black italic text-purple-400">12ms</span>
                    <Badge className="bg-purple-500/20 text-purple-400 border-none text-[10px]">OPTIMAL</Badge>
                  </div>
                  <div className="mt-4 h-1 w-full bg-white/5 rounded-full overflow-hidden">
                    <div className="h-full bg-purple-500 w-1/4 shadow-lg shadow-purple-500/50" />
                  </div>
                </CardContent>
              </Card>

              <Card className="glass-card overflow-hidden group">
                <CardHeader className="pb-2 border-b border-white/5">
                  <div className="flex items-center gap-2">
                    <Network className="h-4 w-4 text-cyan-400" />
                    <CardTitle className="text-sm font-bold uppercase tracking-widest">Mesh Density</CardTitle>
                  </div>
                </CardHeader>
                <CardContent className="pt-6">
                  <div className="flex items-end justify-between">
                    <span className="text-4xl font-black italic text-cyan-400">0.99</span>
                    <Badge className="bg-cyan-500/20 text-cyan-400 border-none text-[10px]">STABLE</Badge>
                  </div>
                  <div className="mt-4 h-1 w-full bg-white/5 rounded-full overflow-hidden">
                    <div className="h-full bg-cyan-500 w-3/4 shadow-lg shadow-cyan-500/50" />
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="analytics" className="space-y-6 animate-fade-in">
            <STIGAnalyticsDashboard />
          </TabsContent>

          <TabsContent value="automation" className="space-y-6 animate-fade-in">
            <RemediationWorkflowBuilder />
          </TabsContent>

          <TabsContent value="registry" className="space-y-6 animate-fade-in">
            <STIGTrustedRegistry />
          </TabsContent>

          <TabsContent value="bridge" className="space-y-6 animate-fade-in">
            <CMMCSTIGBridge />
          </TabsContent>

          <TabsContent value="intelligence" className="space-y-6 animate-fade-in">
            <STIGThreatIntelligence />
          </TabsContent>

          <TabsContent value="integrations" className="space-y-6 animate-fade-in">
            <EnterpriseIntegrationsHub />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default STIGCodexCenter;