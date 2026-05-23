import { useState } from 'react';
import { useOrganizationContext } from "@/components/OrganizationProvider";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 text-white p-6">
      <div className="container mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="space-y-2">
            <h1 className="text-3xl font-bold bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">
              STIG-Codex Center
            </h1>
            <p className="text-gray-300">
              Advanced STIG-first compliance intelligence and automation platform
            </p>
          </div>
          <div className="flex items-center space-x-4">
            <Badge variant="secondary" className="bg-green-500/20 text-green-400 border-green-500/30">
              <Activity className="h-3 w-3 mr-1" />
              System Active
            </Badge>
            <Button
              onClick={() => stigCodex.refreshAllData()}
              disabled={stigCodex.loading}
              className="bg-gradient-to-r from-cyan-500 to-blue-500"
            >
              Refresh Data
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

          <TabsContent value="overview" className="space-y-6">
            <STIGCodexDashboard {...({} as any)} />
          </TabsContent>

          <TabsContent value="analytics" className="space-y-6">
            <STIGAnalyticsDashboard />
          </TabsContent>

          <TabsContent value="automation" className="space-y-6">
            <RemediationWorkflowBuilder />
          </TabsContent>

          <TabsContent value="registry" className="space-y-6">
            <STIGTrustedRegistry />
          </TabsContent>

          <TabsContent value="bridge" className="space-y-6">
            <CMMCSTIGBridge />
          </TabsContent>

          <TabsContent value="intelligence" className="space-y-6">
            <STIGThreatIntelligence />
          </TabsContent>

          <TabsContent value="integrations" className="space-y-6">
            <EnterpriseIntegrationsHub />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default STIGCodexCenter;