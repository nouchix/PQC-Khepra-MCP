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
  Settings,
  Link,
  AlertTriangle
} from "lucide-react";
import { CMMCDashboard } from "@/components/compliance/CMMCDashboard";
import { HostBreachIntegration } from "@/components/integration/HostBreachIntegration";
import { POAMGenerator } from "@/components/automation/POAMGenerator";
import { ThreatIntelligence } from "@/components/ThreatIntelligence";
import { SecurityDashboard } from "@/views/SecurityDashboard";
import { useWhiteLabel } from "@/components/branding/WhiteLabelProvider";
import { UsageTracker } from "@/components/UsageTracker";

export const HostBreachDashboard = () => {
  const [activeTab, setActiveTab] = useState("overview");
  const { branding, isPartnerBranded } = useWhiteLabel();

  const partnerStats = {
    active_clients: 47,
    compliance_score: 87,
    threat_feeds: 12,
    incidents_prevented: 156,
    cost_savings: 2400000
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      <UsageTracker pageName="hostbreach-dashboard" />
      
      {/* Header */}
      <div className="border-b border-slate-700/50 bg-black/20 backdrop-blur-sm">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              {isPartnerBranded && branding.partner_logo_url && (
                <img 
                  src={branding.partner_logo_url} 
                  alt={branding.partner_name}
                  className="h-10 w-auto"
                />
              )}
              <div>
                <h1 className="text-2xl font-bold text-white">
                  {branding.platform_name}
                </h1>
                <p className="text-sm text-gray-400">
                  Intelligence-Driven Compliance & Security Operations
                </p>
              </div>
            </div>
            
            <div className="flex items-center space-x-4">
              <Badge className="bg-green-500/20 text-green-400 border-green-500/30">
                CMMC Level 2 Ready
              </Badge>
              <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30">
                {partnerStats.active_clients} Active Clients
              </Badge>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="container mx-auto px-6 py-6">
        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-7 bg-black/40 border-slate-700">
            <TabsTrigger value="overview" className="data-[state=active]:bg-blue-600">
              <TrendingUp className="h-4 w-4 mr-2" />
              Overview
            </TabsTrigger>
            <TabsTrigger value="cmmc" className="data-[state=active]:bg-blue-600">
              <Shield className="h-4 w-4 mr-2" />
              CMMC
            </TabsTrigger>
            <TabsTrigger value="intelligence" className="data-[state=active]:bg-blue-600">
              <Globe className="h-4 w-4 mr-2" />
              Intel Feeds
            </TabsTrigger>
            <TabsTrigger value="poam" className="data-[state=active]:bg-blue-600">
              <FileText className="h-4 w-4 mr-2" />
              POA&M
            </TabsTrigger>
            <TabsTrigger value="threats" className="data-[state=active]:bg-blue-600">
              <AlertTriangle className="h-4 w-4 mr-2" />
              Threats
            </TabsTrigger>
            <TabsTrigger value="security" className="data-[state=active]:bg-blue-600">
              <Users className="h-4 w-4 mr-2" />
              Security
            </TabsTrigger>
            <TabsTrigger value="integration" className="data-[state=active]:bg-blue-600">
              <Link className="h-4 w-4 mr-2" />
              Integration
            </TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-6 mt-6">
            {/* Partner Performance Metrics */}
            <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
              <Card className="bg-black/40 border-blue-500/30 backdrop-blur-lg">
                <CardContent className="p-4 text-center">
                  <Users className="h-8 w-8 text-blue-400 mx-auto mb-2" />
                  <div className="text-2xl font-bold text-white">{partnerStats.active_clients}</div>
                  <div className="text-xs text-gray-400">Active Clients</div>
                </CardContent>
              </Card>
              
              <Card className="bg-black/40 border-green-500/30 backdrop-blur-lg">
                <CardContent className="p-4 text-center">
                  <Shield className="h-8 w-8 text-green-400 mx-auto mb-2" />
                  <div className="text-2xl font-bold text-white">{partnerStats.compliance_score}%</div>
                  <div className="text-xs text-gray-400">Avg Compliance</div>
                </CardContent>
              </Card>
              
              <Card className="bg-black/40 border-purple-500/30 backdrop-blur-lg">
                <CardContent className="p-4 text-center">
                  <Globe className="h-8 w-8 text-purple-400 mx-auto mb-2" />
                  <div className="text-2xl font-bold text-white">{partnerStats.threat_feeds}</div>
                  <div className="text-xs text-gray-400">Intel Feeds</div>
                </CardContent>
              </Card>
              
              <Card className="bg-black/40 border-yellow-500/30 backdrop-blur-lg">
                <CardContent className="p-4 text-center">
                  <AlertTriangle className="h-8 w-8 text-yellow-400 mx-auto mb-2" />
                  <div className="text-2xl font-bold text-white">{partnerStats.incidents_prevented}</div>
                  <div className="text-xs text-gray-400">Incidents Prevented</div>
                </CardContent>
              </Card>
              
              <Card className="bg-black/40 border-green-500/30 backdrop-blur-lg">
                <CardContent className="p-4 text-center">
                  <TrendingUp className="h-8 w-8 text-green-400 mx-auto mb-2" />
                  <div className="text-2xl font-bold text-white">${(partnerStats.cost_savings / 1000000).toFixed(1)}M</div>
                  <div className="text-xs text-gray-400">Cost Savings</div>
                </CardContent>
              </Card>
            </div>

            {/* Executive Summary */}
            <Card className="bg-gradient-to-r from-blue-900/40 to-purple-900/40 border-blue-500/30">
              <CardHeader>
                <CardTitle className="text-white">
                  HostBreach x SouHimBou AI Partnership Value
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-4">
                    <h3 className="text-blue-400 font-semibold">Joint Solution Benefits</h3>
                    <ul className="space-y-2 text-sm text-gray-300">
                      <li className="flex items-center space-x-2">
                        <div className="w-2 h-2 bg-green-400 rounded-full" />
                        <span>60-80% reduction in compliance assessment time</span>
                      </li>
                      <li className="flex items-center space-x-2">
                        <div className="w-2 h-2 bg-green-400 rounded-full" />
                        <span>Automated POA&M generation and tracking</span>
                      </li>
                      <li className="flex items-center space-x-2">
                        <div className="w-2 h-2 bg-green-400 rounded-full" />
                        <span>Real-time threat intelligence integration</span>
                      </li>
                      <li className="flex items-center space-x-2">
                        <div className="w-2 h-2 bg-green-400 rounded-full" />
                        <span>Executive-ready compliance reporting</span>
                      </li>
                      <li className="flex items-center space-x-2">
                        <div className="w-2 h-2 bg-green-400 rounded-full" />
                        <span>White-labeled client presentations</span>
                      </li>
                    </ul>
                  </div>
                  <div className="space-y-4">
                    <h3 className="text-blue-400 font-semibold">Revenue Opportunities</h3>
                    <ul className="space-y-2 text-sm text-gray-300">
                      <li className="flex items-center space-x-2">
                        <div className="w-2 h-2 bg-yellow-400 rounded-full" />
                        <span>$500K+ ARR target from joint opportunities</span>
                      </li>
                      <li className="flex items-center space-x-2">
                        <div className="w-2 h-2 bg-yellow-400 rounded-full" />
                        <span>Compliance-as-a-Service recurring revenue</span>
                      </li>
                      <li className="flex items-center space-x-2">
                        <div className="w-2 h-2 bg-yellow-400 rounded-full" />
                        <span>Premium pricing for automated solutions</span>
                      </li>
                      <li className="flex items-center space-x-2">
                        <div className="w-2 h-2 bg-yellow-400 rounded-full" />
                        <span>Expanded DoD contractor market reach</span>
                      </li>
                      <li className="flex items-center space-x-2">
                        <div className="w-2 h-2 bg-yellow-400 rounded-full" />
                        <span>Reduced delivery costs through automation</span>
                      </li>
                    </ul>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Quick Overview Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <CMMCDashboard organizationId="default" />
              <ThreatIntelligence />
            </div>
          </TabsContent>

          <TabsContent value="cmmc" className="mt-6">
            <CMMCDashboard organizationId="default" />
          </TabsContent>

          <TabsContent value="intelligence" className="mt-6">
            <HostBreachIntegration />
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
            <HostBreachIntegration />
          </TabsContent>
        </Tabs>
      </div>

      {/* Footer */}
      {isPartnerBranded && branding.footer_text && (
        <div className="border-t border-slate-700/50 bg-black/20 backdrop-blur-sm">
          <div className="container mx-auto px-6 py-4">
            <div className="text-center text-sm text-gray-400">
              {branding.footer_text}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};