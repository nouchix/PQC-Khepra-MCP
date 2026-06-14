
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import { useUserProfile } from "@/hooks/useUserProfile";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ThreatOverview } from "@/components/ThreatOverview";
import { AIAgentStatus } from "@/components/AIAgentStatus";
import { ModuleGrid } from "@/components/ModuleGrid";
import { ThreatIntelligence } from "@/components/ThreatIntelligence";
import { ActivityFeed } from "@/components/ActivityFeed";
import { NetworkTopology } from "@/components/NetworkTopology";
import { ContainerOrchestration } from "@/components/ContainerOrchestration";
import { ComplianceMonitor } from "@/components/ComplianceMonitor";
import { NVIDIAMorpheus } from "@/components/NVIDIAMorpheus";
import { DOCAArgus } from "@/components/DOCAArgus";
import { NVIDIAFlare } from "@/components/NVIDIAFlare";
import { UnifiedAdminConsole } from "@/components/UnifiedAdminConsole";
import { SecurityEventsPanel } from "@/components/SecurityEventsPanel";
import { UserManagement } from "@/components/UserManagement";
import { AuditLog } from "@/components/AuditLog";
import { RealTimeMetrics } from "@/components/RealTimeMetrics";

import { IndustryIntegrationHub } from "@/components/integrations/IndustryIntegrationHub";
import { OrganizationSwitcher } from "@/components/OrganizationSwitcher";
import { useOrganizationContext } from "@/components/OrganizationProvider";
import { ThreatFeedManager } from "@/components/ThreatFeedManager";
import { AIThreatAnalyzer } from "@/components/AIThreatAnalyzer";
import { AlertDashboard } from "@/components/AlertDashboard";

import FeatureGate from "@/components/FeatureGate";
import { TrialOnboarding } from "@/components/onboarding/TrialOnboarding";
import { UsageTracker, useUsageTracker } from "@/components/UsageTracker";
import { Shield, Brain, Activity, Container, Network, LogOut, Users, FileText, Home, BarChart3, Lock, Plug, Target, Bell, Bot, Scale, CreditCard, Crown } from "lucide-react";
import { AISecurityAgent } from "@/components/ai/AISecurityAgent";
import { AutonomousComplianceAgent } from "@/components/ai/AutonomousComplianceAgent";
import { AIAgentDeployment } from '@/components/deployment/AIAgentDeployment';
import { EnterpriseSecurityDashboard } from '@/components/EnterpriseSecurityDashboard';

import { SplunkDataFeed } from '@/components/SplunkDataFeed';
import { EmergencyResponseManager } from '@/components/EmergencyResponseManager';
import { IntegrationStatusWidget, IntegrationQuickActions } from '@/components/IntegrationStatusWidget';
import { STIGCodexCenter } from '@/views/STIGCodexCenter';

const Index = () => {
  const [currentTime, setCurrentTime] = useState(new Date());
  const [activeTab, setActiveTab] = useState("dashboard");
  const navigate = useNavigate();
  const { signOut, user } = useAuth();
  const { profile, loading: profileLoading, canManageUsers } = useUserProfile();
  const { currentOrganization, subscription } = useOrganizationContext();
  const { trackFeatureAccess } = useUsageTracker();

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Track page visit
  useEffect(() => {
    if (user) {
      trackFeatureAccess('dashboard', 'basic');
    }
  }, [user, trackFeatureAccess]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 text-white">
      {/* Header */}
      <header className="border-b border-blue-500/20 bg-black/20 backdrop-blur-lg">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-4">
                <img 
                  src="/lovable-uploads/94f06ba5-2c93-4be0-a03f-e3fff4157ca6.png" 
                  alt="SouHimBou AI Logo" 
                  className="h-12 w-auto"
                />
                 <div className="flex items-center space-x-2">
                   <h1 className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">
                     SouHimBou AI
                   </h1>
                 <span className="text-xs bg-yellow-600/20 text-yellow-400 px-2 py-1 rounded border border-yellow-500/30">
                   IN DEVELOPMENT
                 </span>
                 </div>
                 <div className="ml-6">
                   <OrganizationSwitcher />
                 </div>
              </div>
              <div className="hidden md:flex items-center space-x-6 text-sm text-gray-300">
                <div 
                  className="flex items-center space-x-1 cursor-pointer hover:text-green-300 transition-colors"
                  onClick={() => setActiveTab("security")}
                >
                  <Activity className="h-4 w-4 text-green-400" />
                  <span>System Ready</span>
                </div>
                <div 
                  className="flex items-center space-x-1 cursor-pointer hover:text-purple-300 transition-colors"
                  onClick={() => setActiveTab("ai-asoc")}
                >
                  <Brain className="h-4 w-4 text-purple-400" />
                  <span>AI Agents: Ready</span>
                </div>
                <div 
                  className="flex items-center space-x-1 cursor-pointer hover:text-orange-300 transition-colors"
                  onClick={() => setActiveTab("automation")}
                >
                  <Container className="h-4 w-4 text-orange-400" />
                  <span>Automation: Ready</span>
                </div>
                <div 
                  className="flex items-center space-x-1 cursor-pointer hover:text-cyan-300 transition-colors bg-cyan-500/10 px-3 py-2 rounded-lg border border-cyan-500/30"
                  onClick={() => setActiveTab("integrations")}
                >
                  <Plug className="h-4 w-4 text-cyan-400" />
                  <span className="text-cyan-300 font-semibold">Integration Hub: Ready</span>
                </div>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <div className="text-right">
                <div className="text-sm text-gray-300">
                  {currentTime.toLocaleString()}
                </div>
                <div className="text-xs text-gray-400">ZULU TIME</div>
              </div>
              <div className="flex items-center space-x-4">
                <Button
                  onClick={() => navigate('/dod')}
                  className="bg-gradient-to-r from-orange-500 to-red-500 hover:from-orange-600 hover:to-red-600 text-white border-0"
                >
                  <Shield className="h-4 w-4 mr-2" />
                  DOD Dashboard
                </Button>
                <div className="flex items-center space-x-2">
                  <span className="text-sm text-gray-300">{user?.email}</span>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => signOut()}
                    className="border-red-500/30 text-red-400 hover:bg-red-500/20"
                  >
                    <LogOut className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Development Status Banner */}
      <div className="bg-yellow-900/30 border-b border-yellow-500/30">
        <div className="container mx-auto px-6 py-3">
          <div className="flex items-center justify-center gap-3 text-sm">
            <Shield className="h-4 w-4 text-yellow-400 flex-shrink-0" />
            <p className="text-yellow-300 text-center">
              <strong>Development Platform Notice:</strong> This system is in active development. Beta features shown are UI prototypes only. 
              Production CUI workloads require AWS GovCloud deployment (Q2 2025) with full NIST 800-171 compliance.
            </p>
          </div>
        </div>
      </div>

      {/* Trial Onboarding */}
          <TrialOnboarding />

      <div className="container mx-auto px-6 py-8">
        <UsageTracker pageName="dashboard" />
        {profileLoading ? (
          <div className="flex items-center justify-center p-8">
            <div className="text-white">Loading profile...</div>
          </div>
        ) : (
          <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
            <TabsList className="bg-slate-800/50 border border-slate-700">
              <TabsTrigger value="dashboard" className="flex items-center space-x-2">
                <Home className="h-4 w-4" />
                <span>Dashboard</span>
              </TabsTrigger>
              <TabsTrigger value="analytics" className="flex items-center space-x-2">
                <BarChart3 className="h-4 w-4" />
                <span>Real-Time Analytics</span>
              </TabsTrigger>
              <TabsTrigger value="security" className="flex items-center space-x-2">
                <Lock className="h-4 w-4" />
                <span>Security Monitor</span>
              </TabsTrigger>
              <TabsTrigger value="integrations" className="flex items-center space-x-2 bg-gradient-to-r from-cyan-500/20 to-blue-500/20 border border-cyan-500/30">
                <Plug className="h-4 w-4 text-cyan-400" />
                <span className="text-cyan-400 font-semibold">Integration Hub</span>
              </TabsTrigger>
                <TabsTrigger value="threat-feeds" className="flex items-center space-x-2">
                  <Target className="h-4 w-4" />
                  <span>Threat Feeds</span>
                </TabsTrigger>
                <TabsTrigger value="ai-asoc" className="flex items-center space-x-2">
                  <Bot className="h-4 w-4" />
                  <span>AI ASOC Agent</span>
                </TabsTrigger>
                <TabsTrigger value="ai-analysis" className="flex items-center space-x-2">
                  <Brain className="h-4 w-4" />
                  <span>AI Analysis</span>
                </TabsTrigger>
                <TabsTrigger value="deploy-agents" className="flex items-center space-x-2 bg-gradient-to-r from-primary/20 to-blue-500/20 border border-primary/30">
                  <Bot className="h-4 w-4 text-primary" />
                  <span className="text-primary font-semibold">Deploy AI Agents</span>
                </TabsTrigger>
                <TabsTrigger value="emergency" className="flex items-center space-x-2">
                  <Bell className="h-4 w-4" />
                  <span>Emergency Response</span>
                </TabsTrigger>
                <TabsTrigger value="alerts" className="flex items-center space-x-2">
                  <Bell className="h-4 w-4" />
                  <span>Alert System</span>
                </TabsTrigger>
                <TabsTrigger value="cmmc" className="flex items-center space-x-2">
                  <Shield className="h-4 w-4" />
                  <span>CMMC Compliance</span>
                </TabsTrigger>
                <TabsTrigger value="stig-codex" className="flex items-center space-x-2 bg-gradient-to-r from-yellow-500/20 to-orange-500/20 border border-yellow-500/50">
                  <Shield className="h-4 w-4 text-yellow-400" />
                  <span className="text-yellow-400 font-bold">🚀 STIG-First Autopilot MVP</span>
                </TabsTrigger>
                <TabsTrigger value="dod" className="flex items-center space-x-2 bg-gradient-to-r from-orange-500/20 to-red-500/20 border border-orange-500/30">
                  <Shield className="h-4 w-4 text-orange-400" />
                  <span className="text-orange-400 font-semibold">DOD Operations</span>
                </TabsTrigger>
                <TabsTrigger value="automation" className="flex items-center space-x-2">
                  <Bot className="h-4 w-4" />
                  <span>Automation Engine</span>
                </TabsTrigger>
                <TabsTrigger value="billing" className="flex items-center space-x-2">
                  <CreditCard className="h-4 w-4" />
                  <span>Billing</span>
                </TabsTrigger>
                <TabsTrigger value="legal" className="flex items-center space-x-2">
                  <Scale className="h-4 w-4" />
                  <span>Legal</span>
                </TabsTrigger>
                {profile?.master_admin && (
                  <TabsTrigger value="master-admin" className="flex items-center space-x-2">
                    <Crown className="h-4 w-4" />
                    <span>Master Admin</span>
                  </TabsTrigger>
                )}
                {(profile?.role === 'admin' && !profile?.master_admin) && (
                  <TabsTrigger value="admin" className="flex items-center space-x-2">
                    <Crown className="h-4 w-4" />
                    <span>Admin Console</span>
                  </TabsTrigger>
                )}
              {canManageUsers() && (
                <>
                  <TabsTrigger value="users" className="flex items-center space-x-2">
                    <Users className="h-4 w-4" />
                    <span>User Management</span>
                  </TabsTrigger>
                  <TabsTrigger value="audit" className="flex items-center space-x-2">
                    <FileText className="h-4 w-4" />
                    <span>Audit Log</span>
                  </TabsTrigger>
                </>
              )}
            </TabsList>

            <TabsContent value="dashboard" className="space-y-6">
              {/* Main Dashboard Grid */}
              <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
                {/* Left Column - Main Metrics */}
                <div className="xl:col-span-8 space-y-6">
                  <ThreatOverview />
                  <NVIDIAMorpheus />
                  <UnifiedAdminConsole />
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <NetworkTopology />
                    <ContainerOrchestration />
                  </div>
                  <ModuleGrid onModuleClick={(moduleKey) => {
                    setActiveTab(moduleKey);
                  }} />
                </div>

                {/* Right Column - Status & Intelligence */}
                <div className="xl:col-span-4 space-y-6">
                  <IntegrationStatusWidget />
                  <AIAgentStatus />
                  <IntegrationQuickActions />
                  <SecurityEventsPanel />
                  <DOCAArgus />
                  <NVIDIAFlare />
                  <ComplianceMonitor />
                  <ThreatIntelligence />
                  <ActivityFeed />
                </div>
              </div>
            </TabsContent>

            <TabsContent value="analytics" className="space-y-6">
              <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
                <div className="xl:col-span-2">
                  <RealTimeMetrics />
                </div>
                <div>
                  <SplunkDataFeed />
                </div>
              </div>
            </TabsContent>

            <TabsContent value="security" className="space-y-6">
              <EnterpriseSecurityDashboard />
            </TabsContent>

            <TabsContent value="integrations" className="space-y-6" data-tour="integration-hub">
              <div className="space-y-6">
                <AutonomousComplianceAgent />
                <IndustryIntegrationHub />
              </div>
            </TabsContent>

            <TabsContent value="threat-feeds" className="space-y-6">
              <ThreatFeedManager />
            </TabsContent>

            <TabsContent value="ai-asoc" className="space-y-6">
              <AISecurityAgent />
            </TabsContent>

            <TabsContent value="ai-analysis" className="space-y-6">
              <FeatureGate 
                featureType="premium" 
                featureName="AI Threat Analysis" 
                description="Advanced machine learning algorithms to analyze threats and predict security incidents"
              >
                <AIThreatAnalyzer />
              </FeatureGate>
            </TabsContent>

            <TabsContent value="deploy-agents" className="space-y-6">
              <AIAgentDeployment />
            </TabsContent>

            <TabsContent value="emergency" className="space-y-6">
              <EmergencyResponseManager />
            </TabsContent>

            <TabsContent value="alerts" className="space-y-6">
              <AlertDashboard />
            </TabsContent>

            <TabsContent value="cmmc" className="space-y-6">
              <div className="grid gap-6">
                <div className="bg-gradient-to-r from-blue-600/20 to-purple-600/20 border border-blue-500/30 rounded-lg p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <h2 className="text-xl font-bold text-white mb-2">CMMC Level 3 Compliance Dashboard</h2>
                      <p className="text-gray-300">Comprehensive security controls for DoD contractor compliance</p>
                    </div>
                    <div className="flex space-x-2">
                      <Button
                        onClick={() => window.open('/security', '_blank')}
                        className="bg-gradient-to-r from-blue-500 to-purple-500 hover:from-blue-600 hover:to-purple-600"
                      >
                        <Shield className="h-4 w-4 mr-2" />
                        Open Full Dashboard
                      </Button>
                      <Button
                        onClick={() => navigate('/legal')}
                        variant="outline"
                        className="border-scale-500/30 text-scale-400 hover:bg-scale-500/20"
                      >
                        <Scale className="h-4 w-4 mr-2" />
                        Legal Documents
                      </Button>
                    </div>
                  </div>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  <div 
                    className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 cursor-pointer hover:bg-slate-700/50 transition-colors"
                    onClick={() => setActiveTab("users")}
                  >
                    <div className="flex items-center space-x-2">
                      <Lock className="h-5 w-5 text-blue-400" />
                      <div>
                        <p className="text-sm text-gray-400">MFA Setup</p>
                        <p className="text-lg font-bold text-blue-400">Configure</p>
                      </div>
                    </div>
                  </div>
                  <div 
                    className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 cursor-pointer hover:bg-slate-700/50 transition-colors"
                    onClick={() => setActiveTab("alerts")}
                  >
                    <div className="flex items-center space-x-2">
                      <Activity className="h-5 w-5 text-purple-400" />
                      <div>
                        <p className="text-sm text-gray-400">Security Events</p>
                        <p className="text-lg font-bold text-purple-400">Monitor</p>
                      </div>
                    </div>
                  </div>
                  <div 
                    className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 cursor-pointer hover:bg-slate-700/50 transition-colors"
                    onClick={() => navigate('/compliance-automation')}
                  >
                    <div className="flex items-center space-x-2">
                      <FileText className="h-5 w-5 text-cyan-400" />
                      <div>
                        <p className="text-sm text-gray-400">Compliance</p>
                        <p className="text-lg font-bold text-cyan-400">Setup</p>
                      </div>
                    </div>
                  </div>
                  <div 
                    className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 cursor-pointer hover:bg-slate-700/50 transition-colors"
                    onClick={() => setActiveTab("alerts")}
                  >
                    <div className="flex items-center space-x-2">
                      <Shield className="h-5 w-5 text-orange-400" />
                      <div>
                        <p className="text-sm text-gray-400">Alert System</p>
                        <p className="text-lg font-bold text-orange-400">Configure</p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="automation" className="space-y-6">
              <div className="bg-gradient-to-r from-blue-600/20 to-purple-600/20 border border-blue-500/30 rounded-lg p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-xl font-bold text-white mb-2">Automated Compliance Engine</h2>
                    <p className="text-gray-300">AI-powered infrastructure discovery, vulnerability scanning, and automated remediation</p>
                  </div>
                  <div className="flex space-x-2">
                    <Button
                      onClick={() => navigate('/automation')}
                      className="bg-gradient-to-r from-blue-500 to-purple-500 hover:from-blue-600 hover:to-purple-600"
                    >
                      <Bot className="h-4 w-4 mr-2" />
                      Launch Automation Engine
                    </Button>
                  </div>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="billing" className="space-y-6">
              <div className="bg-gradient-to-r from-blue-600/20 to-purple-600/20 border border-blue-500/30 rounded-lg p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-xl font-bold text-white mb-2">Subscription & Billing</h2>
                    <p className="text-gray-300">Manage your subscription, billing, and access to premium features</p>
                  </div>
                  <div className="flex space-x-2">
                    <Button
                      onClick={() => navigate('/billing')}
                      className="bg-gradient-to-r from-blue-500 to-purple-500 hover:from-blue-600 hover:to-purple-600"
                    >
                      <CreditCard className="h-4 w-4 mr-2" />
                      Manage Billing
                    </Button>
                  </div>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="legal" className="space-y-6">
              <div className="bg-gradient-to-r from-blue-600/20 to-purple-600/20 border border-blue-500/30 rounded-lg p-6">
                <div className="text-center">
                  <h2 className="text-xl font-bold text-white mb-2">Legal Documents</h2>
                  <p className="text-gray-300">Legal document management has been removed.</p>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="dod" className="space-y-6">
              <div className="bg-gradient-to-r from-orange-600/20 to-red-600/20 border border-orange-500/30 rounded-lg p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-xl font-bold text-white mb-2">Department of Defense Operations</h2>
                    <p className="text-gray-300">Deployment orchestration and security platform management</p>
                  </div>
                  <div className="flex space-x-2">
                    <Button
                      onClick={() => navigate('/dod')}
                      className="bg-gradient-to-r from-orange-500 to-red-500 hover:from-orange-600 hover:to-red-600"
                    >
                      <Shield className="h-4 w-4 mr-2" />
                      Launch DOD Dashboard
                    </Button>
                    <Button
                      onClick={() => navigate('/infrastructure')}
                      variant="outline"
                      className="border-orange-500/30 text-orange-400 hover:bg-orange-500/20"
                    >
                      <Network className="h-4 w-4 mr-2" />
                      Infrastructure
                    </Button>
                  </div>
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <div 
                  className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 cursor-pointer hover:bg-slate-700/50 transition-colors"
                  onClick={() => navigate('/dod')}
                >
                  <div className="flex items-center space-x-2">
                    <Shield className="h-5 w-5 text-orange-400" />
                    <div>
                      <p className="text-sm text-gray-400">Deployment</p>
                      <p className="text-lg font-bold text-orange-400">Ready</p>
                    </div>
                  </div>
                </div>
                <div 
                  className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 cursor-pointer hover:bg-slate-700/50 transition-colors"
                  onClick={() => navigate('/infrastructure')}
                >
                  <div className="flex items-center space-x-2">
                    <Network className="h-5 w-5 text-cyan-400" />
                    <div>
                      <p className="text-sm text-gray-400">Infrastructure</p>
                      <p className="text-lg font-bold text-cyan-400">Monitor</p>
                    </div>
                  </div>
                </div>
                <div 
                  className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 cursor-pointer hover:bg-slate-700/50 transition-colors"
                  onClick={() => navigate('/security')}
                >
                  <div className="flex items-center space-x-2">
                    <Lock className="h-5 w-5 text-purple-400" />
                    <div>
                      <p className="text-sm text-gray-400">Security</p>
                      <p className="text-lg font-bold text-purple-400">Active</p>
                    </div>
                  </div>
                </div>
                <div 
                  className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 cursor-pointer hover:bg-slate-700/50 transition-colors"
                  onClick={() => navigate('/compliance-automation')}
                >
                  <div className="flex items-center space-x-2">
                    <Scale className="h-5 w-5 text-green-400" />
                    <div>
                      <p className="text-sm text-gray-400">Compliance</p>
                      <p className="text-lg font-bold text-green-400">Monitor</p>
                    </div>
                  </div>
                </div>
              </div>
            </TabsContent>

            {profile?.master_admin && (
              <TabsContent value="master-admin" className="space-y-6">
                <div className="bg-gradient-to-r from-purple-600/20 to-blue-600/20 border border-purple-500/30 rounded-lg p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <h2 className="text-xl font-bold text-white mb-2">Master Admin Portal</h2>
                      <p className="text-gray-300">Access the full Master Admin console with unrestricted platform access</p>
                    </div>
                    <div className="flex space-x-2">
                      <Button
                        onClick={() => navigate('/admin')}
                        className="bg-gradient-to-r from-purple-500 to-blue-500 hover:from-purple-600 hover:to-blue-600"
                      >
                        <Crown className="h-4 w-4 mr-2" />
                        Open Master Admin Console
                      </Button>
                    </div>
                  </div>
                </div>
              </TabsContent>
            )}

            {(profile?.role === 'admin' && !profile?.master_admin) && (
              <TabsContent value="admin" className="space-y-6">
                <UnifiedAdminConsole />
              </TabsContent>
            )}

            <TabsContent value="stig-codex" className="space-y-6">
              <STIGCodexCenter />
            </TabsContent>

            {canManageUsers() && (
              <>
                <TabsContent value="users">
                  <UserManagement />
                </TabsContent>
                <TabsContent value="audit">
                  <AuditLog />
                </TabsContent>
              </>
            )}
          </Tabs>
        )}
      </div>
    </div>
  );
};

export default Index;
