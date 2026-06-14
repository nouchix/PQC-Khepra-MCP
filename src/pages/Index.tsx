
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import { useUserProfile } from "@/hooks/useUserProfile";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
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

import { useOrganizationContext } from "@/components/OrganizationProvider";
import { ThreatFeedManager } from "@/components/ThreatFeedManager";
import { AIThreatAnalyzer } from "@/components/AIThreatAnalyzer";
import { AlertDashboard } from "@/components/AlertDashboard";

import FeatureGate from "@/components/FeatureGate";
import { TrialOnboarding } from "@/components/onboarding/TrialOnboarding";
import { UsageTracker, useUsageTracker } from "@/components/UsageTracker";
import { Shield, Brain, Activity, Globe, Network, LogOut, Users, FileText, Home, BarChart3, Lock, Plug, Target, Bell, Bot, Scale, CreditCard, Crown } from "lucide-react";
import { AISecurityAgent } from "@/components/ai/AISecurityAgent";
import { AutonomousComplianceAgent } from "@/components/ai/AutonomousComplianceAgent";
import { AIAgentDeployment } from '@/components/deployment/AIAgentDeployment';
import { EnterpriseSecurityDashboard } from '@/components/EnterpriseSecurityDashboard';

import { SplunkDataFeed } from '@/components/SplunkDataFeed';
import { EmergencyResponseManager } from '@/components/EmergencyResponseManager';
import { IntegrationStatusWidget, IntegrationQuickActions } from '@/components/IntegrationStatusWidget';
import { STIGCodexCenter } from '@/pages/STIGCodexCenter';

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
    <div className="min-h-screen bg-cyber-mesh bg-animate text-white selection:bg-primary/30 selection:text-white">
      {/* Premium Multi-Layer Header */}
      <header className="sticky top-0 z-50 w-full border-b border-white/5 bg-background/60 backdrop-blur-2xl transition-all duration-500">
        <div className="mx-auto flex h-20 max-w-[1600px] items-center justify-between px-8">
          <div className="flex items-center gap-10">
            {/* Branding Core */}
            <div className="flex items-center gap-4 group cursor-pointer" onClick={() => setActiveTab("dashboard")}>
              <div className="relative">
                <div className="absolute inset-0 bg-primary/20 blur-xl rounded-full group-hover:bg-primary/40 transition-all" />
                <img
                  src="/lovable-uploads/94f06ba5-2c93-4be0-a03f-e3fff4157ca6.png"
                  alt="SouHimBou AI"
                  className="relative h-12 w-auto drop-shadow-2xl brightness-110"
                />
              </div>
              <div className="flex flex-col mt-0.5">
                <div className="flex items-center gap-2">
                  <h1 className="text-2xl font-black tracking-tighter text-white uppercase italic">
                    SouHimBou <span className="text-primary tracking-normal not-italic">AI</span>
                  </h1>
                  <Badge variant="outline" className="h-4 border-yellow-500/30 bg-yellow-500/10 text-[9px] font-bold text-yellow-500 tracking-widest uppercase py-0 px-1.5">
                    Ra (Standard)
                  </Badge>
                </div>
                <div className="flex items-center gap-2 mt-0.5">
                  <div className="h-0.5 w-6 bg-gradient-to-r from-primary to-transparent rounded-full" />
                  <span className="text-[9px] font-bold text-muted-foreground whitespace-nowrap uppercase tracking-widest">
                    TRL-10 Autonomous Operations
                  </span>
                </div>
              </div>
            </div>

            {/* Global Node Status */}
            <nav className="hidden xl:flex items-center gap-8 pl-10 border-l border-white/10 h-10">
              {[
                { label: 'Security', icon: Shield, status: 'Active', color: 'text-emerald-400' },
                { label: 'AI Core', icon: Brain, status: 'Synced', color: 'text-purple-400' },
                { label: 'Network', icon: Network, status: 'Ready', color: 'text-cyan-400' }
              ].map((node) => (
                <div key={node.label} className="flex items-center gap-3 cursor-pointer hover:opacity-80 transition-opacity">
                  <div className={`p-1.5 rounded-lg bg-white/5 border border-white/10 ${node.color}`}>
                    <node.icon className="h-4 w-4" />
                  </div>
                  <div className="flex flex-col -gap-1">
                    <span className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold">
                      {node.label}
                    </span>
                    <span className={`text-[11px] font-bold ${node.color}`}>
                      {node.status}
                    </span>
                  </div>
                </div>
              ))}
            </nav>
          </div>

          <div className="flex items-center gap-8">
            {/* Dynamic Clock Section */}
            <div className="hidden lg:flex flex-col items-end pr-8 border-r border-white/10">
              <span className="text-lg font-mono font-black tabular-nums tracking-tighter text-white">
                {currentTime.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
              </span>
              <div className="flex items-center gap-1.5">
                <Globe className="h-3 w-3 text-primary animate-spin-[20s]" />
                <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest">
                  Zulu Sync Active
                </span>
              </div>
            </div>

            {/* Quick Actions */}
            <div className="flex items-center gap-4">
              <Button
                onClick={() => navigate('/dod')}
                className="bg-primary/10 hover:bg-primary/20 text-primary border border-primary/30 h-10 px-6 font-black uppercase tracking-widest text-xs gap-2 shadow-lg shadow-primary/5 transition-all"
              >
                <Shield className="h-4 w-4" />
                DoD Dashboard
              </Button>

              <div className="flex items-center gap-3 pl-4 border-l border-white/10">
                <div className="flex flex-col items-end">
                  <span className="text-xs font-bold text-white max-w-[150px] truncate">{user?.email}</span>
                  <span className="text-[10px] font-bold text-primary uppercase tracking-widest">Master Admin</span>
                </div>
                <Button
                  variant="outline"
                  size="icon"
                  onClick={() => signOut()}
                  className="h-10 w-10 border-white/10 bg-white/5 hover:bg-red-500/20 hover:text-red-500 hover:border-red-500/50 transition-all"
                >
                  <LogOut className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* PoC Status Banner */}
      <div className="bg-emerald-900/30 border-b border-emerald-500/30">
        <div className="container mx-auto px-6 py-3">
          <div className="flex items-center justify-center gap-3 text-sm">
            <Shield className="h-4 w-4 text-emerald-400 flex-shrink-0" />
            <p className="text-emerald-300 text-center">
              <strong>KHEPRA Protocol: Proof of Concept Live</strong> — ASAF Flight Recorder deployed on Raspberry Pi Phantom Node.
              CMMC hard deadline: October 1, 2026 (138 days).
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
                        onClick={() => globalThis.open('/security', '_blank')}
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
