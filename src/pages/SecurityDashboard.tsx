import { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { 
  Shield, 
  Lock, 
  Activity, 
  FileText, 
  AlertTriangle,
  CheckCircle2,
  TrendingUp,
  Users,
  Eye,
  ShieldCheck,
  Settings,
  BookOpen,
  Search,
  Target,
  Plus
} from 'lucide-react';
import EnhancedMFAManager from '@/components/security/EnhancedMFAManager';
import SessionSecurityManager from '@/components/security/SessionSecurityManager';
import SecurityEventsDashboard from '@/components/security/SecurityEventsDashboard';
import { ComplianceFrameworkManager } from '@/components/compliance/ComplianceFrameworkManager';
import { ComplianceControlsMatrix } from '@/components/compliance/ComplianceControlsMatrix';
import { ComplianceAuditReport } from '@/components/compliance/ComplianceAuditReport';
import { FeatureGateEnhanced } from '@/components/FeatureGateEnhanced';
import { UsageTracker } from '@/components/UsageTracker';
import { ZeroTrustDashboard } from '@/components/security/ZeroTrustDashboard';
import { FloatingAIAssistant } from '@/components/FloatingAIAssistant';
import { ContextMenuGuide } from '@/components/ui/context-menu-guide';
import { BrowserNavigation } from '@/components/ui/browser-navigation';
import { AutomatedThreatHunting } from '@/components/AutomatedThreatHunting';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';
import { useOrganization } from '@/hooks/useOrganization';

export const SecurityDashboard = () => {
  const [activeTab, setActiveTab] = useState('overview');
  const { user } = useAuth();
  const { currentOrganization } = useOrganization();

  // Real security metrics
  const [securityMetrics, setSecurityMetrics] = useState({
    mfaEnabled: 0,
    activeSessions: 0,
    securityEvents: 0,
    complianceScore: 0,
    criticalAlerts: 0,
    resolvedIncidents: 0
  });
  const [metricsLoading, setMetricsLoading] = useState(true);

  // Load real security metrics
  useEffect(() => {
    if (currentOrganization) {
      loadSecurityMetrics();
    }
  }, [currentOrganization]);

  const loadSecurityMetrics = async () => {
    if (!currentOrganization) return;

    setMetricsLoading(true);
    try {
      // Load security events
      const { data: eventsData, count: eventsCount } = await supabase
        .from('security_events')
        .select('*', { count: 'exact' })
        .eq('resolved', false)
        .order('created_at', { ascending: false });

      // Load critical alerts
      const { count: criticalCount } = await supabase
        .from('security_events')
        .select('*', { count: 'exact', head: true })
        .eq('severity', 'critical')
        .eq('resolved', false);

      // Load resolved incidents from last 30 days
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
      const { count: resolvedCount } = await supabase
        .from('security_events')
        .select('*', { count: 'exact', head: true })
        .eq('resolved', true)
        .gte('created_at', thirtyDaysAgo);

      // Load MFA enabled users (if profiles table has this data)
      const { data: profilesData } = await supabase
        .from('profiles')
        .select('mfa_enabled')
        .not('mfa_enabled', 'is', null);

      const mfaEnabledCount = profilesData?.filter(p => p.mfa_enabled).length || 0;
      const totalUsers = profilesData?.length || 1;
      const mfaPercentage = Math.round((mfaEnabledCount / totalUsers) * 100);

      // Calculate compliance score based on security posture
      const complianceScore = Math.min(100, Math.max(60, 
        100 - (criticalCount || 0) * 10 - (eventsCount || 0) * 2 + mfaPercentage * 0.3
      ));

      // Count active sessions (profiles with recent activity in last 24 hours)
      const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      const { count: activeSessionCount } = await supabase
        .from('profiles')
        .select('*', { count: 'exact', head: true })
        .gte('last_sign_in_at', oneDayAgo);

      setSecurityMetrics({
        mfaEnabled: mfaPercentage,
        activeSessions: activeSessionCount || 0,
        securityEvents: eventsCount || 0,
        complianceScore: Math.round(complianceScore),
        criticalAlerts: criticalCount || 0,
        resolvedIncidents: resolvedCount || 0
      });

    } catch (error) {
      console.error('Error loading security metrics:', error);
    } finally {
      setMetricsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Browser-like Navigation */}
      <BrowserNavigation
        tabs={[
          { id: 'overview', title: 'Security Overview', path: '', isActive: activeTab === 'overview' },
          { id: 'hunting', title: 'Automated Hunting', path: '', hasNotification: false },
          { id: 'zero-trust', title: 'Zero Trust', path: '', hasNotification: securityMetrics.criticalAlerts > 0, notificationCount: securityMetrics.criticalAlerts },
          { id: 'mfa', title: 'MFA Management', path: '' },
          { id: 'sessions', title: 'Session Monitor', path: '', hasNotification: securityMetrics.activeSessions > 10 },
          { id: 'events', title: 'Security Events', path: '', hasNotification: securityMetrics.securityEvents > 0, notificationCount: securityMetrics.securityEvents },
          { id: 'compliance', title: 'Compliance', path: '' },
          { id: 'reports', title: 'Audit Reports', path: '' }
        ]}
        onTabChange={setActiveTab}
        title="Security & Compliance Dashboard"
        subtitle={`CMMC Level 3 & NIST Cybersecurity Framework • ${securityMetrics.complianceScore}% Compliant`}
      />
      
      <div className="container mx-auto p-6 space-y-6">
      <UsageTracker pageName="security-dashboard" />
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-2">
          <Badge variant="default" className="flex items-center space-x-1">
            <Shield className="h-3 w-3" />
            <span>CMMC L3</span>
          </Badge>
          <Badge variant="outline" className="flex items-center space-x-1">
            <CheckCircle2 className="h-3 w-3" />
            <span>NIST Compatible</span>
          </Badge>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid w-full grid-cols-8">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="hunting" className="flex items-center space-x-2">
            <Target className="h-4 w-4" />
            <span>Auto Hunt</span>
          </TabsTrigger>
          <TabsTrigger value="zero-trust">Zero Trust</TabsTrigger>
          <TabsTrigger value="mfa">MFA</TabsTrigger>
          <TabsTrigger value="sessions">Sessions</TabsTrigger>
          <TabsTrigger value="events">Events</TabsTrigger>
          <TabsTrigger value="compliance">Compliance</TabsTrigger>
          <TabsTrigger value="reports">Reports</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-6">
          {metricsLoading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {[...new Array(6)].map((_, i) => (
                <Card key={i} className="card-cyber">
                  <CardContent className="p-6">
                    <div className="animate-pulse">
                      <div className="h-4 bg-muted rounded w-1/2 mb-4"></div>
                      <div className="h-8 bg-muted rounded w-1/3 mb-2"></div>
                      <div className="h-3 bg-muted rounded w-3/4"></div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {/* MFA Status */}
            <ContextMenuGuide
              feature="MFA Adoption"
              description="Monitor and manage Multi-Factor Authentication across your organization"
              menuItems={[
                {
                  label: "Configure MFA Settings",
                  description: "Set up organization-wide MFA policies",
                  action: () => setActiveTab('mfa'),
                  icon: <Settings className="h-3 w-3" />,
                  type: 'action'
                },
                {
                  label: "View MFA Users",
                  description: "See which users have MFA enabled",
                  action: () => setActiveTab('sessions'),
                  icon: <Users className="h-3 w-3" />,
                  type: 'action'
                },
                {
                  label: "MFA Documentation",
                  description: "Learn about MFA best practices",
                  action: () => globalThis.open('/docs/mfa', '_blank'),
                  icon: <BookOpen className="h-3 w-3" />,
                  type: 'link'
                }
              ]}
              className="relative"
            >
              <Card className="card-cyber hover:shadow-lg transition-all duration-300 cursor-pointer">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">MFA Adoption</CardTitle>
                  <Lock className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{securityMetrics.mfaEnabled}%</div>
                  <p className="text-xs text-muted-foreground">
                    Users with MFA enabled
                  </p>
                  <div className="mt-2">
                    <Badge variant={securityMetrics.mfaEnabled >= 80 ? "default" : "destructive"}>
                      {securityMetrics.mfaEnabled >= 80 ? "Compliant" : "Action Required"}
                    </Badge>
                  </div>
                </CardContent>
              </Card>
            </ContextMenuGuide>

            {/* Active Sessions */}
            <ContextMenuGuide
              feature="Active Sessions"
              description="Monitor and manage user sessions across your platform"
              menuItems={[
                {
                  label: "Session Management",
                  description: "View and manage all active sessions",
                  action: () => setActiveTab('sessions'),
                  icon: <Eye className="h-3 w-3" />,
                  type: 'action'
                },
                {
                  label: "Terminate Sessions",
                  description: "Force logout suspicious sessions",
                  action: () => setActiveTab('sessions'),
                  icon: <AlertTriangle className="h-3 w-3" />,
                  type: 'action'
                },
                {
                  label: "Session Policies",
                  description: "Configure session timeout settings",
                  action: () => globalThis.open('/docs/sessions', '_blank'),
                  icon: <Settings className="h-3 w-3" />,
                  type: 'link'
                }
              ]}
              className="relative"
            >
              <Card className="card-cyber hover:shadow-lg transition-all duration-300 cursor-pointer">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Active Sessions</CardTitle>
                  <Users className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{securityMetrics.activeSessions}</div>
                  <p className="text-xs text-muted-foreground">
                    Currently active user sessions
                  </p>
                  <div className="mt-2">
                    <Badge variant="outline">Monitored</Badge>
                  </div>
                </CardContent>
              </Card>
            </ContextMenuGuide>

            {/* Security Events */}
            <Card className="card-cyber">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Security Events</CardTitle>
                <Activity className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{securityMetrics.securityEvents}</div>
                <p className="text-xs text-muted-foreground">
                  Unresolved security events
                </p>
                <div className="mt-2">
                  <Badge variant={securityMetrics.securityEvents <= 5 ? "default" : "destructive"}>
                    {securityMetrics.securityEvents <= 5 ? "Normal" : "Review Required"}
                  </Badge>
                </div>
              </CardContent>
            </Card>

            {/* Compliance Score */}
            <Card className="card-cyber">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Compliance Score</CardTitle>
                <TrendingUp className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{securityMetrics.complianceScore}%</div>
                <p className="text-xs text-muted-foreground">
                  CMMC Level 3 compliance
                </p>
                <div className="mt-2">
                  <Badge variant={securityMetrics.complianceScore >= 90 ? "default" : "secondary"}>
                    {securityMetrics.complianceScore >= 90 ? "Excellent" : "Good"}
                  </Badge>
                </div>
              </CardContent>
            </Card>

            {/* Critical Alerts */}
            <Card className="card-cyber">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Critical Alerts</CardTitle>
                <AlertTriangle className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-red-600">{securityMetrics.criticalAlerts}</div>
                <p className="text-xs text-muted-foreground">
                  Require immediate attention
                </p>
                <div className="mt-2">
                  <Badge variant={securityMetrics.criticalAlerts === 0 ? "default" : "destructive"}>
                    {securityMetrics.criticalAlerts === 0 ? "Clear" : "Action Required"}
                  </Badge>
                </div>
              </CardContent>
            </Card>

            {/* Resolved Incidents */}
            <Card className="card-cyber">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Resolved Incidents</CardTitle>
                <CheckCircle2 className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-green-600">{securityMetrics.resolvedIncidents}</div>
                <p className="text-xs text-muted-foreground">
                  This month
                </p>
                <div className="mt-2">
                  <Badge variant="default">Tracked</Badge>
                </div>
              </CardContent>
            </Card>
            </div>
          )}

          {/* Quick Actions */}
          <Card className="card-cyber mt-6">
            <CardHeader>
              <CardTitle>Quick Actions</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div 
                  className="p-4 border rounded-lg cursor-pointer hover:bg-muted/50 transition-colors"
                  onClick={() => setActiveTab('hunting')}
                >
                  <Target className="h-6 w-6 mb-2 text-primary" />
                  <h3 className="font-medium">Automated Threat Hunting</h3>
                  <p className="text-sm text-muted-foreground">IOCs → Splunk queries → Analyst actions</p>
                </div>
                <div 
                  className="p-4 border rounded-lg cursor-pointer hover:bg-muted/50 transition-colors"
                  onClick={() => setActiveTab('compliance')}
                >
                  <FileText className="h-6 w-6 mb-2 text-primary" />
                  <h3 className="font-medium">Run Compliance Audit</h3>
                  <p className="text-sm text-muted-foreground">Generate compliance assessment report</p>
                </div>
                <div 
                  className="p-4 border rounded-lg cursor-pointer hover:bg-muted/50 transition-colors"
                  onClick={() => setActiveTab('zero-trust')}
                >
                  <ShieldCheck className="h-6 w-6 mb-2 text-primary" />
                  <h3 className="font-medium">Zero Trust Security</h3>
                  <p className="text-sm text-muted-foreground">Manage Zero Trust policies and controls</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="hunting" className="mt-6">
          <AutomatedThreatHunting />
        </TabsContent>

        <TabsContent value="zero-trust" className="mt-6">
          <ZeroTrustDashboard />
        </TabsContent>

        <TabsContent value="mfa" className="mt-6">
          <EnhancedMFAManager />
        </TabsContent>

        <TabsContent value="sessions" className="mt-6">
          <SessionSecurityManager />
        </TabsContent>

        <TabsContent value="events" className="mt-6">
          <FeatureGateEnhanced
            featureType="premium"
            featureName="Advanced Security Events"
            description="Real-time threat detection and automated incident response"
            valueProposition="Get instant alerts, AI-powered threat analysis, and automated remediation workflows"
            upgradeMessage="Upgrade to Premium for comprehensive security event management and CMMC compliance tracking"
          >
            <SecurityEventsDashboard />
          </FeatureGateEnhanced>
        </TabsContent>

        <TabsContent value="compliance" className="mt-6">
          <div className="space-y-6">
            {/* Enhanced STIG Compliance Overview */}
            <Card className="card-cyber">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Shield className="h-6 w-6 text-primary" />
                    <div>
                      <CardTitle className="text-xl">Enterprise STIG Implementation Framework</CardTitle>
                      <p className="text-sm text-muted-foreground">
                        200+ STIGs • Continuous Monitoring • Automated Remediation • Audit-Ready Evidence
                      </p>
                    </div>
                  </div>
                  <div className="flex space-x-2">
                    <Badge variant="default" className="bg-green-500/10 text-green-400 border-green-500/20">
                      Production Ready
                    </Badge>
                    <Badge variant="outline">DOD Optimized</Badge>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="text-center p-4 bg-muted/30 rounded-lg">
                    <div className="text-2xl font-bold text-primary">200+</div>
                    <div className="text-sm text-muted-foreground">STIG Baselines</div>
                  </div>
                  <div className="text-center p-4 bg-muted/30 rounded-lg">
                    <div className="text-2xl font-bold text-success">24/7</div>
                    <div className="text-sm text-muted-foreground">Drift Detection</div>
                  </div>
                  <div className="text-center p-4 bg-muted/30 rounded-lg">
                    <div className="text-2xl font-bold text-warning">Auto</div>
                    <div className="text-sm text-muted-foreground">Remediation</div>
                  </div>
                  <div className="text-center p-4 bg-muted/30 rounded-lg">
                    <div className="text-2xl font-bold text-info">7yr</div>
                    <div className="text-sm text-muted-foreground">Evidence Retention</div>
                  </div>
                </div>
                <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div 
                    className="p-4 border rounded-lg hover:bg-muted/20 transition-colors cursor-pointer"
                    onClick={() => globalThis.open('/enterprise/stig-dashboard', '_blank')}
                  >
                    <div className="flex items-center space-x-3">
                      <CheckCircle2 className="h-5 w-5 text-success" />
                      <div>
                        <div className="font-medium text-sm">Continuous STIG Monitoring</div>
                        <div className="text-xs text-muted-foreground">Real-time compliance validation across all assets</div>
                      </div>
                    </div>
                  </div>
                  <div 
                    className="p-4 border rounded-lg hover:bg-muted/20 transition-colors cursor-pointer"
                    onClick={() => globalThis.open('/enterprise/remediation-engine', '_blank')}
                  >
                    <div className="flex items-center space-x-3">
                      <Activity className="h-5 w-5 text-primary" />
                      <div>
                        <div className="font-medium text-sm">Automated Remediation Engine</div>
                        <div className="text-xs text-muted-foreground">Safe automated fixes with rollback capabilities</div>
                      </div>
                    </div>
                  </div>
                  <div 
                    className="p-4 border rounded-lg hover:bg-muted/20 transition-colors cursor-pointer"
                    onClick={() => globalThis.open('/enterprise/evidence-collection', '_blank')}
                  >
                    <div className="flex items-center space-x-3">
                      <FileText className="h-5 w-5 text-info" />
                      <div>
                        <div className="font-medium text-sm">Audit-Ready Evidence</div>
                        <div className="text-xs text-muted-foreground">Comprehensive evidence collection for DOD audits</div>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Enterprise Dashboards Navigation */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card 
                className="card-cyber cursor-pointer hover:shadow-lg transition-all duration-300"
                onClick={() => globalThis.open('/enterprise/stig-dashboard', '_blank')}
              >
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <Shield className="h-5 w-5 text-primary" />
                    <span>Enterprise STIG Dashboard</span>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-muted-foreground mb-4">
                    Comprehensive STIG compliance monitoring with real-time metrics, compliance tracking, and automated remediation management.
                  </p>
                  <div className="flex flex-wrap gap-2">
                    <Badge variant="outline" className="text-xs">Real-time Monitoring</Badge>
                    <Badge variant="outline" className="text-xs">Compliance Metrics</Badge>
                    <Badge variant="outline" className="text-xs">Drift Detection</Badge>
                  </div>
                </CardContent>
              </Card>

              <Card 
                className="card-cyber cursor-pointer hover:shadow-lg transition-all duration-300"
                onClick={() => globalThis.open('/enterprise/cmmc-dashboard', '_blank')}
              >
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <TrendingUp className="h-5 w-5 text-success" />
                    <span>CMMC Integration Dashboard</span>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-muted-foreground mb-4">
                    DOD contractor CMMC compliance integration with STIG mappings, assessment workflows, and certification tracking.
                  </p>
                  <div className="flex flex-wrap gap-2">
                    <Badge variant="outline" className="text-xs">CMMC Levels 1-3</Badge>
                    <Badge variant="outline" className="text-xs">STIG Mappings</Badge>
                    <Badge variant="outline" className="text-xs">Certification Ready</Badge>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Framework Management & Controls Matrix */}
            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Shield className="h-6 w-6 text-blue-400" />
                    <div>
                      <CardTitle className="text-white">Enterprise STIG & Compliance Framework Management</CardTitle>
                      <CardDescription className="text-slate-400">
                        200+ STIGs • CMMC Level 1-3 • NIST 800-53/171 • Continuous Monitoring • Automated Remediation
                      </CardDescription>
                    </div>
                  </div>
                  <div className="flex space-x-2">
                    <Button 
                      variant="outline" 
                      size="sm" 
                      className="border-slate-600"
                      onClick={() => setActiveTab('compliance')}
                    >
                      <Plus className="h-4 w-4 mr-2" />
                      Add Framework
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  <Card 
                    className="bg-slate-700/50 border-slate-600 cursor-pointer hover:bg-slate-600/30 transition-colors"
                    onClick={() => setActiveTab('compliance')}
                  >
                    <CardHeader className="pb-3">
                      <div className="flex items-center space-x-2">
                        <FileText className="h-5 w-5 text-blue-400" />
                        <CardTitle className="text-white text-sm">Frameworks</CardTitle>
                      </div>
                    </CardHeader>
                    <CardContent className="text-xs text-slate-300">
                      Manage compliance frameworks and standards
                    </CardContent>
                  </Card>

                  <Card 
                    className="bg-slate-700/50 border-slate-600 cursor-pointer hover:bg-slate-600/30 transition-colors"
                    onClick={() => setActiveTab('compliance')}
                  >
                    <CardHeader className="pb-3">
                      <div className="flex items-center space-x-2">
                        <Settings className="h-5 w-5 text-green-400" />
                        <CardTitle className="text-white text-sm">Assessments</CardTitle>
                      </div>
                    </CardHeader>
                    <CardContent className="text-xs text-slate-300">
                      Create and manage compliance assessments
                    </CardContent>
                  </Card>

                  <Card 
                    className="bg-slate-700/50 border-slate-600 cursor-pointer hover:bg-slate-600/30 transition-colors"
                    onClick={() => setActiveTab('compliance')}
                  >
                    <CardHeader className="pb-3">
                      <div className="flex items-center space-x-2">
                        <CheckCircle2 className="h-5 w-5 text-purple-400" />
                        <CardTitle className="text-white text-sm">Compliance Assessments</CardTitle>
                      </div>
                    </CardHeader>
                    <CardContent className="text-xs text-slate-300">
                      View and track assessment progress
                    </CardContent>
                  </Card>

                  <Card 
                    className="bg-slate-700/50 border-slate-600 cursor-pointer hover:bg-slate-600/30 transition-colors"
                    onClick={() => setActiveTab('compliance')}
                  >
                    <CardHeader className="pb-3">
                      <div className="flex items-center space-x-2">
                        <Plus className="h-5 w-5 text-orange-400" />
                        <CardTitle className="text-white text-sm">New Assessment</CardTitle>
                      </div>
                    </CardHeader>
                    <CardContent className="text-xs text-slate-300">
                      Start a new compliance assessment
                    </CardContent>
                  </Card>
                </div>
              </CardContent>
            </Card>

            <ComplianceFrameworkManager />
          </div>
        </TabsContent>

        <TabsContent value="reports" className="mt-6">
          <FeatureGateEnhanced
            featureType="premium"
            featureName="Compliance Audit Reports"
            description="Automated CMMC and NIST compliance reporting"
            valueProposition="Generate professional audit reports, track compliance progress, and export certification documentation"
            upgradeMessage="Upgrade to Premium for automated compliance reporting and audit trail management"
          >
            <ComplianceAuditReport />
          </FeatureGateEnhanced>
        </TabsContent>
      </Tabs>
      </div>
      
      {/* AI Assistant for Security Dashboard */}
      <FloatingAIAssistant />
    </div>
  );
};

export default SecurityDashboard;