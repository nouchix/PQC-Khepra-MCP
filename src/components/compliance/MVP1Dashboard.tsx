
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Shield,
  Search,
  Brain,
  Activity,
  AlertTriangle,
  CheckCircle,
  Database,
  Settings,
  TrendingUp,
  Clock,
  ArrowRight,
  Lock,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useOrganizationContext } from '@/components/OrganizationProvider';
import { useSTIGCompliance } from '@/hooks/useSTIGCompliance';

interface MVP1DashboardProps {
  demoMetrics?: ComplianceMetrics;
  onGatedAction?: () => void;
}

export const MVP1Dashboard = ({ demoMetrics, onGatedAction }: MVP1DashboardProps = {}) => {
  const navigate = useNavigate();
  const isDemoMode = !!demoMetrics;

  const handleAction = (route: string) => {
    if (isDemoMode && onGatedAction) {
      onGatedAction();
    } else {
      navigate(route);
    }
  };

  const mvp1Features = [
    {
      name: 'STIG Configuration Search',
      status: 'live',
      description: 'Search and discover trusted STIG configurations',
      route: '/dod',
      icon: Search,
      color: 'text-green-600',
      bgColor: 'bg-green-50 dark:bg-green-950/20'
    },
    {
      name: 'AI-Powered Verification',
      status: 'live',
      description: 'Verify configurations using AI analysis',
      route: '/dod',
      icon: Brain,
      color: 'text-green-600',
      bgColor: 'bg-green-50 dark:bg-green-950/20'
    },
    {
      name: 'Configuration Baselines',
      status: 'live',
      description: 'Capture and maintain compliance baselines',
      route: '/compliance-reports',
      icon: Database,
      color: 'text-green-600',
      bgColor: 'bg-green-50 dark:bg-green-950/20'
    },
    {
      name: 'Drift Detection',
      status: 'live',
      description: 'Real-time configuration drift monitoring',
      route: '/asset-scanning',
      icon: Activity,
      color: 'text-green-600',
      bgColor: 'bg-green-50 dark:bg-green-950/20'
    }
  ];

  const mvp2Features = [
    {
      name: 'Automated Remediation',
      status: 'q1-2025',
      description: 'Safe, approved configuration fixes with rollback capability',
      icon: Settings,
      color: 'text-amber-600',
      bgColor: 'bg-amber-50 dark:bg-amber-950/20',
      details: [
        'PowerShell & Ansible scripts for Windows/Ubuntu',
        'Approval workflows with rollback',
        'Pre/post validation checks',
        '5-8 high-value remediations in Q1'
      ]
    },
    {
      name: 'MSP Multi-Tenant View',
      status: 'q1-2025',
      description: 'Per-tenant posture, reusable baselines, bulk evidence exports',
      icon: TrendingUp,
      color: 'text-amber-600',
      bgColor: 'bg-amber-50 dark:bg-amber-950/20',
      details: [
        'Per-tenant compliance dashboards',
        'Templated baseline configurations',
        'Bulk evidence package exports',
        'White-label reporting options'
      ]
    },
    {
      name: 'Immutable Evidence Bundles',
      status: 'q2-2025',
      description: 'Cryptographically signed audit-ready compliance packages',
      icon: Shield,
      color: 'text-blue-600',
      bgColor: 'bg-blue-50 dark:bg-blue-950/20',
      details: [
        'Auto-collect commands & configurations',
        'Hash and cryptographic signatures',
        'PDF + CSV POA&M exports',
        'Khepra PQC-ready signing (moat feature)'
      ]
    }
  ];

  const { currentOrganization } = useOrganizationContext();
  const { metrics: liveMetrics, loading } = useSTIGCompliance(
    isDemoMode ? '' : (currentOrganization?.id || '')
  );
  const metrics = demoMetrics ?? liveMetrics;

  const stats = [
    {
      label: 'Compliance Score',
      value: isDemoMode
        ? `${metrics?.overall_compliance_percentage ?? 0}%`
        : (loading ? '...' : `${metrics?.overall_compliance_percentage || 0}%`),
      icon: Shield,
      color: 'text-green-600',
    },
    {
      label: 'Open Findings',
      value: isDemoMode
        ? ((metrics?.critical_findings ?? 0) + (metrics?.high_findings ?? 0) + (metrics?.medium_findings ?? 0)).toString()
        : (loading ? '...' : ((metrics?.critical_findings || 0) + (metrics?.high_findings || 0) + (metrics?.medium_findings || 0)).toString()),
      icon: AlertTriangle,
      color: 'text-red-600',
    },
    {
      label: 'Drift Detection',
      value: 'Active',
      icon: Activity,
      color: 'text-orange-600',
    },
    {
      label: 'AI Verification',
      value: 'Online',
      icon: Brain,
      color: 'text-blue-600',
    },
  ];

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Platform Status</h2>
          <p className="text-muted-foreground mt-1">
            MVP 1.0 Beta - Configuration Management & AI Verification Active
          </p>
        </div>
        <Badge variant="outline" className="bg-green-50 text-green-700 border-green-200 dark:bg-green-950/20 dark:text-green-400">
          Beta Live
        </Badge>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.map((stat) => (
          <Card key={stat.label}>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">{stat.label}</p>
                  <p className="text-2xl font-bold mt-1">{stat.value}</p>
                </div>
                <stat.icon className={`h-8 w-8 ${stat.color} opacity-60`} />
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Feature Roadmap */}
      <Tabs defaultValue="mvp1" className="space-y-4">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="mvp1">MVP 1.0 - Live Now</TabsTrigger>
          <TabsTrigger value="mvp2">MVP 2.0 - Roadmap</TabsTrigger>
        </TabsList>

        <TabsContent value="mvp1" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <CheckCircle className="h-5 w-5 text-green-600" />
                Active Features - Ready for Production Use
              </CardTitle>
              <CardDescription>
                Core STIG configuration management powered by STIGRegistry and STIGEngine services
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {mvp1Features.map((feature) => (
                <div
                  key={feature.name}
                  className="flex items-center justify-between p-4 border rounded-lg hover:bg-accent/50 transition-colors"
                >
                  <div className="flex items-center gap-4">
                    <div className={`p-2 rounded-lg ${feature.bgColor}`}>
                      <feature.icon className={`h-5 w-5 ${feature.color}`} />
                    </div>
                    <div>
                      <h3 className="font-semibold">{feature.name}</h3>
                      <p className="text-sm text-muted-foreground">{feature.description}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <Badge variant="outline" className="bg-green-50 text-green-700 border-green-200 dark:bg-green-950/20 dark:text-green-400">
                      Live
                    </Badge>
                    <Button onClick={() => handleAction(feature.route)} size="sm">
                      {isDemoMode ? <Lock className="mr-2 h-3.5 w-3.5 opacity-60" /> : null}
                      Open <ArrowRight className="ml-2 h-4 w-4" />
                    </Button>
                  </div>
                </div>
              ))}

              <div className="mt-6 p-4 bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-800 rounded-lg">
                <h4 className="font-semibold text-blue-900 dark:text-blue-100 mb-2">
                  Backend Services (Modular & Scalable)
                </h4>
                <ul className="text-sm text-blue-800 dark:text-blue-200 space-y-1">
                  <li>• <code className="font-mono">STIGRegistry</code> - Trusted configuration search & AI verification</li>
                  <li>• <code className="font-mono">STIGEngine</code> - Baseline capture, drift detection, compliance scoring</li>
                  <li>• <code className="font-mono">STIG-Codex TRL10</code> - TypeScript types for enterprise scale</li>
                </ul>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="mvp2" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Clock className="h-5 w-5 text-amber-600" />
                Coming Soon - Full Platform Capabilities
              </CardTitle>
              <CardDescription>
                Advanced remediation, multi-tenant MSP features, and cryptographic evidence bundles
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {mvp2Features.map((feature) => (
                <div
                  key={feature.name}
                  className="border rounded-lg overflow-hidden"
                >
                  <div className="flex items-center justify-between p-4 bg-accent/30">
                    <div className="flex items-center gap-4">
                      <div className={`p-2 rounded-lg ${feature.bgColor}`}>
                        <feature.icon className={`h-5 w-5 ${feature.color}`} />
                      </div>
                      <div>
                        <h3 className="font-semibold">{feature.name}</h3>
                        <p className="text-sm text-muted-foreground">{feature.description}</p>
                      </div>
                    </div>
                    <Badge variant="outline" className="bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/20 dark:text-amber-400">
                      {feature.status.toUpperCase()}
                    </Badge>
                  </div>
                  {feature.details && (
                    <div className="p-4 bg-muted/30">
                      <ul className="text-sm space-y-1 text-muted-foreground">
                        {feature.details.map((detail, idx) => (
                          <li key={idx}>• {detail}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              ))}

              <div className="mt-6 p-6 bg-gradient-to-r from-blue-50 to-purple-50 dark:from-blue-950/20 dark:to-purple-950/20 border border-blue-200 dark:border-blue-800 rounded-lg">
                <div className="flex items-start gap-4">
                  <AlertTriangle className="h-6 w-6 text-blue-600 flex-shrink-0 mt-1" />
                  <div>
                    <h4 className="font-semibold text-blue-900 dark:text-blue-100 mb-2">
                      🎯 Seeking MVP 2.0 Pilot Partners
                    </h4>
                    <p className="text-sm text-blue-800 dark:text-blue-200 mb-4">
                      Join DoD subcontractors and MSPs piloting automated remediation, multi-tenant
                      dashboards, and immutable evidence bundles. Early access with pilot pricing.
                    </p>
                    <div className="flex gap-3">
                      <Button
                        variant="default"
                        className="bg-blue-600 hover:bg-blue-700"
                        onClick={() => navigate('/billing')}
                      >
                        Apply for Pilot Program
                      </Button>
                      <Button
                        variant="outline"
                        onClick={() => navigate('/advisory')}
                      >
                        Book Advisory Call
                      </Button>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Quick Actions */}
      <Card>
        <CardHeader>
          <CardTitle>Quick Start</CardTitle>
          <CardDescription>Jump into key MVP 1.0 capabilities</CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <Button
            variant="outline"
            className="justify-start h-auto py-4 flex-col items-start gap-2"
            onClick={() => handleAction('/dod')}
          >
            <div className="flex items-center gap-2 w-full">
              <Search className="h-5 w-5 text-primary" />
              <div className="font-semibold">Search Registry</div>
              {isDemoMode && <Lock className="h-3.5 w-3.5 ml-auto text-muted-foreground opacity-50" />}
            </div>
            <div className="text-xs text-muted-foreground text-left">
              Browse trusted STIG configurations
            </div>
          </Button>

          <Button
            variant="outline"
            className="justify-start h-auto py-4 flex-col items-start gap-2"
            onClick={() => handleAction('/asset-scanning')}
          >
            <div className="flex items-center gap-2 w-full">
              <Activity className="h-5 w-5 text-primary" />
              <div className="font-semibold">Monitor Drift</div>
              {isDemoMode && <Lock className="h-3.5 w-3.5 ml-auto text-muted-foreground opacity-50" />}
            </div>
            <div className="text-xs text-muted-foreground text-left">
              Real-time configuration tracking
            </div>
          </Button>

          <Button
            variant="outline"
            className="justify-start h-auto py-4 flex-col items-start gap-2"
            onClick={() => handleAction('/compliance-reports')}
          >
            <div className="flex items-center gap-2 w-full">
              <Database className="h-5 w-5 text-primary" />
              <div className="font-semibold">View Baselines</div>
              {isDemoMode && <Lock className="h-3.5 w-3.5 ml-auto text-muted-foreground opacity-50" />}
            </div>
            <div className="text-xs text-muted-foreground text-left">
              Configuration baseline status
            </div>
          </Button>

          <Button
            variant="outline"
            className="justify-start h-auto py-4 flex-col items-start gap-2"
            onClick={() => handleAction('/evidence-collection')}
          >
            <div className="flex items-center gap-2 w-full">
              <Shield className="h-5 w-5 text-primary" />
              <div className="font-semibold">Collect Evidence</div>
              {isDemoMode && <Lock className="h-3.5 w-3.5 ml-auto text-muted-foreground opacity-50" />}
            </div>
            <div className="text-xs text-muted-foreground text-left">
              Build compliance reports
            </div>
          </Button>
        </CardContent>
      </Card>
    </div>
  );
};
