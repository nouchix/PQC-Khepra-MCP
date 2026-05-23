import { useState, useEffect } from 'react';
import { useNavigate } from '@/lib/router-compat';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { useOrganizationContext } from '@/components/OrganizationProvider';
import { 
  Shield, 
  Brain, 
  Activity, 
  TrendingUp, 
  AlertTriangle,
  CheckCircle,
  Clock,
  Zap,
  Users,
  Globe,
  ArrowRight,
  ExternalLink,
  Settings,
  Star,
  Target,
  Play,
  Pause,
  BarChart3,
  Layers,
  Server
} from 'lucide-react';
import { AdinkraSymbolDisplay } from '@/components/khepra/AdinkraSymbolDisplay';
import { PapyrusChecklist } from '@/components/papyrus/PapyrusChecklist';
import { ActivityFeed } from '@/components/ActivityFeed';
import { useContextMenu } from '@/components/ui/context-menu-system';
import { useWorkflowAnalytics } from '@/hooks/useWorkflowAnalytics';
import { ExecutiveModeToggle } from '@/components/ui/executive-mode-toggle';
import { ExecutiveSummaryView } from '@/components/ui/executive-summary-view';
import { CollapsibleSection } from '@/components/ui/collapsible-section';
import { AWSDeploymentStatus } from '@/components/AWSDeploymentStatus';
import { InteractiveTourOverlay } from '@/components/onboarding/InteractiveTourOverlay';

export const ConsoleHome: React.FC = () => {
  const navigate = useNavigate();
  const { currentOrganization } = useOrganizationContext();
  const { showContextMenu, ContextMenuComponent } = useContextMenu();
  const { trackEvent, analytics } = useWorkflowAnalytics();
  const [isExecutiveMode, setIsExecutiveMode] = useState(false);
  const [currentView, setCurrentView] = useState('home');
  const [assetStats, setAssetStats] = useState<any>(null);
  const [isLoadingStats, setIsLoadingStats] = useState(true);
  
  const [metrics, setMetrics] = useState({
    systemHealth: 0, // Real data needed
    activeThreats: 0, // Real data needed  
    blockedAttacks: 0, // Real data needed
    complianceScore: 0 // Real data needed
  });

  // Check URL params for view switching
  useEffect(() => {
    const urlParams = new URLSearchParams(globalThis.location.search);
    const view = urlParams.get('view');
    if (view) {
      setCurrentView(view);
    }
  }, []);


  // Core STIG-focused services
  const coreServices = [
    {
      id: 'stig-compliance',
      title: 'STIG Implementation',
      description: 'Automated STIG rule implementation and validation',
      icon: Shield,
      status: 'Operational',
      path: '/stig-dashboard',
      value: '87%',
      subtitle: 'Implementation Score'
    },
    {
      id: 'asset-scanning', 
      title: 'Asset Scanning',
      description: 'Continuous asset discovery and compliance monitoring',
      icon: Activity,
      status: 'Active',
      path: '/asset-scanning',
      value: '42',
      subtitle: 'Assets Monitored'
    },
    {
      id: 'evidence-collection',
      title: 'Evidence Collection',
      description: 'Automated compliance evidence gathering',
      icon: Target,
      status: 'Active',
      path: '/evidence-collection',
      value: '156',
      subtitle: 'Evidence Items'
    }
  ];

  const quickActions = [
    { 
      title: 'Run STIG Scan', 
      icon: Shield, 
      action: () => {
        trackEvent('button', 'run-stig-scan', { x: 0, y: 0 });
        navigate('/asset-scanning');
      }
    },
    { 
      title: 'View Compliance Report', 
      icon: CheckCircle, 
      action: () => {
        trackEvent('button', 'compliance-report', { x: 0, y: 0 });
        navigate('/compliance-reports');
      }
    },
    { 
      title: 'Collect Evidence', 
      icon: Target, 
      action: () => {
        trackEvent('button', 'collect-evidence', { x: 0, y: 0 });
        navigate('/evidence-collection');
      }
    },
    { 
      title: 'View Billing', 
      icon: AlertTriangle, 
      action: () => {
        trackEvent('button', 'view-billing', { x: 0, y: 0 });
        navigate('/billing');
      }
    }
  ];

  const handleElementClick = (elementType: string, action: string, coordinates: { x: number; y: number }) => {
    trackEvent(elementType, action, coordinates);
  };

  // Show AWS deployment status if view=deployment
  if (currentView === 'deployment') {
    return (
      <div className="p-6">
        <div className="mb-6">
          <Button 
            variant="outline" 
            onClick={() => setCurrentView('home')} 
            className="mb-4"
          >
            ← Back to Console Home
          </Button>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent mb-2">
            AWS Deployment Status
          </h1>
          <p className="text-muted-foreground">
            Monitor and verify your AWS infrastructure deployment
          </p>
        </div>
        <AWSDeploymentStatus />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6"
      onContextMenu={(e) => showContextMenu(e)}
    >
      {/* Welcome Section */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center space-x-3 mb-2">
              <h1 className="text-3xl font-bold bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
                STIG Compliance Dashboard
              </h1>
              <Badge variant="outline" className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30 animate-pulse">
                ⚠️ DEMO MODE - Connect Real Data Sources
              </Badge>
            </div>
            <p className="text-muted-foreground">
              AI-powered CMMC-to-STIG implementation monitoring and automation
            </p>
          </div>
          <div className="hidden md:flex items-center space-x-4">
            <Badge variant="destructive" className="animate-pulse">
              No Real Data Connected
            </Badge>
            <Button variant="outline" size="sm" onClick={() => navigate('/asset-scanning')}>
              <Settings className="h-4 w-4 mr-2" />
              Connect Data Sources
            </Button>
            <Button size="sm" onClick={() => navigate('/evidence-collection')}>
              <ExternalLink className="h-4 w-4 mr-2" />
              Setup Guide
            </Button>
          </div>
        </div>
      </div>

      {/* Executive Mode Toggle */}
      <div data-tour="executive-overview">
        <ExecutiveModeToggle 
          isExecutiveMode={isExecutiveMode}
          onToggle={setIsExecutiveMode}
          className="mb-6"
        />
      </div>

      {/* Conditional Content Based on Executive Mode */}
      {isExecutiveMode ? (
        <ExecutiveSummaryView metrics={metrics} />
      ) : (
        <div className="space-y-8">
        {/* Setup Instructions - Only show when no assets discovered */}
        {!isLoadingStats && (!assetStats?.total_assets || assetStats.total_assets === 0) && (
          <div className="bg-gradient-to-r from-amber-50 to-orange-50 dark:from-amber-950/50 dark:to-orange-950/50 border border-amber-200 dark:border-amber-800 rounded-xl p-6 mb-8">
            <div className="flex items-center space-x-3 mb-4">
              <div className="flex-shrink-0">
                <AlertTriangle className="h-6 w-6 text-amber-600" />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-amber-900 dark:text-amber-100">Setup Required</h3>
                <p className="text-amber-700 dark:text-amber-200">Connect your infrastructure to begin STIG compliance monitoring</p>
              </div>
            </div>

            <div className="space-y-4">
              <div className="flex items-start space-x-3">
                <div className="flex-shrink-0 w-6 h-6 bg-amber-600 text-white rounded-full flex items-center justify-center text-sm font-bold">1</div>
                <div>
                  <h4 className="font-medium text-amber-900 dark:text-amber-100">Connect Infrastructure</h4>
                  <p className="text-sm text-amber-700 dark:text-amber-200">Link your servers, containers, and cloud resources for scanning</p>
                </div>
              </div>

              <div className="flex items-start space-x-3">
                <div className="flex-shrink-0 w-6 h-6 bg-amber-600 text-white rounded-full flex items-center justify-center text-sm font-bold">2</div>
                <div>
                  <h4 className="font-medium text-amber-900 dark:text-amber-100">Configure Scanning</h4>
                  <p className="text-sm text-amber-700 dark:text-amber-200">Set up automated STIG compliance scans and monitoring</p>
                </div>
              </div>

              <div className="flex items-start space-x-3">
                <div className="flex-shrink-0 w-6 h-6 bg-amber-600 text-white rounded-full flex items-center justify-center text-sm font-bold">3</div>
                <div>
                  <h4 className="font-medium text-amber-900 dark:text-amber-100">Review Results</h4>
                  <p className="text-sm text-amber-700 dark:text-amber-200">Analyze compliance reports and remediate findings</p>
                </div>
              </div>
            </div>

            <div className="mt-6">
              <Button 
                className="bg-amber-600 hover:bg-amber-700 text-white"
                onClick={() => globalThis.location.href = '/asset-scanning'}
              >
                <Server className="h-4 w-4 mr-2" />
                Start Infrastructure Discovery
              </Button>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div className="bg-gradient-to-br from-primary/10 to-primary/5 rounded-xl p-6 border border-primary/20">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-medium text-muted-foreground">Total Assets</h3>
              <Server className="h-4 w-4 text-primary" />
            </div>
            <div className="flex items-baseline space-x-2">
              {isLoadingStats ? (
                <div className="w-8 h-8 bg-muted animate-pulse rounded" />
              ) : (
                <>
                  <span className="text-2xl font-bold text-foreground">{assetStats?.total_assets || 0}</span>
                  {!assetStats?.total_assets && (
                    <span className="text-xs text-muted-foreground">(No data)</span>
                  )}
                </>
              )}
            </div>
            <p className="text-xs text-muted-foreground mt-1">Discovered systems</p>
          </div>

          <div className="bg-gradient-to-br from-blue-500/10 to-blue-500/5 rounded-xl p-6 border border-blue-500/20">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-medium text-muted-foreground">STIG Compliance</h3>
              <Shield className="h-4 w-4 text-blue-500" />
            </div>
            <div className="flex items-baseline space-x-2">
              {isLoadingStats ? (
                <div className="w-8 h-8 bg-muted animate-pulse rounded" />
              ) : (
                <>
                  <span className="text-2xl font-bold text-foreground">
                    {assetStats?.compliance_overview?.compliance_percentage || 0}%
                  </span>
                  {!assetStats?.compliance_overview?.compliance_percentage && (
                    <span className="text-xs text-muted-foreground">(No data)</span>
                  )}
                </>
              )}
            </div>
            <p className="text-xs text-muted-foreground mt-1">Overall compliance rate</p>
          </div>

          <div className="bg-gradient-to-br from-yellow-500/10 to-yellow-500/5 rounded-xl p-6 border border-yellow-500/20">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-medium text-muted-foreground">High Risk Assets</h3>
              <AlertTriangle className="h-4 w-4 text-yellow-500" />
            </div>
            <div className="flex items-baseline space-x-2">
              {isLoadingStats ? (
                <div className="w-8 h-8 bg-muted animate-pulse rounded" />
              ) : (
                <>
                  <span className="text-2xl font-bold text-foreground">
                    {(assetStats?.risk_distribution?.high || 0) + (assetStats?.risk_distribution?.critical || 0)}
                  </span>
                  {!assetStats?.risk_distribution?.high && !assetStats?.risk_distribution?.critical && (
                    <span className="text-xs text-muted-foreground">(No data)</span>
                  )}
                </>
              )}
            </div>
            <p className="text-xs text-muted-foreground mt-1">Requiring attention</p>
          </div>

          <div className="bg-gradient-to-br from-red-500/10 to-red-500/5 rounded-xl p-6 border border-red-500/20">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-medium text-muted-foreground">STIG Coverage</h3>
              <Activity className="h-4 w-4 text-red-500" />
            </div>
            <div className="flex items-baseline space-x-2">
              {isLoadingStats ? (
                <div className="w-8 h-8 bg-muted animate-pulse rounded" />
              ) : (
                <>
                  <span className="text-2xl font-bold text-foreground">
                    {assetStats?.compliance_overview?.total_stigs || 0}
                  </span>
                  {!assetStats?.compliance_overview?.total_stigs && (
                    <span className="text-xs text-muted-foreground">(No data)</span>
                  )}
                </>
              )}
            </div>
            <p className="text-xs text-muted-foreground mt-1">Applicable STIGs</p>
          </div>
        </div>

          {/* Core STIG Services */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {coreServices.map((service) => {
              const Icon = service.icon;
              return (
                <Card 
                  key={service.id}
                  className="bg-card/30 backdrop-blur-sm border-border/50 cursor-pointer group hover:bg-card/50 transition-all duration-300"
                  onClick={() => navigate(service.path)}
                >
                  <CardContent className="p-6">
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex items-center space-x-4">
                        <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center">
                          <Icon className="h-6 w-6 text-primary" />
                        </div>
                        <div>
                          <div className="font-semibold mb-1 flex items-center space-x-2">
                            <span>{service.title}</span>
                            <Badge variant="outline" className="text-xs bg-yellow-500/20 text-yellow-400 border-yellow-500/30">
                              DEMO
                            </Badge>
                          </div>
                          <div className="text-sm text-muted-foreground">{service.description}</div>
                        </div>
                      </div>
                      <Badge variant="secondary" className="text-xs">
                        {service.status}
                      </Badge>
                    </div>
                    <div className="flex items-end justify-between">
                      <div>
                        <div className="text-2xl font-bold text-gray-400">No Data</div>
                        <div className="text-xs text-muted-foreground">Connect real data source</div>
                      </div>
                      <ArrowRight className="h-4 w-4 text-muted-foreground group-hover:text-primary group-hover:translate-x-1 transition-all duration-200" />
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>

          {/* System Overview - Clean */}
          <Card className="bg-card/30 backdrop-blur-sm border-border/50">
            <CardHeader className="pb-4">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-lg">STIG Compliance Overview</CardTitle>
                  <div className="text-sm text-muted-foreground">AI-powered CMMC-to-STIG implementation status</div>
                </div>
                <Badge variant="outline" className="text-success border-success/30">
                  Operational
                </Badge>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-3 gap-6">
                <div className="text-center">
                  <div className="text-sm text-muted-foreground mb-2">STIG Rules</div>
                  <div className="text-2xl font-bold text-gray-400">0</div>
                  <div className="text-xs text-muted-foreground">No rules loaded</div>
                </div>
                <div className="text-center">
                  <div className="text-sm text-muted-foreground mb-2">Assets</div>
                  <div className="text-2xl font-bold text-gray-400">0</div>
                  <div className="text-xs text-muted-foreground">No assets discovered</div>
                </div>
                <div className="text-center">
                  <div className="text-sm text-muted-foreground mb-2">Compliance</div>
                  <div className="text-2xl font-bold text-gray-400">0%</div>
                  <div className="text-xs text-muted-foreground">No scan results</div>
                </div>
              </div>
              <div className="mt-6 pt-6 border-t border-border/50">
                <div className="flex justify-between items-center text-sm">
                  <span className="text-muted-foreground">Evidence Items Collected</span>
                  <span className="font-semibold text-gray-400">0</span>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* AI Actions */}
          <div className="flex items-center justify-center space-x-4">
            <Button onClick={() => navigate('/asset-scanning')} className="flex items-center space-x-2">
              <Play className="h-4 w-4" />
              <span>Run Asset Scan</span>
            </Button>
            <Button variant="outline" onClick={() => navigate('/compliance-reports')}>
              <BarChart3 className="h-4 w-4 mr-2" />
              Generate Report
            </Button>
            <Button variant="outline" onClick={() => navigate('/evidence-collection')}>
              <Target className="h-4 w-4 mr-2" />
              Collect Evidence
            </Button>
          </div>
        </div>
      )}
      
      {/* Interactive Tour Overlay */}
      <InteractiveTourOverlay />
      
      {/* Context Menu Component */}
      <ContextMenuComponent />
    </div>
  );
};