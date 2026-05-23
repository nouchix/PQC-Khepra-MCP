import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { KhepraScansWidget } from '@/components/khepra/KhepraScansWidget';
import { KhepraLicenseWidget } from '@/components/khepra/KhepraLicenseWidget';
import { KhepraDAGVisualization } from '@/components/khepra/KhepraDAGVisualization';
import { KhepraVPSIntegration } from '@/components/khepra/KhepraVPSIntegration';
import { useKhepraDeployment } from '@/hooks/useKhepraDeployment';
import {
  Network,
  Key,
  Activity,
  BarChart3,
  Shield,
} from 'lucide-react';

export default function ClientPortal() {
  const { config, isLoading, isUpdating, updateConfig } = useKhepraDeployment();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <Shield className="h-12 w-12 animate-pulse mx-auto mb-4 text-primary" />
          <p className="text-muted-foreground font-black italic uppercase tracking-widest text-xs">Synchronizing Portal...</p>
        </div>
      </div>
    );
  }

  if (!config) {
    return (
      <div className="min-h-screen bg-cyber-mesh p-12 flex items-center justify-center">
        <Card className="glass-card max-w-md w-full border-red-500/20">
          <CardHeader>
            <CardTitle className="text-2xl font-black italic text-red-500 uppercase tracking-tight">Deployment Missing</CardTitle>
            <CardDescription className="text-muted-foreground uppercase text-[10px] font-bold tracking-widest">
              No Khepra orchestration endpoint detected
            </CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground bg-white/5 p-4 rounded-xl border border-white/5">
              Protocol execution requires a linked private node. Please contact your administrator to provision an orchestration endpoint.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  // Wrapper for updateConfig to match the component's expectations
  const handleUpdateConfig = async (url: string, key: string) => {
    await updateConfig({ deploymentUrl: url, apiKey: key });
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
            KHEPRA DISCOVERY ACTIVE
          </span>
        </div>
      </div>

      <div className="container mx-auto space-y-8 animate-fade-in">
        {/* Header */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <div className="p-3 bg-gradient-to-br from-blue-600 to-indigo-600 rounded-2xl shadow-lg shadow-blue-500/20">
                <Shield className="h-8 w-8 text-white" />
              </div>
              <div>
                <h1 className="text-4xl font-black tracking-tight text-white italic bg-gradient-to-r from-white to-white/60 bg-clip-text">
                  CLIENT PORTAL
                </h1>
                <p className="text-primary/80 text-xs font-bold uppercase tracking-[0.2em]">
                  Hybrid Security Orchestration & Monitoring
                </p>
              </div>
            </div>
            <p className="text-muted-foreground max-w-2xl leading-relaxed">
              Real-time synchronization with isolated <span className="text-white font-semibold">Khepra VPS</span> nodes.
              Manage PQC licenses and monitor cryptographic audit trails across your private cloud.
            </p>
          </div>

          <KhepraVPSIntegration
            config={config}
            updateConfig={handleUpdateConfig}
            isUpdating={isUpdating}
          />
        </div>

        {/* Main Content */}
        <Tabs defaultValue="overview" className="space-y-4">
          <TabsList className="bg-black/20 border-white/5 p-1 rounded-xl h-12">
            <TabsTrigger value="overview" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary font-black italic uppercase text-[10px] tracking-widest transition-all">
              <Activity className="h-3 w-3 mr-2" />
              Overview
            </TabsTrigger>
            <TabsTrigger value="scans" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary font-black italic uppercase text-[10px] tracking-widest transition-all">
              <Shield className="h-3 w-3 mr-2" />
              Security Scans
            </TabsTrigger>
            <TabsTrigger value="dag" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary font-black italic uppercase text-[10px] tracking-widest transition-all">
              <Network className="h-3 w-3 mr-2" />
              DAG Constellation
            </TabsTrigger>
            <TabsTrigger value="license" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary font-black italic uppercase text-[10px] tracking-widest transition-all">
              <Key className="h-3 w-3 mr-2" />
              License
            </TabsTrigger>
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview" className="space-y-6 pt-4 animate-slide-up">
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
              <KhepraScansWidget
                deploymentUrl={config.deploymentUrl}
                apiKey={config.apiKey}
              />
              <KhepraLicenseWidget
                deploymentUrl={config.deploymentUrl}
                apiKey={config.apiKey}
              />
            </div>
            <KhepraDAGVisualization
              deploymentUrl={config.deploymentUrl}
              apiKey={config.apiKey}
              height={400}
            />
          </TabsContent>

          {/* Scans Tab */}
          <TabsContent value="scans" className="pt-4 animate-slide-up">
            <KhepraScansWidget
              deploymentUrl={config.deploymentUrl}
              apiKey={config.apiKey}
            />
          </TabsContent>

          {/* DAG Tab */}
          <TabsContent value="dag" className="pt-4 animate-slide-up">
            <KhepraDAGVisualization
              deploymentUrl={config.deploymentUrl}
              apiKey={config.apiKey}
              height={600}
            />
          </TabsContent>

          {/* License Tab */}
          <TabsContent value="license" className="pt-4 animate-slide-up">
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
              <KhepraLicenseWidget
                deploymentUrl={config.deploymentUrl}
                apiKey={config.apiKey}
              />
              <Card className="glass-card border-white/5 shadow-2xl">
                <CardHeader className="border-b border-white/5 bg-white/2">
                  <CardTitle className="flex items-center gap-2 text-xl font-black italic">
                    <BarChart3 className="h-5 w-5 text-primary" />
                    USAGE STATISTICS
                  </CardTitle>
                  <CardDescription className="text-muted-foreground uppercase text-[10px] tracking-widest font-bold">
                    License consumption & API telemetry
                  </CardDescription>
                </CardHeader>
                <CardContent className="p-6">
                  <div className="grid grid-cols-2 gap-4 text-center">
                    <div className="bg-white/5 border border-white/5 rounded-xl p-4 transition-all hover:bg-white/10 group">
                      <div className="text-3xl font-black italic text-primary group-hover:scale-110 transition-transform">--</div>
                      <div className="text-[10px] uppercase font-bold tracking-widest text-muted-foreground mt-2">API Calls / 24h</div>
                    </div>
                    <div className="bg-white/5 border border-white/5 rounded-xl p-4 transition-all hover:bg-white/10 group">
                      <div className="text-3xl font-black italic text-primary group-hover:scale-110 transition-transform">--</div>
                      <div className="text-[10px] uppercase font-bold tracking-widest text-muted-foreground mt-2">Scans / Month</div>
                    </div>
                    <div className="bg-white/5 border border-white/5 rounded-xl p-4 transition-all hover:bg-white/10 group">
                      <div className="text-3xl font-black italic text-emerald-400 group-hover:scale-110 transition-transform">--</div>
                      <div className="text-[10px] uppercase font-bold tracking-widest text-muted-foreground mt-2">Remediations</div>
                    </div>
                    <div className="bg-white/5 border border-white/5 rounded-xl p-4 transition-all hover:bg-white/10 group">
                      <div className="text-3xl font-black italic text-red-400 group-hover:scale-110 transition-transform">--</div>
                      <div className="text-[10px] uppercase font-bold tracking-widest text-muted-foreground mt-2">Open Findings</div>
                    </div>
                  </div>
                  <p className="text-[9px] uppercase tracking-tighter text-muted-foreground mt-6 text-center opacity-40">
                    Telemetry data stream initializing... Standby for node sync.
                  </p>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
