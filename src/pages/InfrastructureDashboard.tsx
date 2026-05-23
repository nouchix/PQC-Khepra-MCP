import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { DataLakeManager } from '@/components/infrastructure/DataLakeManager';
import { CustomConnectorBuilder } from '@/components/infrastructure/CustomConnectorBuilder';
import { PerformanceMonitor } from '@/components/infrastructure/PerformanceMonitor';
import { InfrastructureDiscovery } from '@/components/InfrastructureDiscovery';
import { PageLayout } from '@/components/PageLayout';
import { 
  Database, Code, Activity, Search, 
  Server, Cloud, Network, Zap
} from 'lucide-react';

export default function InfrastructureDashboard() {
  return (
    <PageLayout>
      <div className="space-y-6">
        <div className="space-y-2">
          <h1 className="text-3xl font-bold text-foreground">Infrastructure Management</h1>
          <p className="text-muted-foreground">
            Complete infrastructure monitoring, data lake management, and custom integration tools
          </p>
        </div>

        <Tabs defaultValue="discovery" className="space-y-6">
          <TabsList className="bg-card border border-border">
            <TabsTrigger value="discovery" className="flex items-center space-x-2">
              <Search className="h-4 w-4" />
              <span>Discovery</span>
            </TabsTrigger>
            <TabsTrigger value="datalake" className="flex items-center space-x-2">
              <Database className="h-4 w-4" />
              <span>Data Lake</span>
            </TabsTrigger>
            <TabsTrigger value="connectors" className="flex items-center space-x-2">
              <Code className="h-4 w-4" />
              <span>Connectors</span>
            </TabsTrigger>
            <TabsTrigger value="performance" className="flex items-center space-x-2">
              <Activity className="h-4 w-4" />
              <span>Performance</span>
            </TabsTrigger>
          </TabsList>

          <TabsContent value="discovery">
            <InfrastructureDiscovery />
          </TabsContent>

          <TabsContent value="datalake">
            <DataLakeManager />
          </TabsContent>

          <TabsContent value="connectors">
            <CustomConnectorBuilder />
          </TabsContent>

          <TabsContent value="performance">
            <PerformanceMonitor />
          </TabsContent>
        </Tabs>
      </div>
    </PageLayout>
  );
}