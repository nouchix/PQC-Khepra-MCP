
import { PageLayout } from '@/components/PageLayout';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ModernAPIStandards } from '@/components/integration/ModernAPIStandards';
import { EnterpriseAuthManager } from '@/components/integration/EnterpriseAuthManager';
import { ObservabilityDashboard } from '@/components/integration/ObservabilityDashboard';
import { AdvancedIntegrationPatterns } from '@/components/integration/AdvancedIntegrationPatterns';
import { ComplianceSecurityEnhancement } from '@/components/integration/ComplianceSecurityEnhancement';
import { PerformanceScaleOptimization } from '@/components/integration/PerformanceScaleOptimization';

export default function IntegrationEnhancement() {
  return (
    <PageLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Integration Enhancement Platform</h1>
          <p className="text-muted-foreground">Enterprise-grade integration capabilities with modern standards</p>
        </div>

        <Tabs defaultValue="api-standards" className="space-y-4">
          <TabsList className="grid w-full grid-cols-6">
            <TabsTrigger value="api-standards">API Standards</TabsTrigger>
            <TabsTrigger value="auth">Enterprise Auth</TabsTrigger>
            <TabsTrigger value="observability">Observability</TabsTrigger>
            <TabsTrigger value="patterns">Advanced Patterns</TabsTrigger>
            <TabsTrigger value="compliance">Compliance</TabsTrigger>
            <TabsTrigger value="performance">Performance</TabsTrigger>
          </TabsList>

          <TabsContent value="api-standards">
            <ModernAPIStandards />
          </TabsContent>

          <TabsContent value="auth">
            <EnterpriseAuthManager />
          </TabsContent>

          <TabsContent value="observability">
            <ObservabilityDashboard />
          </TabsContent>

          <TabsContent value="patterns">
            <AdvancedIntegrationPatterns />
          </TabsContent>

          <TabsContent value="compliance">
            <ComplianceSecurityEnhancement />
          </TabsContent>

          <TabsContent value="performance">
            <PerformanceScaleOptimization />
          </TabsContent>
        </Tabs>
      </div>
    </PageLayout>
  );
}