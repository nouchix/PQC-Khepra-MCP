
import { ProductionReadinessDashboard } from '@/components/admin/ProductionReadinessDashboard';
import { SecurityAuditDashboard } from '@/components/admin/SecurityAuditDashboard';
import { PerformanceTestingDashboard } from '@/components/admin/PerformanceTestingDashboard';
import { ComplianceValidationDashboard } from '@/components/admin/ComplianceValidationDashboard';
import { IntegrationTestingDashboard } from '@/components/admin/IntegrationTestingDashboard';
import { DataProtectionAuditDashboard } from '@/components/admin/DataProtectionAuditDashboard';
import { BusinessLogicAuditDashboard } from '@/components/admin/BusinessLogicAuditDashboard';
import { CustomerJourneyAuditDashboard } from '@/components/admin/CustomerJourneyAuditDashboard';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Shield, CheckCircle, Zap, FileCheck, Plug, Database, Brain, Users } from 'lucide-react';

const ProductionAudit = () => {
  return (
    <div className="min-h-screen bg-background">
      <div className="container mx-auto py-6">
        <div className="mb-6">
          <h1 className="text-4xl font-bold tracking-tight">Production Readiness Audit Suite</h1>
          <p className="text-muted-foreground">
            Comprehensive audit covering security, performance, compliance, integrations, data protection, business logic, and customer journey
          </p>
        </div>
        
        <Tabs defaultValue="overview" className="space-y-6">
          <TabsList className="grid w-full grid-cols-4 lg:grid-cols-8">
            <TabsTrigger value="overview" className="flex items-center gap-2">
              <CheckCircle className="h-4 w-4" />
              Overview
            </TabsTrigger>
            <TabsTrigger value="security" className="flex items-center gap-2">
              <Shield className="h-4 w-4" />
              Security
            </TabsTrigger>
            <TabsTrigger value="performance" className="flex items-center gap-2">
              <Zap className="h-4 w-4" />
              Performance
            </TabsTrigger>
            <TabsTrigger value="compliance" className="flex items-center gap-2">
              <FileCheck className="h-4 w-4" />
              Compliance
            </TabsTrigger>
            <TabsTrigger value="integration" className="flex items-center gap-2">
              <Plug className="h-4 w-4" />
              Integration
            </TabsTrigger>
            <TabsTrigger value="data" className="flex items-center gap-2">
              <Database className="h-4 w-4" />
              Data Protection
            </TabsTrigger>
            <TabsTrigger value="business" className="flex items-center gap-2">
              <Brain className="h-4 w-4" />
              Business Logic
            </TabsTrigger>
            <TabsTrigger value="journey" className="flex items-center gap-2">
              <Users className="h-4 w-4" />
              Customer Journey
            </TabsTrigger>
          </TabsList>

          <TabsContent value="overview">
            <ProductionReadinessDashboard />
          </TabsContent>

          <TabsContent value="security">
            <SecurityAuditDashboard />
          </TabsContent>

          <TabsContent value="performance">
            <PerformanceTestingDashboard />
          </TabsContent>

          <TabsContent value="compliance">
            <ComplianceValidationDashboard />
          </TabsContent>

          <TabsContent value="integration">
            <IntegrationTestingDashboard />
          </TabsContent>

          <TabsContent value="data">
            <DataProtectionAuditDashboard />
          </TabsContent>

          <TabsContent value="business">
            <BusinessLogicAuditDashboard />
          </TabsContent>

          <TabsContent value="journey">
            <CustomerJourneyAuditDashboard />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default ProductionAudit;