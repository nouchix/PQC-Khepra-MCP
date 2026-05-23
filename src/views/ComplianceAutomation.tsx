import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { InfrastructureDiscovery } from '@/components/InfrastructureDiscovery';
import { VulnerabilityScanner } from '@/components/VulnerabilityScanner';
import { AutomatedRemediation } from '@/components/AutomatedRemediation';
import ProtectedRoute from '@/components/ProtectedRoute';
import { FeatureGateEnhanced } from '@/components/FeatureGateEnhanced';
import { UsageTracker } from '@/components/UsageTracker';
import { BrowserNavigation } from '@/components/ui/browser-navigation';
import { FloatingAIAssistant } from '@/components/FloatingAIAssistant';
import { ContextMenuGuide } from '@/components/ui/context-menu-guide';

export const ComplianceAutomation = () => {
  return (
    <ProtectedRoute>
      <div className="min-h-screen bg-background">
        <UsageTracker pageName="compliance-automation" />
        
        {/* Browser Navigation */}
        <BrowserNavigation
          tabs={[
            { id: 'discovery', title: 'Infrastructure Discovery', path: '#', isActive: true },
            { id: 'scanning', title: 'Vulnerability Scanning', path: '#' },
            { id: 'remediation', title: 'Automated Remediation', path: '#' },
            { id: 'compliance', title: 'Compliance Tracking', path: '#' }
          ]}
          title="Automated Compliance Engine"
          subtitle="AI-powered infrastructure discovery, vulnerability scanning, and automated remediation to achieve CMMC certification in 90 days"
          showAddTab={false}
        />
        
        <div className="max-w-7xl mx-auto p-6 space-y-6">
          <div className="text-center space-y-2">
            <h1 className="text-3xl font-bold bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
              Automated Compliance Engine
            </h1>
            <p className="text-muted-foreground max-w-2xl mx-auto">
              AI-powered infrastructure discovery, vulnerability scanning, and automated remediation 
              to achieve CMMC certification in 90 days
            </p>
          </div>

          <Tabs defaultValue="discovery" className="space-y-6">
            <TabsList className="grid w-full grid-cols-3 bg-card border border-border">
              <TabsTrigger value="discovery" className="flex items-center space-x-2">
                <span>Infrastructure Discovery</span>
              </TabsTrigger>
              <TabsTrigger value="scanning" className="flex items-center space-x-2">
                <span>Vulnerability Scanning</span>
              </TabsTrigger>
              <TabsTrigger value="remediation" className="flex items-center space-x-2">
                <span>Automated Remediation</span>
              </TabsTrigger>
            </TabsList>

            <TabsContent value="discovery">
              <ContextMenuGuide
                feature="Infrastructure Discovery Guide"
                description="Discover and catalog your IT infrastructure automatically"
                menuItems={[
                  { 
                    label: "Start Discovery", 
                    description: "Click 'Start Discovery' to scan your network",
                    action: () => console.log("Start Discovery guide"), 
                    icon: "🔍", 
                    type: "action" as const 
                  },
                  { 
                    label: "Review Assets", 
                    description: "Review discovered assets in the Assets tab",
                    action: () => console.log("Review Assets guide"), 
                    icon: "📊", 
                    type: "guide" as const 
                  },
                  { 
                    label: "Check Networks", 
                    description: "Check network segments for security zones",
                    action: () => console.log("Check Networks guide"), 
                    icon: "🌐", 
                    type: "guide" as const 
                  },
                  { 
                    label: "Configure Settings", 
                    description: "Configure asset settings as needed",
                    action: () => console.log("Configure Settings guide"), 
                    icon: "⚙️", 
                    type: "action" as const 
                  }
                ]}
              >
                <InfrastructureDiscovery />
              </ContextMenuGuide>
            </TabsContent>

            <TabsContent value="scanning">
              <FeatureGateEnhanced
                featureType="premium"
                featureName="Advanced Vulnerability Scanning"
                description="Continuous security scanning with AI-powered risk assessment"
                valueProposition="Automated vulnerability detection, prioritization, and remediation planning for CMMC compliance"
                upgradeMessage="Upgrade to Premium for continuous vulnerability management and compliance tracking"
              >
                <ContextMenuGuide
                  feature="Vulnerability Scanning Guide"
                  description="Scan for security vulnerabilities across your infrastructure"
                  menuItems={[
                    { 
                      label: "Choose Scan Type", 
                      description: "Choose scan type (Quick, Full, or Compliance)",
                      action: () => console.log("Choose Scan Type guide"), 
                      icon: "🎯", 
                      type: "action" as const 
                    },
                    { 
                      label: "Monitor Progress", 
                      description: "Monitor scan progress in real-time",
                      action: () => console.log("Monitor Progress guide"), 
                      icon: "📈", 
                      type: "guide" as const 
                    },
                    { 
                      label: "Review Vulnerabilities", 
                      description: "Review vulnerabilities by severity",
                      action: () => console.log("Review Vulnerabilities guide"), 
                      icon: "🔴", 
                      type: "guide" as const 
                    },
                    { 
                      label: "Auto-Remediation", 
                      description: "Enable auto-remediation for critical issues",
                      action: () => console.log("Auto-Remediation guide"), 
                      icon: "⚡", 
                      type: "action" as const 
                    },
                    { 
                      label: "Export Reports", 
                      description: "Export scan reports for compliance",
                      action: () => console.log("Export Reports guide"), 
                      icon: "📄", 
                      type: "link" as const 
                    }
                  ]}
                >
                  <VulnerabilityScanner />
                </ContextMenuGuide>
              </FeatureGateEnhanced>
            </TabsContent>

            <TabsContent value="remediation">
              <FeatureGateEnhanced
                featureType="enterprise"
                featureName="Automated Remediation Engine"
                description="AI-powered automated security remediation and compliance workflows"
                valueProposition="Automatically fix security issues, apply patches, and maintain CMMC compliance without manual intervention"
                upgradeMessage="Contact our team for Enterprise features including automated remediation and custom compliance workflows"
              >
                <ContextMenuGuide
                  feature="Automated Remediation Guide"
                  description="Automatically fix security issues and maintain compliance"
                  menuItems={[
                    { 
                      label: "Review Tasks", 
                      description: "Review pending remediation tasks",
                      action: () => console.log("Review Tasks guide"), 
                      icon: "📋", 
                      type: "guide" as const 
                    },
                    { 
                      label: "Configure Rules", 
                      description: "Configure automation rules for different scenarios",
                      action: () => console.log("Configure Rules guide"), 
                      icon: "⚙️", 
                      type: "action" as const 
                    },
                    { 
                      label: "Enable Auto-Mode", 
                      description: "Enable auto-mode for approved actions",
                      action: () => console.log("Enable Auto-Mode guide"), 
                      icon: "🤖", 
                      type: "action" as const 
                    },
                    { 
                      label: "Maintenance Windows", 
                      description: "Set maintenance windows for system reboots",
                      action: () => console.log("Maintenance Windows guide"), 
                      icon: "🕒", 
                      type: "guide" as const 
                    },
                    { 
                      label: "Execute Tasks", 
                      description: "Execute tasks individually or in batch",
                      action: () => console.log("Execute Tasks guide"), 
                      icon: "▶️", 
                      type: "action" as const 
                    }
                  ]}
                >
                  <AutomatedRemediation />
                </ContextMenuGuide>
              </FeatureGateEnhanced>
            </TabsContent>
          </Tabs>
        </div>
        
        {/* Floating AI Assistant */}
        <FloatingAIAssistant position="bottom-right" />
      </div>
    </ProtectedRoute>
  );
};