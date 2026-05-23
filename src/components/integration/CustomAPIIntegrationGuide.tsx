import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Copy, CheckCircle, Code, Globe, Shield, Zap, ExternalLink, Play, AlertCircle } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { BrowserNavigation } from '@/components/ui/browser-navigation';
import { FloatingAIAssistant } from '@/components/FloatingAIAssistant';
import { ContextMenuGuide } from '@/components/ui/context-menu-guide';

const CustomAPIIntegrationGuide = () => {
  const [testEndpoint, setTestEndpoint] = useState('');
  const [testApiKey, setTestApiKey] = useState('');
  const [testResult, setTestResult] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);
  const { toast } = useToast();

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied!",
      description: "Code copied to clipboard",
    });
  };

  const testCustomAPI = async () => {
    setIsLoading(true);
    try {
      // Simulate API test
      await new Promise(resolve => setTimeout(resolve, 2000));
      setTestResult({
        status: 'success',
        data: {
          endpoint: testEndpoint,
          response_time: '234ms',
          data_types: ['security_events', 'user_logs', 'system_metrics'],
          last_updated: new Date().toISOString()
        }
      });
    } catch (error) {
      console.error('API test error:', error);
      setTestResult({ status: 'error', message: 'Connection failed' });
    } finally {
      setIsLoading(false);
    }
  };

  const codeExamples = {
    webhook: `// Static Website Integration - Webhook Endpoint
// Add this to your static site's JavaScript

const IMOHTEP_WEBHOOK_URL = 'https://xjknkjbrjgljuovaazeu.supabase.co/functions/v1/integration-manager';

// Function to send security events to IMOHTEP
async function sendSecurityEvent(eventData) {
  try {
    const response = await fetch(IMOHTEP_WEBHOOK_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer YOUR_API_KEY'
      },
      body: JSON.stringify({
        action: 'sync',
        integration_type: 'custom_website',
        config: {
          endpoint_url: globalThis.location.origin,
          site_name: 'Your Website Name'
        },
        data: {
          event_type: eventData.type,
          timestamp: new Date().toISOString(),
          user_id: eventData.userId,
          ip_address: eventData.ip,
          user_agent: navigator.userAgent,
          page_url: globalThis.location.href,
          details: eventData.details
        }
      })
    });

    if (response.ok) {
      console.log('Security event sent to IMOHTEP successfully');
    }
  } catch (error) {
    console.error('Failed to send security event:', error);
  }
}

// Example usage - Track login attempts
document.getElementById('loginForm').addEventListener('submit', async (e) => {
  const formData = new FormData(e.target);
  
  await sendSecurityEvent({
    type: 'authentication_attempt',
    userId: formData.get('email'),
    ip: await fetch('https://api.ipify.org?format=json').then(r => r.json()).then(d => d.ip),
    details: {
      success: false, // Update based on actual result
      method: 'password',
      timestamp: Date.now()
    }
  });
});`,

    monitoring: `// Client-Side Security Monitoring
const IMOHTEP_WEBHOOK_URL = 'https://xjknkjbrjgljuovaazeu.supabase.co/functions/v1/integration-manager';

class IMOHTEPSecurityMonitor {
  constructor(apiKey, siteId) {
    this.apiKey = apiKey;
    this.siteId = siteId;
    this.init();
  }

  init() {
    // Monitor failed login attempts
    this.monitorFailedLogins();
    
    // Track suspicious activity
    this.monitorSuspiciousActivity();
    
    // Monitor form submissions
    this.monitorFormSubmissions();
  }

  async sendEvent(eventType, data) {
    try {
      await fetch(IMOHTEP_WEBHOOK_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': \`Bearer \${this.apiKey}\`
        },
        body: JSON.stringify({
          action: 'sync',
          integration_type: 'static_website_monitor',
          config: { site_id: this.siteId },
          data: {
            event_type: eventType,
            timestamp: new Date().toISOString(),
            site_url: globalThis.location.origin,
            page_url: globalThis.location.href,
            user_agent: navigator.userAgent,
            ...data
          }
        })
      });
    } catch (error) {
      console.error('IMOHTEP monitoring error:', error);
    }
  }

  monitorFailedLogins() {
    // Detect multiple failed login attempts
    let failedAttempts = 0;
    const maxAttempts = 3;
    
    document.addEventListener('submit', (e) => {
      if (e.target.matches('form[data-login-form]')) {
        e.target.addEventListener('ajax:error', () => {
          failedAttempts++;
          if (failedAttempts >= maxAttempts) {
            this.sendEvent('multiple_failed_logins', {
              attempts: failedAttempts,
              threshold_exceeded: true,
              risk_level: 'high'
            });
          }
        });
      }
    });
  }

  monitorSuspiciousActivity() {
    // Monitor rapid page visits
    let pageViews = [];
    
    globalThis.addEventListener('beforeunload', () => {
      pageViews.push({
        url: globalThis.location.href,
        timestamp: Date.now(),
        duration: Date.now() - globalThis.performance.timing.navigationStart
      });
      
      // If more than 10 pages in 30 seconds
      const recentViews = pageViews.filter(view => 
        Date.now() - view.timestamp < 30000
      );
      
      if (recentViews.length > 10) {
        this.sendEvent('rapid_page_browsing', {
          page_count: recentViews.length,
          time_window: '30s',
          risk_level: 'medium'
        });
      }
    });
  }

  monitorFormSubmissions() {
    document.addEventListener('submit', (e) => {
      const form = e.target;
      this.sendEvent('form_submission', {
        form_id: form.id,
        form_action: form.action,
        field_count: form.elements.length,
        has_file_upload: [...form.elements].some(el => el.type === 'file')
      });
    });
  }
}

// Initialize monitoring
const monitor = new IMOHTEPSecurityMonitor('YOUR_API_KEY', 'your-site-id');`,

    api: `// REST API Integration for Static Sites
class IMOHTEPAPIClient {
  constructor(apiKey, baseUrl = 'https://bqxmmonqibpmnxgypevd.supabase.co') {
    this.apiKey = apiKey;
    this.baseUrl = baseUrl;
  }

  async makeRequest(endpoint, data, method = 'POST') {
    try {
      const response = await fetch(\`\${this.baseUrl}/functions/v1/\${endpoint}\`, {
        method,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': \`Bearer \${this.apiKey}\`
        },
        body: JSON.stringify(data)
      });

      if (!response.ok) {
        throw new Error(\`HTTP error! status: \${response.status}\`);
      }

      return await response.json();
    } catch (error) {
      console.error('IMOHTEP API Error:', error);
      throw error;
    }
  }

  // Send security event
  async sendSecurityEvent(eventData) {
    return this.makeRequest('integration-manager', {
      action: 'sync',
      integration_type: 'custom_api',
      config: {
        endpoint_url: globalThis.location.origin,
        integration_name: 'Static Website Security Feed'
      },
      data: eventData
    });
  }

  // Test connection
  async testConnection() {
    return this.makeRequest('integration-manager', {
      action: 'test',
      integration_type: 'custom_api',
      config: {
        endpoint_url: globalThis.location.origin
      }
    });
  }

  // Bulk send events
  async sendBulkEvents(events) {
    return this.makeRequest('integration-manager', {
      action: 'sync',
      integration_type: 'bulk_events',
      config: {
        endpoint_url: globalThis.location.origin,
        batch_size: events.length
      },
      data: { events }
    });
  }
}

// Usage example
const imohtep = new IMOHTEPAPIClient('YOUR_API_KEY');

// Send single event
await imohtep.sendSecurityEvent({
  event_type: 'user_login',
  user_id: 'user@example.com',
  ip_address: '192.168.1.1',
  success: true,
  timestamp: new Date().toISOString()
});

// Test connection
const connectionTest = await imohtep.testConnection();
console.log('Connection status:', connectionTest);`
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Browser Navigation */}
      <BrowserNavigation
        tabs={[
          { id: 'overview', title: 'Integration Overview', path: '#', isActive: true },
          { id: 'webhook', title: 'Webhook Setup', path: '#' },
          { id: 'monitoring', title: 'Security Monitoring', path: '#' },
          { id: 'api', title: 'API Client', path: '#' },
          { id: 'testing', title: 'Testing & Validation', path: '#' }
        ]}
        title="Custom API Integration Guide"
        subtitle="Learn how to integrate your static website or custom API with IMOHTEP's security platform"
        showAddTab={false}
      />

      <div className="max-w-7xl mx-auto p-6 space-y-6">
        <div className="text-center space-y-6">
          <h1 className="text-3xl font-bold bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
            Custom API Integration Guide
          </h1>
          <p className="text-muted-foreground max-w-2xl mx-auto">
            Learn how to integrate your static website or custom API with IMOHTEP's security platform.
            This comprehensive guide covers everything from basic webhooks to advanced monitoring.
          </p>

          {/* New Integration Hub Callout */}
          <Alert className="max-w-4xl mx-auto bg-gradient-to-r from-primary/10 to-accent/10 border-primary/20">
            <Zap className="h-4 w-4" />
            <AlertDescription className="text-left">
              <div className="flex items-center justify-between">
                <div>
                  <strong>New Integration Hub Available!</strong>
                  <p className="text-sm mt-1">Access our comprehensive Integration Hub with 150+ pre-built connectors, health monitoring, and analytics dashboard.</p>
                </div>
                <Button
                  variant="outline"
                  className="ml-4 border-primary/50 text-primary hover:bg-primary/10"
                  onClick={() => globalThis.open('/integration-guide', '_blank')}
                >
                  <ExternalLink className="h-4 w-4 mr-2" />
                  Open Integration Hub
                </Button>
              </div>
            </AlertDescription>
          </Alert>

          {/* Quick Setup Options */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 max-w-4xl mx-auto">
            <Card className="bg-gradient-to-br from-blue-500/10 to-cyan-500/10 border-blue-500/20">
              <CardContent className="p-4 text-center">
                <div className="w-12 h-12 mx-auto mb-3 bg-blue-500/20 rounded-lg flex items-center justify-center">
                  <Zap className="h-6 w-6 text-blue-400" />
                </div>
                <h3 className="font-semibold text-blue-400">Quick Setup</h3>
                <p className="text-sm text-muted-foreground mt-1">Popular tools like Splunk, CrowdStrike, Microsoft Sentinel</p>
              </CardContent>
            </Card>

            <Card className="bg-gradient-to-br from-green-500/10 to-emerald-500/10 border-green-500/20">
              <CardContent className="p-4 text-center">
                <div className="w-12 h-12 mx-auto mb-3 bg-green-500/20 rounded-lg flex items-center justify-center">
                  <Shield className="h-6 w-6 text-green-400" />
                </div>
                <h3 className="font-semibold text-green-400">Health Monitoring</h3>
                <p className="text-sm text-muted-foreground mt-1">Real-time status and performance tracking</p>
              </CardContent>
            </Card>

            <Card className="bg-gradient-to-br from-purple-500/10 to-violet-500/10 border-purple-500/20">
              <CardContent className="p-4 text-center">
                <div className="w-12 h-12 mx-auto mb-3 bg-purple-500/20 rounded-lg flex items-center justify-center">
                  <Globe className="h-6 w-6 text-purple-400" />
                </div>
                <h3 className="font-semibold text-purple-400">Custom APIs</h3>
                <p className="text-sm text-muted-foreground mt-1">Build custom integrations with our flexible API</p>
              </CardContent>
            </Card>
          </div>
        </div>

        <Tabs defaultValue="overview" className="w-full">
          <TabsList className="grid w-full grid-cols-5 bg-card border border-border">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="webhook">Webhook Setup</TabsTrigger>
            <TabsTrigger value="monitoring">Monitoring</TabsTrigger>
            <TabsTrigger value="api">API Client</TabsTrigger>
            <TabsTrigger value="testing">Testing</TabsTrigger>
          </TabsList>

          <TabsContent value="overview">
            <ContextMenuGuide
              feature="Integration Overview Guide"
              description="Get started with API integration fundamentals"
              menuItems={[
                {
                  label: "Static Website Integration",
                  description: "Learn about client-side JavaScript integration",
                  action: () => console.log("Static Website guide"),
                  icon: <Globe className="w-3 h-3" />,
                  type: "guide" as const
                },
                {
                  label: "Security Events",
                  description: "Understanding monitored security events",
                  action: () => console.log("Security Events guide"),
                  icon: <Shield className="w-3 h-3" />,
                  type: "guide" as const
                },
                {
                  label: "Integration Flow",
                  description: "Step-by-step implementation process",
                  action: () => console.log("Integration Flow guide"),
                  icon: <Zap className="w-3 h-3" />,
                  type: "action" as const
                }
              ]}
            >
              <div className="grid gap-6 md:grid-cols-2">
                <Card className="card-cyber">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Globe className="w-5 h-5" />
                      Static Website Integration
                    </CardTitle>
                    <CardDescription>
                      Perfect for portfolios, landing pages, and client websites
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="flex items-center gap-2">
                      <CheckCircle className="w-4 h-4 text-success" />
                      <span className="text-sm">No server required</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <CheckCircle className="w-4 h-4 text-success" />
                      <span className="text-sm">Client-side JavaScript only</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <CheckCircle className="w-4 h-4 text-success" />
                      <span className="text-sm">Real-time security monitoring</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <CheckCircle className="w-4 h-4 text-success" />
                      <span className="text-sm">Easy to implement</span>
                    </div>
                  </CardContent>
                </Card>

                <Card className="card-cyber">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Shield className="w-5 h-5" />
                      Security Events Tracked
                    </CardTitle>
                    <CardDescription>
                      Comprehensive monitoring capabilities
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <Badge variant="secondary">Login Attempts</Badge>
                    <Badge variant="secondary">Form Submissions</Badge>
                    <Badge variant="secondary">Page Navigation</Badge>
                    <Badge variant="secondary">Failed Auth</Badge>
                    <Badge variant="secondary">Suspicious Activity</Badge>
                    <Badge variant="secondary">User Sessions</Badge>
                    <Badge variant="secondary">Error Events</Badge>
                    <Badge variant="secondary">Custom Events</Badge>
                  </CardContent>
                </Card>

                <Card className="md:col-span-2 card-cyber">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Zap className="w-5 h-5" />
                      Enhanced Integration Flow
                    </CardTitle>
                    <CardDescription>
                      New comprehensive integration workflow with health monitoring and analytics
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    <div className="flex items-center gap-4 text-sm">
                      <div className="flex items-center gap-2">
                        <div className="w-6 h-6 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-xs">1</div>
                        <span>Choose integration type</span>
                      </div>
                      <div className="flex-1 h-px bg-border"></div>
                      <div className="flex items-center gap-2">
                        <div className="w-6 h-6 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-xs">2</div>
                        <span>Configure via Hub UI</span>
                      </div>
                      <div className="flex-1 h-px bg-border"></div>
                      <div className="flex items-center gap-2">
                        <div className="w-6 h-6 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-xs">3</div>
                        <span>Test & validate</span>
                      </div>
                      <div className="flex-1 h-px bg-border"></div>
                      <div className="flex items-center gap-2">
                        <div className="w-6 h-6 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-xs">4</div>
                        <span>Monitor health & analytics</span>
                      </div>
                    </div>

                    {/* New Features Highlight */}
                    <div className="grid grid-cols-2 gap-4 pt-4 border-t border-border">
                      <div className="space-y-2">
                        <h4 className="font-medium text-sm flex items-center gap-2">
                          <CheckCircle className="w-4 h-4 text-success" />
                          New Hub Features
                        </h4>
                        <ul className="text-xs text-muted-foreground space-y-1">
                          <li>• 150+ pre-built connectors</li>
                          <li>• Health monitoring dashboard</li>
                          <li>• Integration marketplace</li>
                          <li>• Industry-specific solutions</li>
                        </ul>
                      </div>
                      <div className="space-y-2">
                        <h4 className="font-medium text-sm flex items-center gap-2">
                          <Shield className="w-4 h-4 text-blue-400" />
                          Enhanced Security
                        </h4>
                        <ul className="text-xs text-muted-foreground space-y-1">
                          <li>• Real-time status tracking</li>
                          <li>• Failed integration alerts</li>
                          <li>• Performance analytics</li>
                          <li>• Compliance recommendations</li>
                        </ul>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </ContextMenuGuide>
          </TabsContent>

          <TabsContent value="webhook">
            <ContextMenuGuide
              feature="Webhook Integration Setup"
              description="Configure webhooks to send security events from your website"
              menuItems={[
                {
                  label: "Copy Code",
                  description: "Copy the webhook integration code",
                  action: () => copyToClipboard(codeExamples.webhook),
                  icon: <Copy className="w-3 h-3" />,
                  type: "action" as const
                },
                {
                  label: "Configure Events",
                  description: "Set up authentication and form monitoring",
                  action: () => console.log("Configure Events guide"),
                  icon: <Shield className="w-3 h-3" />,
                  type: "guide" as const
                },
                {
                  label: "Test Webhook",
                  description: "Test your webhook implementation",
                  action: () => console.log("Test Webhook guide"),
                  icon: <Play className="w-3 h-3" />,
                  type: "action" as const
                }
              ]}
            >
              <Card className="card-cyber">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Code className="w-5 h-5" />
                    Webhook Integration Setup
                  </CardTitle>
                  <CardDescription>
                    Send security events from your static website to IMOHTEP using webhooks
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <Alert>
                    <AlertCircle className="h-4 w-4" />
                    <AlertDescription>
                      <strong>Step 1:</strong> Add this JavaScript code to your static website. Replace YOUR_API_KEY with your actual API key.
                    </AlertDescription>
                  </Alert>

                  <div className="relative">
                    <pre className="bg-muted p-4 rounded-lg text-sm overflow-x-auto">
                      <code>{codeExamples.webhook}</code>
                    </pre>
                    <Button
                      size="sm"
                      variant="outline"
                      className="absolute top-2 right-2 hover:bg-accent"
                      onClick={() => copyToClipboard(codeExamples.webhook)}
                    >
                      <Copy className="w-4 h-4" />
                    </Button>
                  </div>

                  <Separator />

                  <div className="space-y-4">
                    <h4 className="font-semibold">Common Use Cases:</h4>
                    <div className="grid gap-4 md:grid-cols-2">
                      <div className="space-y-2">
                        <h5 className="font-medium text-sm">🔐 Authentication Events</h5>
                        <p className="text-xs text-muted-foreground">Track login attempts, password resets, and account lockouts</p>
                      </div>
                      <div className="space-y-2">
                        <h5 className="font-medium text-sm">📝 Form Submissions</h5>
                        <p className="text-xs text-muted-foreground">Monitor contact forms, newsletter signups, and user registrations</p>
                      </div>
                      <div className="space-y-2">
                        <h5 className="font-medium text-sm">🚨 Error Events</h5>
                        <p className="text-xs text-muted-foreground">Capture JavaScript errors and failed API calls</p>
                      </div>
                      <div className="space-y-2">
                        <h5 className="font-medium text-sm">👤 User Behavior</h5>
                        <p className="text-xs text-muted-foreground">Track page views, session duration, and suspicious activity</p>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </ContextMenuGuide>
          </TabsContent>

          <TabsContent value="monitoring">
            <ContextMenuGuide
              feature="Advanced Security Monitoring"
              description="Implement comprehensive client-side security monitoring"
              menuItems={[
                {
                  label: "Failed Login Detection",
                  description: "Set up automatic failed login monitoring",
                  action: () => console.log("Failed Login guide"),
                  icon: <AlertCircle className="w-3 h-3" />,
                  type: "guide" as const
                },
                {
                  label: "Behavior Analysis",
                  description: "Monitor suspicious user behavior patterns",
                  action: () => console.log("Behavior Analysis guide"),
                  icon: <Shield className="w-3 h-3" />,
                  type: "guide" as const
                },
                {
                  label: "Form Monitoring",
                  description: "Track and analyze form submissions",
                  action: () => console.log("Form Monitoring guide"),
                  icon: <Code className="w-3 h-3" />,
                  type: "action" as const
                }
              ]}
            >
              <Card className="card-cyber">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Shield className="w-5 h-5" />
                    Advanced Security Monitoring
                  </CardTitle>
                  <CardDescription>
                    Implement comprehensive client-side security monitoring
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <Alert>
                    <AlertCircle className="h-4 w-4" />
                    <AlertDescription>
                      <strong>Step 2:</strong> Add this monitoring class to detect and report security events automatically.
                    </AlertDescription>
                  </Alert>

                  <div className="relative">
                    <pre className="bg-muted p-4 rounded-lg text-sm overflow-x-auto max-h-96">
                      <code>{codeExamples.monitoring}</code>
                    </pre>
                    <Button
                      size="sm"
                      variant="outline"
                      className="absolute top-2 right-2 hover:bg-accent"
                      onClick={() => copyToClipboard(codeExamples.monitoring)}
                    >
                      <Copy className="w-4 h-4" />
                    </Button>
                  </div>

                  <div className="grid gap-4 md:grid-cols-3">
                    <div className="p-4 border rounded-lg">
                      <h4 className="font-semibold text-sm mb-2">Failed Login Detection</h4>
                      <p className="text-xs text-muted-foreground">Automatically detects and reports multiple failed login attempts</p>
                    </div>
                    <div className="p-4 border rounded-lg">
                      <h4 className="font-semibold text-sm mb-2">Suspicious Behavior</h4>
                      <p className="text-xs text-muted-foreground">Monitors rapid page browsing and unusual navigation patterns</p>
                    </div>
                    <div className="p-4 border rounded-lg">
                      <h4 className="font-semibold text-sm mb-2">Form Monitoring</h4>
                      <p className="text-xs text-muted-foreground">Tracks all form submissions including file uploads</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </ContextMenuGuide>
          </TabsContent>

          <TabsContent value="api">
            <ContextMenuGuide
              feature="API Client Implementation"
              description="Full-featured API client for advanced integrations"
              menuItems={[
                {
                  label: "Single Events",
                  description: "Send individual security events",
                  action: () => console.log("Single Events guide"),
                  icon: <Zap className="w-3 h-3" />,
                  type: "action" as const
                },
                {
                  label: "Bulk Processing",
                  description: "Process multiple events efficiently",
                  action: () => console.log("Bulk Processing guide"),
                  icon: <Code className="w-3 h-3" />,
                  type: "guide" as const
                },
                {
                  label: "Error Handling",
                  description: "Implement robust error handling",
                  action: () => console.log("Error Handling guide"),
                  icon: <AlertCircle className="w-3 h-3" />,
                  type: "guide" as const
                }
              ]}
            >
              <Card className="card-cyber">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Code className="w-5 h-5" />
                    API Client Implementation
                  </CardTitle>
                  <CardDescription>
                    Full-featured API client for advanced integrations
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <Alert>
                    <AlertCircle className="h-4 w-4" />
                    <AlertDescription>
                      <strong>Step 3:</strong> Use this API client class for more complex integrations and bulk operations.
                    </AlertDescription>
                  </Alert>

                  <div className="relative">
                    <pre className="bg-muted p-4 rounded-lg text-sm overflow-x-auto max-h-96">
                      <code>{codeExamples.api}</code>
                    </pre>
                    <Button
                      size="sm"
                      variant="outline"
                      className="absolute top-2 right-2 hover:bg-accent"
                      onClick={() => copyToClipboard(codeExamples.api)}
                    >
                      <Copy className="w-4 h-4" />
                    </Button>
                  </div>

                  <div className="space-y-4">
                    <h4 className="font-semibold">API Features:</h4>
                    <div className="grid gap-2 md:grid-cols-2">
                      <div className="flex items-center gap-2">
                        <CheckCircle className="w-4 h-4 text-success" />
                        <span className="text-sm">Single event sending</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <CheckCircle className="w-4 h-4 text-success" />
                        <span className="text-sm">Bulk event processing</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <CheckCircle className="w-4 h-4 text-success" />
                        <span className="text-sm">Connection testing</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <CheckCircle className="w-4 h-4 text-success" />
                        <span className="text-sm">Error handling</span>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </ContextMenuGuide>
          </TabsContent>

          <TabsContent value="testing">
            <ContextMenuGuide
              feature="Test Your Integration"
              description="Verify your API connection and test data flow"
              menuItems={[
                {
                  label: "Connection Test",
                  description: "Test your API connection and credentials",
                  action: () => console.log("Connection Test guide"),
                  icon: <Play className="w-3 h-3" />,
                  type: "action" as const
                },
                {
                  label: "Integration Steps",
                  description: "Follow the next steps checklist",
                  action: () => console.log("Integration Steps guide"),
                  icon: <CheckCircle className="w-3 h-3" />,
                  type: "guide" as const
                },
                {
                  label: "Documentation",
                  description: "Access detailed API documentation",
                  action: () => globalThis.open('#', '_blank'),
                  icon: <ExternalLink className="w-3 h-3" />,
                  type: "link" as const
                }
              ]}
            >
              <Card className="card-cyber">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Play className="w-5 h-5" />
                    Test Your Integration
                  </CardTitle>
                  <CardDescription>
                    Verify your API connection and test data flow
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2">
                      <Label htmlFor="test-endpoint">Your Website URL</Label>
                      <Input
                        id="test-endpoint"
                        placeholder="https://yoursite.com"
                        value={testEndpoint}
                        onChange={(e) => setTestEndpoint(e.target.value)}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="test-api-key">API Key</Label>
                      <Input
                        id="test-api-key"
                        type="password"
                        placeholder="Enter your API key"
                        value={testApiKey}
                        onChange={(e) => setTestApiKey(e.target.value)}
                      />
                    </div>
                  </div>

                  <Button
                    onClick={testCustomAPI}
                    disabled={!testEndpoint || !testApiKey || isLoading}
                    className="w-full hover:bg-primary/90 transition-colors"
                    variant="cyber"
                  >
                    {isLoading ? 'Testing Connection...' : 'Test API Integration'}
                  </Button>

                  {testResult && (
                    <Alert className={testResult.status === 'success' ? 'border-success bg-success/10' : 'border-destructive bg-destructive/10'}>
                      <CheckCircle className="h-4 w-4" />
                      <AlertDescription>
                        {testResult.status === 'success' ? (
                          <div className="space-y-2">
                            <p className="font-semibold">✅ Connection Successful!</p>
                            <p className="text-sm">Response time: {testResult.data.response_time}</p>
                            <p className="text-sm">Data types: {testResult.data.data_types.join(', ')}</p>
                          </div>
                        ) : (
                          <p className="font-semibold">❌ Connection Failed: {testResult.message}</p>
                        )}
                      </AlertDescription>
                    </Alert>
                  )}

                  <Separator />

                  <div className="space-y-4">
                    <h4 className="font-semibold">Next Steps:</h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex items-center gap-2">
                        <div className="w-4 h-4 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-xs">1</div>
                        <span>Copy the integration code to your website</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <div className="w-4 h-4 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-xs">2</div>
                        <span>Replace YOUR_API_KEY with your actual key</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <div className="w-4 h-4 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-xs">3</div>
                        <span>Test the integration on your live site</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <div className="w-4 h-4 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-xs">4</div>
                        <span>Monitor events in your IMOHTEP dashboard</span>
                      </div>
                    </div>
                  </div>

                  <Alert>
                    <AlertCircle className="h-4 w-4" />
                    <AlertDescription>
                      <strong>Need help?</strong> Contact our support team or check the{' '}
                      <Button variant="link" className="p-0 h-auto">
                        <ExternalLink className="w-3 h-3 mr-1" />
                        API documentation
                      </Button>
                      {' '}for more details.
                    </AlertDescription>
                  </Alert>
                </CardContent>
              </Card>
            </ContextMenuGuide>
          </TabsContent>
        </Tabs>
      </div>

      {/* Floating AI Assistant */}
      <FloatingAIAssistant position="bottom-right" />
    </div>
  );
};

export default CustomAPIIntegrationGuide;