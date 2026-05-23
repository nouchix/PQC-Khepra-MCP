import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Progress } from '@/components/ui/progress';
import { 
  Shield, Zap, Monitor, UserCheck, Cloud, AlertTriangle, Activity, Globe,
  Plus, Settings, TestTube, Trash2, CheckCircle, AlertCircle, Clock, 
  ExternalLink, Filter, Search, Ticket, Award, Info, Brain, Sparkles,
  Network, Eye, Workflow, MessageSquare, TrendingUp
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { useToast } from '@/hooks/use-toast';
import { useIndustryIntegrations, IntegrationLibraryItem } from '@/hooks/useIndustryIntegrations';
import { useAuth } from '@/hooks/useAuth';
import { AdinkraSymbolDisplay } from '@/components/khepra/AdinkraSymbolDisplay';
import { useKhepraAuth } from '@/khepra/hooks/useKhepraAuth';
import { supabase } from '@/integrations/supabase/client';


interface KhepraIntegrationData {
  connectedTools: number;
  activeProtocols: string[];
  culturalAlignment: string;
  trustScore: number;
  aiAgentConnections: number;
}

interface PapyrusWisdomInsight {
  id: string;
  category: string;
  insight: string;
  priority: 'low' | 'medium' | 'high';
  actionable: boolean;
}

export const IndustryIntegrationHub = () => {
  const { 
    library, 
    userIntegrations, 
    tickets, 
    loading, 
    connectIntegration, 
    disconnectIntegration, 
    testConnection 
  } = useIndustryIntegrations();
  
  const { user } = useAuth();
  const { toast } = useToast();
  const { authState } = useKhepraAuth();
  const khepraAuth = authState?.isAuthenticated || false;
  const culturalContext = authState?.culturalContext || null;
  
  const [selectedTemplate, setSelectedTemplate] = useState<IntegrationLibraryItem | null>(null);
  const [configValues, setConfigValues] = useState<Record<string, string>>({});
  const [isConnecting, setIsConnecting] = useState(false);
  const [showConnectDialog, setShowConnectDialog] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [showDoDOnly, setShowDoDOnly] = useState(false);
  const [khepraData, setKhepraData] = useState<KhepraIntegrationData | null>(null);
  const [papyrusInsights, setPapyrusInsights] = useState<PapyrusWisdomInsight[]>([]);
  const [aiAgentActive, setAiAgentActive] = useState(false);
  const [integrationProgress, setIntegrationProgress] = useState(0);

  // Check if user is DoD (based on security clearance or role)
  const isDoDUser = user?.user_metadata?.security_clearance === 'SECRET' || 
                   user?.user_metadata?.security_clearance === 'TOP_SECRET' ||
                   user?.user_metadata?.role === 'dod_user';

  // Load Khepra Protocol integration data
  useEffect(() => {
    const loadKhepraData = async () => {
      try {
        const connectedCount = userIntegrations.length;
        const protocols = userIntegrations.map(int => int.integration_library?.category || 'Unknown');
        const uniqueProtocols = [...new Set(protocols)];
        
        setKhepraData({
          connectedTools: connectedCount,
          activeProtocols: uniqueProtocols,
          culturalAlignment: culturalContext || 'Sankofa - Learning from the past',
          trustScore: Math.min(95, 70 + (connectedCount * 5)),
          aiAgentConnections: Math.floor(connectedCount * 0.6)
        });
        
        // Calculate integration progress
        const maxIntegrations = 10; // Target for complete setup
        setIntegrationProgress(Math.min(100, (connectedCount / maxIntegrations) * 100));
      } catch (error) {
        console.error('Failed to load Khepra data:', error);
      }
    };

    const loadPapyrusInsights = async () => {
      try {
        // Generate AI-powered insights based on integration status
        const insights: PapyrusWisdomInsight[] = [];
        
        if (userIntegrations.length === 0) {
          insights.push({
            id: 'first-integration',
            category: 'Getting Started',
            insight: 'Begin your security journey by connecting your first SIEM tool. This establishes the foundation for comprehensive threat monitoring.',
            priority: 'high',
            actionable: true
          });
        }
        
        if (userIntegrations.length > 0 && userIntegrations.length < 3) {
          insights.push({
            id: 'expand-coverage',
            category: 'Security Coverage',
            insight: 'Consider adding endpoint protection and identity management tools to create a more complete security ecosystem.',
            priority: 'medium',
            actionable: true
          });
        }
        
        if (userIntegrations.some(int => int.status === 'error')) {
          insights.push({
            id: 'fix-errors',
            category: 'Health Monitoring',
            insight: 'Some integrations are experiencing issues. Address these to maintain optimal security posture.',
            priority: 'high',
            actionable: true
          });
        }
        
        setPapyrusInsights(insights);
      } catch (error) {
        console.error('Failed to load Papyrus insights:', error);
      }
    };

    if (userIntegrations.length >= 0) {
      loadKhepraData();
      loadPapyrusInsights();
    }
  }, [userIntegrations, culturalContext]);

    // Simulate AI agent activity
  useEffect(() => {
    const interval = setInterval(() => {
      setAiAgentActive(prev => !prev);
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  // Handle voice assistant integration requests
  const handleVoiceIntegrationRequest = async (request: string) => {
    console.log('Voice integration request:', request);
    
    // Parse the request and trigger appropriate actions
    const lowerRequest = request.toLowerCase();
    
    if (lowerRequest.includes('siem') || lowerRequest.includes('splunk')) {
      setCategoryFilter('SIEM');
      setSearchTerm('splunk');
    } else if (lowerRequest.includes('crowdstrike') || lowerRequest.includes('endpoint')) {
      setCategoryFilter('ENDPOINT');
      setSearchTerm('crowdstrike');
    } else if (lowerRequest.includes('test all')) {
      // Test all integrations
      for (const integration of userIntegrations) {
        try {
          await testConnection(integration.id);
        } catch (error) {
          console.error('Failed to test integration:', integration.name, error);
        }
      }
      toast({
        title: "Integration Testing",
        description: `Testing ${userIntegrations.length} integrations...`
      });
    }
    
    // Log the voice interaction
    try {
      await supabase.functions.invoke('grok-ai-agent', {
        body: {
          action: 'voice_integration_request',
          request: request,
          context: {
            user_id: user?.id,
            integration_count: userIntegrations.length,
            cultural_context: culturalContext
          }
        }
      });
    } catch (error) {
      console.error('Failed to log voice interaction:', error);
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'SIEM': return <Shield className="h-5 w-5" />;
      case 'FIREWALL': return <Zap className="h-5 w-5" />;
      case 'ENDPOINT': return <Monitor className="h-5 w-5" />;
      case 'IDENTITY': return <UserCheck className="h-5 w-5" />;
      case 'CLOUD': return <Cloud className="h-5 w-5" />;
      case 'VULNERABILITY': return <AlertTriangle className="h-5 w-5" />;
      case 'NETWORK': return <Activity className="h-5 w-5" />;
      case 'COMPLIANCE': return <Award className="h-5 w-5" />;
      default: return <Globe className="h-5 w-5" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'connected': return 'bg-success text-success-foreground';
      case 'disconnected': return 'bg-muted text-muted-foreground';
      case 'error': return 'bg-destructive text-destructive-foreground';
      case 'pending': return 'bg-warning text-warning-foreground';
      case 'secure_ticket_required': return 'bg-blue-500 text-white';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'connected': return <CheckCircle className="h-4 w-4" />;
      case 'disconnected': return <AlertCircle className="h-4 w-4" />;
      case 'error': return <AlertCircle className="h-4 w-4" />;
      case 'pending': return <Clock className="h-4 w-4" />;
      case 'secure_ticket_required': return <Ticket className="h-4 w-4" />;
      default: return <AlertCircle className="h-4 w-4" />;
    }
  };

  const filteredLibrary = library.filter(item => {
    const matchesSearch = item.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         item.provider.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         item.description.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesCategory = categoryFilter === 'all' || item.category === categoryFilter;
    const matchesDoDFilter = !showDoDOnly || item.is_dod_approved;
    
    return matchesSearch && matchesCategory && matchesDoDFilter;
  });

  const popularItems = filteredLibrary.filter(item => item.is_popular);
  const connectedIntegrations = userIntegrations.filter(int => int.status === 'connected');

  const handleConnect = async () => {
    if (!selectedTemplate) return;

    setIsConnecting(true);
    try {
      await connectIntegration(selectedTemplate, configValues, isDoDUser);
      
      if (isDoDUser || selectedTemplate.is_dod_approved) {
        toast({
          title: "Secure Ticket Submitted",
          description: `Your request for ${selectedTemplate.name} has been submitted for approval.`,
        });
      } else {
        toast({
          title: "Integration Added",
          description: `${selectedTemplate.name} is being configured...`,
        });
      }
      
      setShowConnectDialog(false);
      setSelectedTemplate(null);
      setConfigValues({});
    } catch (error: any) {
      toast({
        title: "Connection Failed",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setIsConnecting(false);
    }
  };

  const handleDisconnect = async (integrationId: string, name: string) => {
    try {
      await disconnectIntegration(integrationId);
    } catch (error: any) {
      toast({
        title: "Disconnection Failed",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const handleTest = async (integrationId: string, name: string) => {
    try {
      const result = await testConnection(integrationId);
      toast({
        title: result.success ? "Test Successful" : "Test Failed",
        description: result.success ? `${name} is responding correctly` : result.error,
        variant: result.success ? "default" : "destructive"
      });
    } catch (error: any) {
      toast({
        title: "Test Failed",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="text-foreground">Loading Industry Standard Integration Hub...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Enhanced Header with Khepra Integration */}
      <div className="relative">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <div>
              <h1 className="text-3xl font-bold bg-gradient-to-r from-primary to-primary/60 bg-clip-text text-transparent">
                Industry Standard Integration Hub (ISIH)
              </h1>
              <p className="text-muted-foreground">
                Connect to industry-leading security tools and platforms • Enhanced by KHEPRA Protocol
              </p>
            </div>
            {khepraAuth && (
              <div className="w-8 h-8 bg-primary/20 rounded-lg flex items-center justify-center">
                <Sparkles className="h-4 w-4 text-primary" />
              </div>
            )}
          </div>
          <div className="flex items-center space-x-3">
            {isDoDUser && (
              <Badge variant="outline" className="bg-blue-500/10 text-blue-400 border-blue-500/20">
                <Ticket className="h-3 w-3 mr-1" />
                DoD Secure Mode
              </Badge>
            )}
            {aiAgentActive && (
              <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/20 animate-pulse">
                <Brain className="h-3 w-3 mr-1" />
                AI Agent Active
              </Badge>
            )}
          </div>
        </div>
        
        {/* Integration Progress Bar */}
        {integrationProgress > 0 && (
          <div className="mt-4 space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Integration Progress</span>
              <span className="text-primary font-medium">{Math.round(integrationProgress)}%</span>
            </div>
            <Progress value={integrationProgress} className="h-2" />
          </div>
        )}
      </div>

      {/* Khepra Protocol & AI Integration Status Cards */}
      {khepraData && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <Card className="border-primary/20">
            <CardContent className="p-4">
              <div className="flex items-center space-x-2">
                <Network className="h-5 w-5 text-primary" />
                <div>
                  <p className="text-sm font-medium">Connected Tools</p>
                  <p className="text-2xl font-bold text-primary">{khepraData.connectedTools}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card className="border-amber-500/20">
            <CardContent className="p-4">
              <div className="flex items-center space-x-2">
                <Shield className="h-5 w-5 text-amber-400" />
                <div>
                  <p className="text-sm font-medium">Trust Score</p>
                  <p className="text-2xl font-bold text-amber-400">{khepraData.trustScore}%</p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card className="border-purple-500/20">
            <CardContent className="p-4">
              <div className="flex items-center space-x-2">
                <Brain className="h-5 w-5 text-purple-400" />
                <div>
                  <p className="text-sm font-medium">AI Connections</p>
                  <p className="text-2xl font-bold text-purple-400">{khepraData.aiAgentConnections}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card className="border-green-500/20">
            <CardContent className="p-4">
              <div className="flex items-center space-x-2">
                <Activity className="h-5 w-5 text-green-400" />
                <div>
                  <p className="text-sm font-medium">Active Protocols</p>
                  <p className="text-lg font-bold text-green-400">{khepraData.activeProtocols.length}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Enhanced Integration Grid - Papyrus Wisdom & Voice Assistant */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Integration Content */}
        <div className="lg:col-span-2 space-y-6">
          {/* Papyrus Wisdom Insights */}
          {papyrusInsights.length > 0 && (
            <Card className="border-orange-500/20 bg-gradient-to-r from-orange-500/5 to-amber-500/5">
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Sparkles className="h-5 w-5 text-orange-400" />
                  <span>Papyrus Wisdom • Integration Insights</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {papyrusInsights.map((insight) => (
                    <div key={insight.id} className="flex items-start space-x-3 p-3 rounded-lg bg-card/50">
                      <div className={`w-2 h-2 rounded-full mt-2 ${
                        insight.priority === 'high' ? 'bg-red-400' :
                        insight.priority === 'medium' ? 'bg-yellow-400' : 'bg-green-400'
                      }`} />
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-1">
                          <Badge variant="outline" className="text-xs">{insight.category}</Badge>
                          {insight.actionable && (
                            <Badge variant="outline" className="text-xs bg-blue-500/10 text-blue-400">
                              Actionable
                            </Badge>
                          )}
                        </div>
                        <p className="text-sm text-muted-foreground">{insight.insight}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>

        {/* Autonomous Compliance Operations */}
        <div className="space-y-6">
          <div className="p-6 bg-gradient-to-r from-primary/20 to-secondary/20 rounded-lg border border-primary/30">
            <h3 className="text-lg font-semibold text-primary mb-2">Autonomous AI Operations</h3>
            <p className="text-sm text-muted-foreground">AI agents working 24/7 to ensure CMMC compliance</p>
          </div>
          
          {/* Quick Integration Stats */}
          <Card className="border-slate-700">
            <CardHeader>
              <CardTitle className="text-sm">Quick Actions</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <Button
                variant="outline"
                size="sm"
                className="w-full justify-start"
                onClick={() => setShowConnectDialog(true)}
              >
                <Plus className="h-4 w-4 mr-2" />
                Add Integration
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="w-full justify-start"
                onClick={() => {
                  userIntegrations.forEach(int => testConnection(int.id));
                }}
              >
                <TestTube className="h-4 w-4 mr-2" />
                Test All
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="w-full justify-start"
                onClick={() => setCategoryFilter('all')}
              >
                <Eye className="h-4 w-4 mr-2" />
                View All
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Active Integrations</p>
                <p className="text-2xl font-bold text-success">{connectedIntegrations.length}</p>
              </div>
              <CheckCircle className="h-8 w-8 text-success" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Available Tools</p>
                <p className="text-2xl font-bold text-primary">{library.length}</p>
              </div>
              <Shield className="h-8 w-8 text-primary" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">DoD Approved</p>
                <p className="text-2xl font-bold text-accent">
                  {library.filter(item => item.is_dod_approved).length}
                </p>
              </div>
              <Award className="h-8 w-8 text-accent" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Pending Tickets</p>
                <p className="text-2xl font-bold text-warning">
                  {tickets.filter(t => t.status === 'pending').length}
                </p>
              </div>
              <Ticket className="h-8 w-8 text-warning" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Content */}
      <Tabs defaultValue="catalog" className="space-y-4">
        <div className="flex items-center justify-between">
          <TabsList className="bg-card border border-border">
            <TabsTrigger value="catalog" className="flex items-center space-x-2">
              <Search className="h-4 w-4" />
              <span>Integration Catalog</span>
            </TabsTrigger>
            <TabsTrigger value="active" className="flex items-center space-x-2">
              <CheckCircle className="h-4 w-4" />
              <span>Active Integrations</span>
            </TabsTrigger>
            {isDoDUser && (
              <TabsTrigger value="tickets" className="flex items-center space-x-2">
                <Ticket className="h-4 w-4" />
                <span>Security Tickets</span>
              </TabsTrigger>
            )}
          </TabsList>
          
          <Dialog open={showConnectDialog} onOpenChange={setShowConnectDialog}>
            <DialogTrigger asChild>
              <Button variant="cyber" className="flex items-center space-x-2">
                <Plus className="h-4 w-4" />
                <span>Connect Integration</span>
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-2xl card-cyber">
              <DialogHeader>
                <DialogTitle>Connect New Integration</DialogTitle>
                <DialogDescription>
                  {isDoDUser 
                    ? "Submit a secure request to connect your security tool"
                    : "Connect IMOHTEP with your existing security infrastructure"
                  }
                </DialogDescription>
              </DialogHeader>
              
              {!selectedTemplate ? (
                <div className="space-y-4">
                  <h3 className="font-semibold text-foreground">Popular Integrations</h3>
                  <div className="grid grid-cols-2 gap-3 max-h-80 overflow-y-auto">
                    {popularItems.map((template) => (
                      <div
                        key={template.id}
                        className="p-4 border border-border rounded-lg cursor-pointer hover:bg-accent/50 transition-colors"
                        onClick={() => setSelectedTemplate(template)}
                      >
                        <div className="flex items-center space-x-3">
                          {getCategoryIcon(template.category)}
                          <div className="flex-1">
                            <p className="font-medium text-foreground">{template.name}</p>
                            <p className="text-sm text-muted-foreground">{template.provider}</p>
                            {template.is_dod_approved && (
                              <Badge variant="outline" className="text-xs mt-1">DoD Approved</Badge>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="flex items-center space-x-3">
                    {getCategoryIcon(selectedTemplate.category)}
                    <div>
                      <h3 className="font-semibold text-foreground">{selectedTemplate.name}</h3>
                      <p className="text-sm text-muted-foreground">{selectedTemplate.description}</p>
                      <div className="flex items-center space-x-2 mt-2">
                        <Badge variant="outline">{selectedTemplate.category}</Badge>
                        {selectedTemplate.is_dod_approved && (
                          <Badge variant="outline" className="text-green-400">DoD Approved</Badge>
                        )}
                      </div>
                    </div>
                  </div>
                  
                  {isDoDUser ? (
                    <div className="space-y-3">
                      <Label htmlFor="justification" className="text-foreground">
                        Business Justification
                      </Label>
                      <Textarea
                        id="justification"
                        value={configValues.justification || ''}
                        onChange={(e) => setConfigValues(prev => ({ ...prev, justification: e.target.value }))}
                        placeholder="Explain why this integration is needed for your mission..."
                        className="bg-input/50 border-border"
                      />
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {selectedTemplate.required_fields.map((field) => (
                        <div key={field} className="space-y-2">
                          <Label htmlFor={field} className="text-foreground capitalize">
                            {field.replace(/_/g, ' ')}
                          </Label>
                          <Input
                            id={field}
                            type={field.includes('password') || field.includes('secret') || field.includes('key') ? 'password' : 'text'}
                            value={configValues[field] || ''}
                            onChange={(e) => setConfigValues(prev => ({ ...prev, [field]: e.target.value }))}
                            placeholder={`Enter ${field.replace(/_/g, ' ')}`}
                            className="bg-input/50 border-border"
                          />
                        </div>
                      ))}
                    </div>
                  )}
                  
                  <div className="flex items-center justify-between pt-4">
                    <Button
                      variant="outline"
                      onClick={() => {
                        setSelectedTemplate(null);
                        setConfigValues({});
                      }}
                    >
                      Back
                    </Button>
                    <Button
                      variant="cyber"
                      onClick={handleConnect}
                      disabled={isConnecting}
                    >
                      {isConnecting ? 'Processing...' : 
                       isDoDUser ? 'Submit Request' : 'Connect Integration'}
                    </Button>
                  </div>
                </div>
              )}
            </DialogContent>
          </Dialog>
        </div>

        <TabsContent value="catalog" className="space-y-4">
          {/* Search and Filters */}
          <div className="flex items-center space-x-4">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search integrations..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10"
              />
            </div>
            <Select value={categoryFilter} onValueChange={setCategoryFilter}>
              <SelectTrigger className="w-48">
                <SelectValue placeholder="Filter by category" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Categories</SelectItem>
                <SelectItem value="SIEM">SIEM</SelectItem>
                <SelectItem value="ENDPOINT">Endpoint</SelectItem>
                <SelectItem value="FIREWALL">Firewall</SelectItem>
                <SelectItem value="IDENTITY">Identity</SelectItem>
                <SelectItem value="CLOUD">Cloud</SelectItem>
                <SelectItem value="VULNERABILITY">Vulnerability</SelectItem>
                <SelectItem value="NETWORK">Network</SelectItem>
                <SelectItem value="COMPLIANCE">Compliance</SelectItem>
              </SelectContent>
            </Select>
            <Button
              variant={showDoDOnly ? "default" : "outline"}
              onClick={() => setShowDoDOnly(!showDoDOnly)}
            >
              <Award className="h-4 w-4 mr-2" />
              DoD Only
            </Button>
          </div>

          {/* Integration Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredLibrary.map((item) => (
              <Card key={item.id} className="card-cyber hover:bg-accent/30 transition-colors">
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="flex items-center space-x-3">
                      {getCategoryIcon(item.category)}
                      <div>
                        <CardTitle className="text-lg">{item.name}</CardTitle>
                        <CardDescription className="text-sm">{item.provider}</CardDescription>
                      </div>
                    </div>
                    <div className="flex flex-col space-y-1">
                      {item.is_popular && (
                        <Badge variant="secondary" className="text-xs">Popular</Badge>
                      )}
                      {item.is_dod_approved && (
                        <Badge variant="outline" className="text-xs text-green-400">DoD</Badge>
                      )}
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-muted-foreground mb-3">{item.description}</p>
                  
                  <div className="space-y-2 mb-4">
                    <div className="text-xs text-muted-foreground">
                      <strong>Auth:</strong> {item.auth_type.toUpperCase()}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      <strong>Data Types:</strong> {item.supported_data_types.slice(0, 3).join(', ')}
                      {item.supported_data_types.length > 3 && '...'}
                    </div>
                    {item.compliance_standards.length > 0 && (
                      <div className="text-xs text-muted-foreground">
                        <strong>Compliance:</strong> {item.compliance_standards.slice(0, 2).join(', ')}
                        {item.compliance_standards.length > 2 && '...'}
                      </div>
                    )}
                  </div>
                  
                  <div className="flex items-center space-x-2">
                    <Button
                      className="flex-1"
                      onClick={() => {
                        setSelectedTemplate(item);
                        setShowConnectDialog(true);
                      }}
                    >
                      <Plus className="h-4 w-4 mr-2" />
                      Connect
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => globalThis.open(item.documentation_url, '_blank')}
                    >
                      <ExternalLink className="h-4 w-4" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="active" className="space-y-4">
          <Card className="card-cyber">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <CheckCircle className="h-5 w-5 text-primary" />
                <span>Active Integrations</span>
              </CardTitle>
              <CardDescription>
                Manage your connected security tools and data sources
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {userIntegrations.length === 0 ? (
                  <div className="text-center text-muted-foreground py-8">
                    <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No integrations configured</p>
                    <p className="text-sm">Connect your security tools to get started</p>
                  </div>
                ) : (
                  userIntegrations.map((integration) => (
                    <div
                      key={integration.id}
                      className="p-4 border border-border rounded-lg bg-card hover:bg-accent/30 transition-colors"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-4">
                          {getCategoryIcon(integration.integration_library?.category || 'CUSTOM')}
                          <div className="flex-1">
                            <div className="flex items-center space-x-2 mb-1">
                              <h4 className="font-medium text-foreground">{integration.name}</h4>
                              <Badge className={getStatusColor(integration.status)}>
                                {getStatusIcon(integration.status)}
                                <span className="ml-1">{integration.status}</span>
                              </Badge>
                              {integration.integration_library?.category && (
                                <Badge variant="outline">{integration.integration_library.category}</Badge>
                              )}
                            </div>
                            <p className="text-sm text-muted-foreground mb-2">
                              {integration.integration_library?.description}
                            </p>
                            <div className="flex items-center space-x-4 text-xs text-muted-foreground">
                              <span>Sync: {integration.sync_frequency}</span>
                              {integration.last_sync && (
                                <span>
                                  Last sync: {formatDistanceToNow(new Date(integration.last_sync), { addSuffix: true })}
                                </span>
                              )}
                              <span>Health: {integration.health_status}</span>
                            </div>
                          </div>
                        </div>
                        
                        <div className="flex items-center space-x-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleTest(integration.id, integration.name)}
                          >
                            <TestTube className="h-3 w-3 mr-1" />
                            Test
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                          >
                            <Settings className="h-3 w-3 mr-1" />
                            Config
                          </Button>
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={() => handleDisconnect(integration.id, integration.name)}
                          >
                            <Trash2 className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {isDoDUser && (
          <TabsContent value="tickets" className="space-y-4">
            <Card className="card-cyber">
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Ticket className="h-5 w-5 text-primary" />
                  <span>Security Integration Tickets</span>
                </CardTitle>
                <CardDescription>
                  Track your secure integration requests and approvals
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {tickets.length === 0 ? (
                    <div className="text-center text-muted-foreground py-8">
                      <Ticket className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No tickets submitted</p>
                      <p className="text-sm">Submit integration requests through the catalog</p>
                    </div>
                  ) : (
                    tickets.map((ticket) => (
                      <div
                        key={ticket.id}
                        className="p-4 border border-border rounded-lg bg-card"
                      >
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <div className="flex items-center space-x-2 mb-2">
                              <h4 className="font-medium text-foreground">{ticket.title}</h4>
                              <Badge className={getStatusColor(ticket.status)}>
                                {ticket.status.toUpperCase()}
                              </Badge>
                              <Badge variant="outline">{ticket.priority.toUpperCase()}</Badge>
                            </div>
                            <p className="text-sm text-muted-foreground mb-2">{ticket.description}</p>
                            <div className="text-xs text-muted-foreground">
                              Submitted {formatDistanceToNow(new Date(ticket.created_at), { addSuffix: true })}
                            </div>
                          </div>
                          <div className="flex items-center space-x-2">
                            {ticket.integration_library && getCategoryIcon(ticket.integration_library.category)}
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        )}
      </Tabs>
    </div>
  );
};