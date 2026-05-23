import { useState, useRef, useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';
import { useOrganizationContext } from '@/components/OrganizationProvider';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Bot, User, Send, Loader2, Shield, AlertTriangle, CheckCircle, Brain, Clock, Zap, PlayCircle, Sparkles } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { CulturalThreatTaxonomy } from '@/khepra/taxonomy/CulturalThreatTaxonomy';
import { AdinkraAlgebraicEngine } from '@/khepra/aae/AdinkraEngine';
import { useKhepraAuth } from '@/khepra/hooks/useKhepraAuth';

interface ChatMessage {
  id: string;
  message: string;
  messageType: 'user' | 'agent' | 'system';
  timestamp: Date;
  context?: any;
  actionableItems?: ActionableItem[];
  executionResults?: ExecutionResult[];
}

interface ActionableItem {
  type: string;
  text: string;
  priority: 'high' | 'medium' | 'low';
  category: string;
  canAutoExecute?: boolean;
  remediationType?: string;
  targets?: string[];
  requiresApproval?: boolean;
}

interface ExecutionResult {
  actionId: string;
  status: 'executed' | 'pending_approval' | 'failed' | 'error';
  result?: any;
  error?: string;
  reason?: string;
  type: string;
  targets?: string[];
  successRate?: number;
}

interface SecurityContext {
  alertsCount: number;
  threatsCount: number;
  complianceScore: number;
  culturalPatterns?: any[];
  adinkraSignature?: string;
}

export const AISecurityAgent = () => {
  const { user } = useAuth();
  const { currentOrganization } = useOrganizationContext();
  const { toast } = useToast();
  const { authState } = useKhepraAuth();
  
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [sessionId] = useState(() => crypto.randomUUID());
  const [actionableItems, setActionableItems] = useState<ActionableItem[]>([]);
  const [securityContext, setSecurityContext] = useState<SecurityContext | null>(null);
  
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    // Add enhanced welcome message with cultural context
    const culturalGreeting = authState.isAuthenticated 
      ? `\n\n🔮 **Cultural Intelligence Enhanced**: Currently operating with ${authState.culturalContext} context (Trust Score: ${authState.trustScore})\n• **Adinkra Pattern Recognition** - Detect threats using cultural symbolic analysis\n• **Cultural Threat Taxonomy** - Classify threats with traditional wisdom`
      : '';

    setMessages([
      {
        id: crypto.randomUUID(),
        message: `🛡️ **ARGUS AI Security Agent Activated**\n\nI'm your AI-powered Security Operations Center assistant enhanced with KHEPRA Protocol cultural intelligence. I can help you with:\n\n• **Threat Analysis** - Analyze current security posture and active threats\n• **Incident Response** - Guide you through security incidents\n• **Compliance Review** - Check compliance status and identify gaps\n• **Risk Assessment** - Evaluate and prioritize security risks\n• **Security Automation** - Suggest automation opportunities${culturalGreeting}\n\nWhat security challenge can I help you with today?`,
        messageType: 'agent',
        timestamp: new Date(),
      }
    ]);
  }, [authState]);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || loading || !currentOrganization) return;

    const userMessage: ChatMessage = {
      id: crypto.randomUUID(),
      message: input.trim(),
      messageType: 'user',
      timestamp: new Date(),
    };

    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setLoading(true);

    try {
      // Enhance request with cultural context
      const culturalContext = authState.isAuthenticated ? {
        culturalContext: authState.culturalContext,
        trustScore: authState.trustScore,
        adinkraTransformations: authState.adinkraTransformations.length,
        culturalFingerprint: AdinkraAlgebraicEngine.generateFingerprint(input.trim(), ['Nyame', 'Eban'])
      } : {};

      const { data, error } = await supabase.functions.invoke('grok-ai-agent', {
        body: {
          message: input.trim(),
          sessionId,
          organizationId: currentOrganization.organization_id,
          userId: user?.id,
          context: {
            timestamp: new Date().toISOString(),
            userAgent: navigator.userAgent,
            ...culturalContext
          }
        }
      });

      if (error) throw error;

      // Enhance response with cultural analysis if threat data is available
      let enhancedResponse = data.response;
      let culturalAnalysis = null;
      
      if (data.securityContext?.threats && authState.isAuthenticated) {
        try {
          const symbolicAnalysis = CulturalThreatTaxonomy.analyzeSymbolicPatterns(data.securityContext.threats);
          if (symbolicAnalysis.length > 0) {
            culturalAnalysis = symbolicAnalysis;
            enhancedResponse += `\n\n🔮 **Cultural Pattern Analysis:**\n`;
            symbolicAnalysis.slice(0, 3).forEach(analysis => {
              enhancedResponse += `• ${analysis.detectedPatterns.length} cultural patterns detected\n`;
              if (analysis.culturalRecommendations.length > 0) {
                enhancedResponse += `• Recommendation: ${analysis.culturalRecommendations[0]}\n`;
              }
            });
          }
        } catch (error) {
          console.log('Cultural analysis error:', error);
        }
      }

      const agentMessage: ChatMessage = {
        id: crypto.randomUUID(),
        message: enhancedResponse,
        messageType: 'agent',
        timestamp: new Date(),
        context: { 
          ...data.securityContext, 
          culturalAnalysis,
          adinkraSignature: culturalAnalysis ? culturalAnalysis[0]?.symbolicFingerprint : undefined
        },
        actionableItems: data.actionableItems,
        executionResults: data.executionResults
      };

      setMessages(prev => [...prev, agentMessage]);
      setActionableItems(data.actionableItems || []);
      setSecurityContext(data.securityContext);

      // Show execution summary toast if actions were executed
      if (data.executionResults && data.executionResults.length > 0) {
        const executed = data.executionResults.filter(r => r.status === 'executed').length;
        const pending = data.executionResults.filter(r => r.status === 'pending_approval').length;
        const failed = data.executionResults.filter(r => r.status === 'failed' || r.status === 'error').length;
        
        let toastMessage = '';
        if (executed > 0) toastMessage += `${executed} actions executed automatically. `;
        if (pending > 0) toastMessage += `${pending} actions require approval. `;
        if (failed > 0) toastMessage += `${failed} actions failed.`;
        
        if (toastMessage) {
          toast({
            title: "Autonomous Actions Update",
            description: toastMessage.trim(),
            variant: executed > 0 ? "default" : pending > 0 ? "default" : "destructive"
          });
        }
      }

    } catch (error: any) {
      console.error('Error calling AI agent:', error);
      
      const errorMessage: ChatMessage = {
        id: crypto.randomUUID(),
        message: `❌ **Error**: Unable to process your request. ${error.message || 'Please try again.'}`,
        messageType: 'system',
        timestamp: new Date(),
      };

      setMessages(prev => [...prev, errorMessage]);
      
      toast({
        title: "AI Agent Error",
        description: "Failed to get response from security agent.",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
      inputRef.current?.focus();
    }
  };

  const handleQuickAction = async (suggestion: string) => {
    setInput(suggestion);
    inputRef.current?.focus();
  };

  const formatMessage = (message: string) => {
    // Convert markdown-like formatting to JSX
    return message
      .split('\n')
      .map((line, index) => {
        if (line.startsWith('• ')) {
          return <li key={index} className="ml-4">{line.substring(2)}</li>;
        }
        if (line.startsWith('**') && line.endsWith('**')) {
          return <div key={index} className="font-semibold text-primary mb-2">{line.slice(2, -2)}</div>;
        }
        if (line.trim() === '') {
          return <br key={index} />;
        }
        return <div key={index} className="mb-1">{line}</div>;
      });
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'high': return 'destructive';
      case 'medium': return 'warning';
      case 'low': return 'secondary';
      default: return 'outline';
    }
  };

  const getPriorityIcon = (priority: string) => {
    switch (priority) {
      case 'high': return <AlertTriangle className="h-3 w-3" />;
      case 'medium': return <Shield className="h-3 w-3" />;
      case 'low': return <CheckCircle className="h-3 w-3" />;
      default: return null;
    }
  };

  const getExecutionStatusBadge = (status: string) => {
    switch (status) {
      case 'executed': return 'bg-success text-success-foreground';
      case 'pending_approval': return 'bg-warning text-warning-foreground';
      case 'failed':
      case 'error': return 'bg-destructive text-destructive-foreground';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  return (
    <div className="flex flex-col h-full max-h-[800px]">
      <Card className="flex-1 flex flex-col card-cyber">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <div className="relative">
                <Bot className="h-6 w-6 text-primary" />
                <div className="absolute -top-1 -right-1 w-3 h-3 bg-success rounded-full animate-pulse" />
              </div>
              <div>
                <CardTitle className="text-lg">ARGUS AI Security Agent</CardTitle>
                <CardDescription>
                  AI-Powered Security Operations Center Assistant
                </CardDescription>
              </div>
            </div>
            {securityContext && (
              <div className="flex items-center space-x-2">
                <Badge variant="outline" className="text-xs">
                  <Shield className="h-3 w-3 mr-1" />
                  {securityContext.alertsCount} Alerts
                </Badge>
                <Badge variant="outline" className="text-xs">
                  <Brain className="h-3 w-3 mr-1" />
                  {securityContext.threatsCount} Threats
                </Badge>
                {securityContext.culturalPatterns && securityContext.culturalPatterns.length > 0 && (
                  <Badge variant="outline" className="text-xs bg-purple-500/20 text-purple-300 border-purple-500/30">
                    <Sparkles className="h-3 w-3 mr-1" />
                    {securityContext.culturalPatterns.length} Cultural Patterns
                  </Badge>
                )}
                {authState.isAuthenticated && (
                  <Badge variant="outline" className="text-xs bg-blue-500/20 text-blue-300 border-blue-500/30">
                    KHEPRA Enhanced
                  </Badge>
                )}
              </div>
            )}
          </div>
        </CardHeader>

        <CardContent className="flex-1 flex flex-col space-y-4 p-4">
          {/* Messages Area */}
          <ScrollArea className="flex-1 pr-4">
            <div className="space-y-4">
              {messages.map((message) => (
                <div
                  key={message.id}
                  className={`flex items-start space-x-3 ${
                    message.messageType === 'user' ? 'flex-row-reverse space-x-reverse' : ''
                  }`}
                >
                  <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${
                    message.messageType === 'user' 
                      ? 'bg-primary text-primary-foreground' 
                      : message.messageType === 'agent'
                      ? 'bg-accent text-accent-foreground'
                      : 'bg-warning text-warning-foreground'
                  }`}>
                    {message.messageType === 'user' ? (
                      <User className="h-4 w-4" />
                    ) : message.messageType === 'agent' ? (
                      <Bot className="h-4 w-4" />
                    ) : (
                      <AlertTriangle className="h-4 w-4" />
                    )}
                  </div>
                  
                  <div className={`flex-1 max-w-[80%] ${
                    message.messageType === 'user' ? 'text-right' : 'text-left'
                  }`}>
                    <div className={`inline-block p-3 rounded-lg ${
                      message.messageType === 'user'
                        ? 'bg-primary text-primary-foreground'
                        : message.messageType === 'agent'
                        ? 'bg-card border border-border'
                        : 'bg-warning/10 border border-warning/20'
                    }`}>
                     <div className="text-sm">
                        {formatMessage(message.message)}
                      </div>
                      
                      {/* Show actionable items for this message */}
                      {message.actionableItems && message.actionableItems.length > 0 && (
                        <div className="mt-3 p-3 bg-accent/20 rounded border border-border/50">
                          <div className="text-xs font-medium text-foreground mb-2 flex items-center">
                            <Zap className="h-3 w-3 mr-1" />
                            Recommended Actions
                          </div>
                          <div className="space-y-2">
                            {message.actionableItems.map((item, idx) => (
                              <div key={idx} className="text-xs">
                                <div className="flex items-center space-x-2">
                                  <Badge variant={getPriorityColor(item.priority) as any} className="text-xs">
                                    {item.priority}
                                  </Badge>
                                  <span className="text-muted-foreground">{item.category}</span>
                                </div>
                                <p className="mt-1 text-foreground">{item.text}</p>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Show execution results for this message */}
                      {message.executionResults && message.executionResults.length > 0 && (
                        <div className="mt-3 p-3 bg-success/10 rounded border border-success/30">
                          <div className="text-xs font-medium text-foreground mb-2 flex items-center">
                            <PlayCircle className="h-3 w-3 mr-1 text-success" />
                            Autonomous Execution Results
                          </div>
                          <div className="space-y-2">
                            {message.executionResults.map((result, idx) => (
                              <div key={idx} className="flex items-center justify-between p-2 bg-card rounded border border-border/50">
                                <div className="flex-1">
                                  <div className="flex items-center space-x-2">
                                    <Badge className={getExecutionStatusBadge(result.status)}>
                                      {result.status.replaceAll('_', ' ').toUpperCase()}
                                    </Badge>
                                    <span className="text-xs text-muted-foreground">{result.type}</span>
                                  </div>
                                  <p className="text-xs text-foreground mt-1">{result.actionId}...</p>
                                  {result.targets && result.targets.length > 0 && (
                                    <p className="text-xs text-muted-foreground">
                                      Targets: {result.targets.join(', ')}
                                    </p>
                                  )}
                                  {result.successRate && (
                                    <p className="text-xs text-success">Success Rate: {result.successRate}%</p>
                                  )}
                                  {result.reason && (
                                    <p className="text-xs text-warning">{result.reason}</p>
                                  )}
                                  {result.error && (
                                    <p className="text-xs text-destructive">Error: {result.error}</p>
                                  )}
                                </div>
                                <div className="ml-2">
                                  {result.status === 'executed' && <CheckCircle className="h-4 w-4 text-success" />}
                                  {result.status === 'pending_approval' && <Clock className="h-4 w-4 text-warning" />}
                                  {(result.status === 'failed' || result.status === 'error') && <AlertTriangle className="h-4 w-4 text-destructive" />}
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">
                      {message.timestamp.toLocaleTimeString()}
                    </div>
                  </div>
                </div>
              ))}
              {loading && (
                <div className="flex items-start space-x-3">
                  <div className="flex-shrink-0 w-8 h-8 rounded-full bg-accent text-accent-foreground flex items-center justify-center">
                    <Bot className="h-4 w-4" />
                  </div>
                  <div className="flex-1">
                    <div className="inline-block p-3 rounded-lg bg-card border border-border">
                      <div className="flex items-center space-x-2 text-sm text-muted-foreground">
                        <Loader2 className="h-4 w-4 animate-spin" />
                        <span>ARGUS is analyzing security data...</span>
                      </div>
                    </div>
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>
          </ScrollArea>

          {/* Actionable Items */}
          {actionableItems.length > 0 && (
            <div className="space-y-2">
              <Separator />
              <div className="flex items-center space-x-2">
                <CheckCircle className="h-4 w-4 text-primary" />
                <span className="text-sm font-medium">Recommended Actions</span>
              </div>
              <div className="space-y-2 max-h-32 overflow-y-auto">
                {actionableItems.map((item, index) => (
                  <div key={index} className="flex items-start space-x-2 p-2 bg-card/50 rounded-lg border border-border/50">
                    <div className="flex-shrink-0 mt-0.5">
                      {getPriorityIcon(item.priority)}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs text-muted-foreground">
                        <Badge variant={getPriorityColor(item.priority) as any} className="text-xs mr-2">
                          {item.priority}
                        </Badge>
                        <Badge variant="outline" className="text-xs">
                          {item.category}
                        </Badge>
                      </div>
                      <p className="text-sm mt-1">{item.text}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Quick Actions */}
          <div className="space-y-2">
            <Separator />
            <div className="flex flex-wrap gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleQuickAction("Analyze current security posture and active threats")}
                disabled={loading}
              >
                <Shield className="h-3 w-3 mr-1" />
                Threat Analysis
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleQuickAction("Review compliance status and identify gaps")}
                disabled={loading}
              >
                <CheckCircle className="h-3 w-3 mr-1" />
                Compliance Check
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleQuickAction("Test emergency response: simulate high-priority threat requiring immediate blocking of IP 192.168.1.100")}
                disabled={loading}
                className="border-destructive text-destructive hover:bg-destructive hover:text-destructive-foreground"
              >
                <AlertTriangle className="h-3 w-3 mr-1" />
                Emergency Test
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleQuickAction("Suggest security automation opportunities")}
                disabled={loading}
              >
                <Brain className="h-3 w-3 mr-1" />
                Automation Ideas
              </Button>
            </div>
          </div>

          {/* Input Area */}
          <form onSubmit={handleSubmit} className="flex space-x-2">
            <Input
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask ARGUS about security threats, compliance, or incident response..."
              disabled={loading}
              className="flex-1"
            />
            <Button type="submit" disabled={loading || !input.trim()} size="icon">
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Send className="h-4 w-4" />
              )}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
};