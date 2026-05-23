import { useState, useRef, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Badge } from '@/components/ui/badge';
import { 
  Bot, 
  MessageCircle, 
  X, 
  Send, 
  Minimize2, 
  Maximize2,
  User,
  Loader2,
  Sparkles,
  Shield,
  Brain,
  Zap
} from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import { useOrganizationContext } from '@/components/OrganizationProvider';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';
import { AdinkraSymbolDisplay } from '@/components/khepra/AdinkraSymbolDisplay';
import { useKhepraAuth } from '@/khepra/hooks/useKhepraAuth';

interface ChatMessage {
  id: string;
  message: string;
  messageType: 'user' | 'agent' | 'system';
  timestamp: Date;
}

interface FloatingAIAssistantProps {
  position?: 'bottom-right' | 'bottom-left' | 'top-right' | 'top-left';
}

export const FloatingAIAssistant = ({ 
  position = 'bottom-right' 
}: FloatingAIAssistantProps) => {
  const { user } = useAuth();
  const { currentOrganization } = useOrganizationContext();
  const { toast } = useToast();
  const { authState } = useKhepraAuth();
  
  const [isOpen, setIsOpen] = useState(false);
  const [isMinimized, setIsMinimized] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [sessionId] = useState(() => crypto.randomUUID());
  
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Initialize with welcome message
  useEffect(() => {
    if (isOpen && messages.length === 0) {
      const culturalGreeting = authState.isAuthenticated 
        ? `\n\n🔮 **KHEPRA Enhanced**: Operating with ${authState.culturalContext} intelligence`
        : '';

      setMessages([
        {
          id: crypto.randomUUID(),
          message: `🛡️ **ARGUS AI Assistant**\n\nI'm your 24/7 cybersecurity companion. Ask me about:\n• Security alerts & threats\n• Compliance status\n• Risk assessments\n• Quick actions${culturalGreeting}\n\nHow can I help you secure your environment?`,
          messageType: 'agent',
          timestamp: new Date(),
        }
      ]);
    }
  }, [isOpen, authState]);

  useEffect(() => {
    if (isOpen && !isMinimized) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, isOpen, isMinimized]);

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
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
      const { data, error } = await supabase.functions.invoke('grok-ai-agent', {
        body: {
          message: input.trim(),
          sessionId,
          organizationId: currentOrganization.organization_id,
          userId: user?.id,
          context: {
            timestamp: new Date().toISOString(),
            floatingAssistant: true,
            culturalContext: authState.isAuthenticated ? authState.culturalContext : null
          }
        }
      });

      if (error) throw error;

      const agentMessage: ChatMessage = {
        id: crypto.randomUUID(),
        message: data.response,
        messageType: 'agent',
        timestamp: new Date(),
      };

      setMessages(prev => [...prev, agentMessage]);

    } catch (error: any) {
      const errorMessage: ChatMessage = {
        id: crypto.randomUUID(),
        message: `❌ Unable to process request: ${error.message || 'Please try again.'}`,
        messageType: 'system',
        timestamp: new Date(),
      };
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setLoading(false);
    }
  };

  const quickSuggestions = [
    "What's my current security status?",
    "Any critical alerts?",
    "Run compliance check",
    "Show threat intelligence"
  ];

  const getPositionClass = () => {
    switch (position) {
      case 'bottom-left':
        return 'bottom-4 left-4';
      case 'top-right':
        return 'top-4 right-4';
      case 'top-left':
        return 'top-4 left-4';
      default:
        return 'bottom-4 right-4';
    }
  };

  const formatMessage = (message: string) => {
    return message.split('\n').map((line, index) => {
      if (line.startsWith('• ')) {
        return <li key={index} className="ml-4 text-sm">{line.substring(2)}</li>;
      }
      if (line.startsWith('**') && line.endsWith('**')) {
        return <div key={index} className="font-semibold text-primary mb-1 text-sm">{line.slice(2, -2)}</div>;
      }
      if (line.trim() === '') {
        return <br key={index} />;
      }
      return <div key={index} className="text-sm mb-1">{line}</div>;
    });
  };

  return (
    <div className={`fixed ${getPositionClass()} z-50 transition-all duration-300`}>
      {!isOpen ? (
        // Floating button
        <Button
          onClick={() => setIsOpen(true)}
          className="w-14 h-14 rounded-full bg-gradient-primary shadow-lg hover:shadow-xl transition-all duration-300 group relative animate-float animation-paused hover:animation-running"
          size="lg"
        >
          <div className="absolute inset-0 rounded-full bg-gradient-to-r from-primary/20 to-accent/20 animate-pulse" />
          <Bot className="h-6 w-6 text-primary-foreground relative z-10" />
          <div className="absolute -top-1 -right-1 w-4 h-4 bg-success rounded-full animate-pulse flex items-center justify-center">
            <Sparkles className="h-2 w-2 text-white" />
          </div>
        </Button>
      ) : (
        // Chat interface
        <Card className={`card-cyber transition-all duration-300 ${
          isMinimized 
            ? 'w-80 h-16' 
            : 'w-96 h-[500px]'
        } shadow-2xl border-primary/30`}>
          {/* Header */}
          <CardHeader className="pb-2 px-4 py-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <div className="relative">
                  <div className="w-8 h-8 bg-gradient-primary rounded-full flex items-center justify-center">
                    <Bot className="h-4 w-4 text-primary-foreground" />
                  </div>
                  <div className="absolute -top-1 -right-1 w-3 h-3 bg-success rounded-full animate-pulse" />
                </div>
                <div>
                  <CardTitle className="text-sm font-semibold">ARGUS AI Assistant</CardTitle>
                  {authState.isAuthenticated && (
                    <Badge variant="outline" className="text-xs bg-purple-500/20 text-purple-300 border-purple-500/30">
                      <AdinkraSymbolDisplay 
                        symbolName="Nyame" 
                        showMatrix={false} 
                        showMeaning={false}
                        className="w-3 h-3 mr-1"
                      />
                      KHEPRA Enhanced
                    </Badge>
                  )}
                </div>
              </div>
              <div className="flex items-center space-x-1">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setIsMinimized(!isMinimized)}
                  className="h-6 w-6 p-0"
                >
                  {isMinimized ? <Maximize2 className="h-3 w-3" /> : <Minimize2 className="h-3 w-3" />}
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setIsOpen(false)}
                  className="h-6 w-6 p-0"
                >
                  <X className="h-3 w-3" />
                </Button>
              </div>
            </div>
          </CardHeader>

          {!isMinimized && (
            <CardContent className="flex flex-col h-[420px] p-4 pt-0">
              {/* Messages Area */}
              <ScrollArea className="flex-1 pr-2 mb-3">
                <div className="space-y-3">
                  {messages.map((message) => (
                    <div
                      key={message.id}
                      className={`flex items-start space-x-2 ${
                        message.messageType === 'user' ? 'flex-row-reverse space-x-reverse' : ''
                      }`}
                    >
                      <div className={`w-6 h-6 rounded-full flex items-center justify-center flex-shrink-0 ${
                        message.messageType === 'user' 
                          ? 'bg-primary text-primary-foreground' 
                          : 'bg-accent text-accent-foreground'
                      }`}>
                        {message.messageType === 'user' ? (
                          <User className="h-3 w-3" />
                        ) : (
                          <Bot className="h-3 w-3" />
                        )}
                      </div>
                      
                      <div className={`max-w-[85%] ${
                        message.messageType === 'user' ? 'text-right' : 'text-left'
                      }`}>
                        <div className={`inline-block p-2 rounded-lg text-xs ${
                          message.messageType === 'user'
                            ? 'bg-primary text-primary-foreground'
                            : 'bg-card border border-border/50'
                        }`}>
                          {formatMessage(message.message)}
                        </div>
                        <div className="text-xs text-muted-foreground mt-1">
                          {message.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </div>
                      </div>
                    </div>
                  ))}
                  {loading && (
                    <div className="flex items-center space-x-2">
                      <div className="w-6 h-6 bg-accent rounded-full flex items-center justify-center">
                        <Bot className="h-3 w-3" />
                      </div>
                      <div className="bg-card border border-border/50 p-2 rounded-lg">
                        <Loader2 className="h-3 w-3 animate-spin text-muted-foreground" />
                      </div>
                    </div>
                  )}
                  <div ref={messagesEndRef} />
                </div>
              </ScrollArea>

              {/* Quick suggestions */}
              {messages.length === 1 && (
                <div className="mb-3">
                  <div className="text-xs text-muted-foreground mb-2">Quick suggestions:</div>
                  <div className="grid grid-cols-2 gap-1">
                    {quickSuggestions.map((suggestion, index) => (
                      <Button
                        key={index}
                        variant="outline"
                        size="sm"
                        className="text-xs h-8 p-2 justify-start hover:bg-primary/5"
                        onClick={() => setInput(suggestion)}
                      >
                        {suggestion}
                      </Button>
                    ))}
                  </div>
                </div>
              )}

              {/* Input Form */}
              <form onSubmit={handleSubmit} className="flex space-x-2">
                <Input
                  ref={inputRef}
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="Ask about security, compliance, threats..."
                  className="text-sm h-8"
                  disabled={loading}
                />
                <Button 
                  type="submit" 
                  size="sm" 
                  disabled={loading || !input.trim()}
                  className="h-8 w-8 p-0"
                >
                  {loading ? (
                    <Loader2 className="h-3 w-3 animate-spin" />
                  ) : (
                    <Send className="h-3 w-3" />
                  )}
                </Button>
              </form>
            </CardContent>
          )}
        </Card>
      )}
    </div>
  );
};