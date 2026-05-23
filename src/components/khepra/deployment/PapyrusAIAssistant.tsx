import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Input } from '@/components/ui/input';
import { 
  Brain, 
  MessageSquare, 
  X, 
  Send, 
  Lightbulb,
  Shield,
  Info,
  AlertTriangle,
  CheckCircle,
  Minimize2,
  Maximize2
} from 'lucide-react';
import { AdinkraSymbolDisplay } from '../AdinkraSymbolDisplay';

interface Message {
  id: string;
  type: 'user' | 'papyrus' | 'system';
  content: string;
  timestamp: Date;
  cultural_context?: string;
  suggestions?: string[];
}

interface PapyrusAIAssistantProps {
  currentStep: any;
  deploymentData: any;
  onClose: () => void;
}

export const PapyrusAIAssistant: React.FC<PapyrusAIAssistantProps> = ({
  currentStep,
  deploymentData,
  onClose
}) => {
  const [isMinimized, setIsMinimized] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputMessage, setInputMessage] = useState('');
  const [isThinking, setIsThinking] = useState(false);

  // Initialize with welcome message
  useEffect(() => {
    const welcomeMessage: Message = {
      id: 'welcome',
      type: 'papyrus',
      content: `Greetings! I am Papyrus, your AI guide through the KHEPRA Protocol deployment. I embody the ancient wisdom of African mathematical traditions while helping you navigate modern cybersecurity.

The papyrus represents the preservation and transmission of knowledge - just as ancient scribes recorded wisdom for future generations, I will guide you through this transformative deployment process.

How may I assist you on this journey?`,
      timestamp: new Date(),
      cultural_context: 'Sankofa - Learning from the past to move forward',
      suggestions: [
        'What is the KHEPRA Protocol?',
        'Explain the current deployment step',
        'What are the security benefits?',
        'How does cultural symbolism enhance security?'
      ]
    };
    setMessages([welcomeMessage]);
  }, []);

  // Provide contextual guidance based on current step
  useEffect(() => {
    if (currentStep?.id) {
      const stepGuidance = getStepGuidance(currentStep.id);
      if (stepGuidance) {
        const guidanceMessage: Message = {
          id: `guidance-${currentStep.id}`,
          type: 'system',
          content: stepGuidance.content,
          timestamp: new Date(),
          cultural_context: stepGuidance.cultural_context,
          suggestions: stepGuidance.suggestions
        };
        setMessages(prev => [...prev, guidanceMessage]);
      }
    }
  }, [currentStep?.id]);

  const getStepGuidance = (stepId: string) => {
    switch (stepId) {
      case 'welcome':
        return {
          content: `Welcome to the KHEPRA Protocol deployment! This step represents Sankofa - learning from the past to create a secure future. You are about to embark on a journey that combines ancient African wisdom with quantum-safe cybersecurity.`,
          cultural_context: 'Sankofa - Looking back to move forward wisely',
          suggestions: [
            'What makes KHEPRA different?',
            'Why is cultural context important in security?',
            'What will happen during deployment?'
          ]
        };
      case 'detection':
        return {
          content: `The environment discovery phase uses Gye Nyame principles - recognizing the supremacy of unified intelligence. Our AI agents are scanning your infrastructure with cultural awareness, understanding that each system has its own 'personality' that must be respected and protected.`,
          cultural_context: 'Gye Nyame - Supreme intelligence and coordination',
          suggestions: [
            'How does cultural scanning work?',
            'What assets will be discovered?',
            'How secure is my current setup?'
          ]
        };
      case 'selection':
        return {
          content: `Choosing deployment vectors follows the Eban principle - building a fortress that is both strong and adaptable. Each vector represents a different approach to protection, like different gates in a fortress, each serving its purpose while contributing to overall security.`,
          cultural_context: 'Eban - Fortress of protection and strength',
          suggestions: [
            'Which deployment vector is best for me?',
            'Can I use multiple vectors?',
            'What are the trade-offs?'
          ]
        };
      default:
        return null;
    }
  };

  const sendMessage = async () => {
    if (!inputMessage.trim()) return;

    const userMessage: Message = {
      id: `user-${Date.now()}`,
      type: 'user',
      content: inputMessage,
      timestamp: new Date()
    };

    setMessages(prev => [...prev, userMessage]);
    setInputMessage('');
    setIsThinking(true);

    // Simulate AI response
    setTimeout(() => {
      const response = generateResponse(inputMessage);
      const aiMessage: Message = {
        id: `papyrus-${Date.now()}`,
        type: 'papyrus',
        content: response.content,
        timestamp: new Date(),
        cultural_context: response.cultural_context,
        suggestions: response.suggestions
      };
      setMessages(prev => [...prev, aiMessage]);
      setIsThinking(false);
    }, 1500);
  };

  const generateResponse = (userInput: string) => {
    const input = userInput.toLowerCase();
    
    if (input.includes('khepra') || input.includes('protocol')) {
      return {
        content: `The KHEPRA Protocol (Kinetic Heuristic Encryption for Perimeter-Resilient Agents) is a revolutionary cybersecurity framework that integrates African mathematical wisdom with quantum-safe cryptography. 

Named after the sacred scarab beetle that symbolizes transformation and protection in ancient Egyptian culture, KHEPRA transforms your infrastructure into a living, breathing defense system that adapts and learns.

Key features:
• Adinkra-encoded security policies
• Quantum-resistant encryption
• Cultural threat intelligence
• Autonomous agent networks
• Supersymmetric validation`,
        cultural_context: 'Khepra - Transformation and renewal',
        suggestions: [
          'How does Adinkra encoding work?',
          'What is quantum-safe cryptography?',
          'Tell me about cultural threat intelligence'
        ]
      };
    }
    
    if (input.includes('cultural') || input.includes('adinkra')) {
      return {
        content: `Cultural symbolism in cybersecurity isn't just aesthetic - it's functional intelligence. Adinkra symbols represent complex mathematical relationships that can encode security policies in ways that are both human-readable and cryptographically secure.

For example:
• Eban (fortress) encodes perimeter defense strategies
• Nkyinkyim (journey) represents adaptive data flow patterns
• Gye Nyame (supremacy) governs hierarchical access controls

This approach creates security systems that are intuitively understood by human operators while being mathematically rigorous for AI agents.`,
        cultural_context: 'Adinkra - Symbolic wisdom encoding',
        suggestions: [
          'Show me specific symbol meanings',
          'How does this improve security?',
          'Can I customize the cultural context?'
        ]
      };
    }
    
    if (input.includes('secure') || input.includes('safe') || input.includes('security')) {
      return {
        content: `KHEPRA provides multi-layered security that goes beyond traditional approaches:

**Quantum Safety**: Post-quantum cryptography protects against future quantum computing threats.

**Cultural Resilience**: Symbolic encoding creates security patterns that are resistant to algorithmic attacks because they embed human wisdom.

**Autonomous Adaptation**: AI agents learn and adapt to new threats while maintaining cultural alignment.

**Transparency**: Unlike black-box security, KHEPRA's cultural foundation makes security decisions explainable and auditable.

Your data isn't just encrypted - it's protected by wisdom that has safeguarded communities for centuries.`,
        cultural_context: 'Dwennimmen - Humility and strength',
        suggestions: [
          'How does quantum-safe encryption work?',
          'What threats does this protect against?',
          'How do I monitor the security?'
        ]
      };
    }
    
    // Default response
    return {
      content: `I understand you're curious about this aspect of KHEPRA. Let me share some wisdom from the ancestors: "The best security comes not from walls alone, but from understanding the nature of what you protect."

In the context of your question, KHEPRA approaches this through:
• Adaptive intelligence that learns your specific environment
• Cultural patterns that resist algorithmic prediction
• Community-based validation that ensures authenticity
• Symbolic encoding that creates multi-layered protection

What specific aspect would you like me to explore further?`,
      cultural_context: 'Aya - Endurance and resourcefulness',
      suggestions: [
        'Explain how KHEPRA adapts',
        'What is community-based validation?',
        'How does symbolic encoding work?'
      ]
    };
  };

  const handleSuggestionClick = (suggestion: string) => {
    setInputMessage(suggestion);
    sendMessage();
  };

  if (isMinimized) {
    return (
      <Card className="w-64 h-16 card-cyber">
        <CardContent className="p-3 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Brain className="h-4 w-4 text-primary" />
            <span className="text-sm font-medium">Papyrus AI</span>
          </div>
          <div className="flex space-x-1">
            <Button size="sm" variant="ghost" onClick={() => setIsMinimized(false)}>
              <Maximize2 className="h-3 w-3" />
            </Button>
            <Button size="sm" variant="ghost" onClick={onClose}>
              <X className="h-3 w-3" />
            </Button>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="h-full flex flex-col card-cyber">
      <CardHeader className="flex-shrink-0 border-b border-primary/20">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8">
              <AdinkraSymbolDisplay 
                symbolName="Sankofa" 
                size="small" 
                showMatrix={false}
                className="animate-cultural-pulse"
              />
            </div>
            <div>
              <CardTitle className="text-primary flex items-center space-x-2">
                <Brain className="h-4 w-4" />
                <span>Papyrus AI Assistant</span>
              </CardTitle>
              <p className="text-xs text-muted-foreground">
                Cultural cybersecurity guidance
              </p>
            </div>
          </div>
          <div className="flex space-x-1">
            <Button size="sm" variant="ghost" onClick={() => setIsMinimized(true)}>
              <Minimize2 className="h-3 w-3" />
            </Button>
            <Button size="sm" variant="ghost" onClick={onClose}>
              <X className="h-3 w-3" />
            </Button>
          </div>
        </div>
      </CardHeader>

      <CardContent className="flex-1 flex flex-col p-0">
        {/* Messages */}
        <ScrollArea className="flex-1 p-4">
          <div className="space-y-4">
            {messages.map((message) => (
              <div key={message.id} className="space-y-2">
                <div className={`flex ${message.type === 'user' ? 'justify-end' : 'justify-start'}`}>
                  <div className={`max-w-[85%] rounded-lg p-3 ${
                    message.type === 'user' 
                      ? 'bg-primary text-primary-foreground ml-4' 
                      : message.type === 'system'
                      ? 'bg-muted/20 border border-border'
                      : 'bg-card border border-primary/20'
                  }`}>
                    <div className="flex items-start space-x-2">
                      {message.type !== 'user' && (
                        <div className="flex-shrink-0 mt-1">
                          {message.type === 'system' ? (
                            <Info className="h-3 w-3 text-blue-400" />
                          ) : (
                            <Brain className="h-3 w-3 text-primary" />
                          )}
                        </div>
                      )}
                      <div className="flex-1">
                        <p className="text-sm whitespace-pre-wrap">{message.content}</p>
                        {message.cultural_context && (
                          <div className="mt-2 p-2 bg-muted/20 rounded text-xs">
                            <div className="text-purple-400 font-medium">Cultural Context:</div>
                            <div>{message.cultural_context}</div>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
                
                {/* Suggestions */}
                {message.suggestions && message.suggestions.length > 0 && (
                  <div className="flex flex-wrap gap-2 ml-8">
                    {message.suggestions.map((suggestion, index) => (
                      <Button
                        key={index}
                        size="sm"
                        variant="outline"
                        className="text-xs h-6"
                        onClick={() => handleSuggestionClick(suggestion)}
                      >
                        {suggestion}
                      </Button>
                    ))}
                  </div>
                )}
              </div>
            ))}
            
            {isThinking && (
              <div className="flex justify-start">
                <div className="bg-card border border-primary/20 rounded-lg p-3 max-w-[85%]">
                  <div className="flex items-center space-x-2">
                    <Brain className="h-3 w-3 text-primary animate-pulse" />
                    <span className="text-sm text-muted-foreground">Papyrus is thinking...</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </ScrollArea>

        {/* Input */}
        <div className="flex-shrink-0 p-4 border-t border-border">
          <div className="flex space-x-2">
            <Input
              value={inputMessage}
              onChange={(e) => setInputMessage(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
              placeholder="Ask Papyrus about KHEPRA..."
              className="flex-1"
            />
            <Button size="sm" onClick={sendMessage} disabled={!inputMessage.trim() || isThinking}>
              <Send className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};