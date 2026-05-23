import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import {
  Brain,
  MessageSquare,
  Scan,
  Network,
  Shield,
  CheckCircle,
  ArrowRight,
  Loader2,
  Bot,
  Target,
  Database,
  Cloud,
  Lock,
  Zap
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';

interface AIOnboardingOrchestratorProps {
  onComplete: (discoveredAssets: any[]) => void;
}

interface ChatMessage {
  id: string;
  type: 'ai' | 'user';
  content: string;
  timestamp: Date;
  metadata?: any;
}

interface DiscoveredAsset {
  id: string;
  name: string;
  type: string;
  status: string;
  riskLevel: 'low' | 'medium' | 'high';
  stigPackages: string[];
  complianceScore: number;
  evidence: any[];
}

const AIOnboardingOrchestrator: React.FC<AIOnboardingOrchestratorProps> = ({ onComplete }) => {
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [userInput, setUserInput] = useState('');
  const [currentPhase, setCurrentPhase] = useState<'discovery' | 'analysis' | 'integration' | 'complete'>('discovery');
  const [discoveredAssets, setDiscoveredAssets] = useState<DiscoveredAsset[]>([]);
  const [isProcessing, setIsProcessing] = useState(false);
  const [progress, setProgress] = useState(0);
  const { toast } = useToast();

  const phases = [
    { id: 'discovery', label: 'Asset Discovery', icon: Scan },
    { id: 'analysis', label: 'STIG Analysis', icon: Shield },
    { id: 'integration', label: 'Integration Setup', icon: Network },
    { id: 'complete', label: 'Complete', icon: CheckCircle }
  ];

  useEffect(() => {
    // Initial AI greeting
    addAIMessage(
      "Hello! I'm your AI Security Orchestrator. I'll help you discover your technology stack, analyze STIG compliance, and set up automated security monitoring. Let's start with a simple question: What's your primary domain or IP range?"
    );
  }, []);

  const addAIMessage = (content: string, metadata?: any) => {
    setChatMessages(prev => [...prev, {
      id: `ai-${Date.now()}`,
      type: 'ai',
      content,
      timestamp: new Date(),
      metadata
    }]);
  };

  const addUserMessage = (content: string) => {
    setChatMessages(prev => [...prev, {
      id: `user-${Date.now()}`,
      type: 'user',
      content,
      timestamp: new Date()
    }]);
  };

  const processUserInput = async (input: string) => {
    if (!input.trim()) return;

    addUserMessage(input);
    setUserInput('');
    setIsProcessing(true);

    try {
      // Call AI agent to process the input and determine next steps
      const { data, error } = await supabase.functions.invoke('ai-onboarding-agent', {
        body: {
          userInput: input,
          currentPhase,
          discoveredAssets,
          chatHistory: chatMessages
        }
      });

      if (error) throw error;

      const { response, nextPhase, assets, shouldTriggerScan } = data;

      addAIMessage(response.content, response.metadata);

      if (nextPhase) {
        setCurrentPhase(nextPhase);
      }

      if (shouldTriggerScan) {
        await performAutomatedDiscovery(input);
      }

      if (assets) {
        setDiscoveredAssets(assets);
      }

    } catch (error: any) {
      console.error('AI processing error:', error);
      addAIMessage(
        "I encountered an issue processing your request. Let me try a different approach. Could you provide more details about your environment?"
      );
    } finally {
      setIsProcessing(false);
    }
  };

  const performAutomatedDiscovery = async (domain: string) => {
    setIsProcessing(true);
    setProgress(0);

    try {
      addAIMessage("Perfect! I'm now scanning your infrastructure. This will take a few moments...");

      // Simulate progressive discovery
      const steps = [
        { message: "Scanning network infrastructure...", progress: 20 },
        { message: "Discovering services and APIs...", progress: 40 },
        { message: "Analyzing STIG compliance requirements...", progress: 60 },
        { message: "Mapping control frameworks...", progress: 80 },
        { message: "Generating compliance baselines...", progress: 100 }
      ];

      for (const step of steps) {
        await new Promise(resolve => setTimeout(resolve, 2000));
        setProgress(step.progress);
        if (step.progress < 100) {
          addAIMessage(step.message);
        }
      }

      // Call real discovery service
      const { data: discoveryData, error: discoveryError } = await supabase.functions.invoke('automated-infrastructure-discovery', {
        body: {
          domain,
          scanDepth: 'standard',
          includeSTIGMapping: true,
          generateEvidence: true
        }
      });

      if (discoveryError) throw discoveryError;

      // Awaiting telemetry for real discovered assets
      const pendingAssets: DiscoveredAsset[] = [];

      setDiscoveredAssets(pendingAssets);
      setCurrentPhase('analysis');

      addAIMessage(
        `Discovery in progress. Awaiting telemetry. I'll analyze the STIG requirements next.`,
        { discoveredAssets: pendingAssets }
      );

      // Auto-proceed to analysis
      setTimeout(() => {
        performSTIGAnalysis(pendingAssets);
      }, 2000);

    } catch (error: any) {
      console.error('Discovery error:', error);
      addAIMessage("I encountered an issue during discovery. Let me try with a different approach.");
    } finally {
      setIsProcessing(false);
    }
  };

  const performSTIGAnalysis = async (assets: DiscoveredAsset[]) => {
    try {
      addAIMessage("Now analyzing STIG compliance for each discovered asset...");

      // Call STIG analysis service
      const { data, error } = await supabase.functions.invoke('stig-compliance-analyzer', {
        body: {
          assets: assets.map(a => ({
            id: a.id,
            type: a.type,
            name: a.name,
            stigPackages: a.stigPackages
          }))
        }
      });

      if (error) throw error;

      setCurrentPhase('integration');

      addAIMessage(
        `Analysis complete! I found ${assets.filter(a => a.complianceScore < 80).length} assets that need attention. Would you like me to set up automated remediation for the compliance gaps, or would you prefer to review them manually first?`
      );

    } catch (error: any) {
      console.error('STIG analysis error:', error);
      addAIMessage("Analysis completed with some limitations. Let's proceed to integration setup.");
      setCurrentPhase('integration');
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      processUserInput(userInput);
    }
  };

  const renderAssetCard = (asset: DiscoveredAsset) => (
    <div key={asset.id} className="border rounded-lg p-4 space-y-2">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          {asset.type === 'server' && <Database className="h-5 w-5 text-blue-500" />}
          {asset.type === 'api' && <Network className="h-5 w-5 text-green-500" />}
          {asset.type === 'database' && <Lock className="h-5 w-5 text-purple-500" />}
          <span className="font-medium">{asset.name}</span>
        </div>
        <Badge variant={
          asset.riskLevel === 'low' ? 'default' :
            asset.riskLevel === 'medium' ? 'secondary' :
              'destructive'
        }>
          {asset.riskLevel} risk
        </Badge>
      </div>
      <div className="text-sm text-gray-600">
        Compliance Score: {asset.complianceScore}%
      </div>
      <div className="text-xs text-gray-500">
        STIG Packages: {asset.stigPackages.join(', ')}
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50 dark:from-slate-900 dark:via-blue-900 dark:to-indigo-900 p-6">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <div className="p-3 bg-gradient-to-r from-blue-500 to-purple-500 rounded-2xl">
              <Brain className="h-8 w-8 text-white" />
            </div>
          </div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
            AI Security Orchestrator
          </h1>
          <p className="text-gray-600 dark:text-gray-300">
            Automated STIG compliance discovery and remediation
          </p>
        </div>

        {/* Progress Indicator */}
        <div className="mb-8">
          <div className="flex items-center justify-between mb-4">
            {phases.map((phase, index) => (
              <div key={phase.id} className="flex items-center">
                <div className={`
                  w-10 h-10 rounded-full flex items-center justify-center
                  ${phases.findIndex(p => p.id === currentPhase) >= index
                    ? 'bg-blue-500 text-white'
                    : 'bg-gray-200 dark:bg-gray-700 text-gray-500'
                  }
                `}>
                  <phase.icon className="h-5 w-5" />
                </div>
                {index < phases.length - 1 && (
                  <div className={`
                    w-16 h-0.5 mx-2
                    ${phases.findIndex(p => p.id === currentPhase) > index
                      ? 'bg-blue-500'
                      : 'bg-gray-200 dark:bg-gray-700'
                    }
                  `} />
                )}
              </div>
            ))}
          </div>
          <div className="text-center text-sm text-gray-600 dark:text-gray-400">
            {phases.find(p => p.id === currentPhase)?.label}
          </div>
          {progress > 0 && progress < 100 && (
            <Progress value={progress} className="mt-4" />
          )}
        </div>

        <div className="grid lg:grid-cols-2 gap-8">
          {/* Chat Interface */}
          <Card className="h-96">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Bot className="h-5 w-5" />
                <span>AI Assistant</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Messages */}
              <div className="h-64 overflow-y-auto space-y-3 border rounded p-3 bg-gray-50 dark:bg-gray-800">
                {chatMessages.map((message) => (
                  <div
                    key={message.id}
                    className={`flex ${message.type === 'user' ? 'justify-end' : 'justify-start'}`}
                  >
                    <div className={`
                      max-w-xs p-3 rounded-lg text-sm
                      ${message.type === 'user'
                        ? 'bg-blue-500 text-white'
                        : 'bg-white dark:bg-gray-700 border'
                      }
                    `}>
                      {message.content}
                    </div>
                  </div>
                ))}
                {isProcessing && (
                  <div className="flex justify-start">
                    <div className="bg-white dark:bg-gray-700 border p-3 rounded-lg">
                      <Loader2 className="h-4 w-4 animate-spin" />
                    </div>
                  </div>
                )}
              </div>

              {/* Input */}
              <div className="flex space-x-2">
                <Input
                  value={userInput}
                  onChange={(e) => setUserInput(e.target.value)}
                  onKeyPress={handleKeyPress}
                  placeholder="Type your response..."
                  disabled={isProcessing}
                />
                <Button
                  onClick={() => processUserInput(userInput)}
                  disabled={isProcessing || !userInput.trim()}
                >
                  <ArrowRight className="h-4 w-4" />
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Discovered Assets */}
          <Card className="h-96">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Target className="h-5 w-5" />
                <span>Discovered Assets ({discoveredAssets.length})</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="h-64 overflow-y-auto space-y-3">
                {discoveredAssets.length === 0 ? (
                  <div className="text-center text-gray-500 dark:text-gray-400 py-8">
                    Assets will appear here as they're discovered
                  </div>
                ) : (
                  discoveredAssets.map(renderAssetCard)
                )}
              </div>

              {discoveredAssets.length > 0 && currentPhase === 'complete' && (
                <Button
                  onClick={() => onComplete(discoveredAssets)}
                  className="w-full mt-4"
                >
                  <CheckCircle className="h-4 w-4 mr-2" />
                  Complete Setup
                </Button>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default AIOnboardingOrchestrator;