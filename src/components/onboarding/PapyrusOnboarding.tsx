import { useState, useEffect, useCallback } from 'react';
import { Dialog, DialogContent } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Progress } from '@/components/ui/progress';
import {
  Brain,
  Send,
  Sparkles,
  Shield,
  User,
  ArrowRight,
  CheckCircle2,
  Wand2,
  MessageSquare,
  ChevronRight
} from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { AdinkraSymbolDisplay } from '@/components/khepra/AdinkraSymbolDisplay';

interface PapyrusOnboardingProps {
  open: boolean;
  onClose: () => void;
  onComplete: () => void;
}

interface Message {
  id: string;
  type: 'papyrus' | 'user' | 'action';
  content: string;
  timestamp: Date;
  actions?: { label: string; action: string }[];
}

type OnboardingPhase = 'welcome' | 'profile' | 'explore';

export const PapyrusOnboarding = ({ open, onClose, onComplete }: PapyrusOnboardingProps) => {
  const { user } = useAuth();
  const { toast } = useToast();

  const [phase, setPhase] = useState<OnboardingPhase>('welcome');
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputMessage, setInputMessage] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [profileData, setProfileData] = useState({
    fullName: '',
    department: '',
    organization: ''
  });
  const [savingProfile, setSavingProfile] = useState(false);

  const progress = phase === 'welcome' ? 33 : phase === 'profile' ? 66 : 100;

  // Papyrus speaks
  const papyrusSays = useCallback((content: string, actions?: { label: string; action: string }[]) => {
    setIsTyping(true);
    setTimeout(() => {
      setMessages(prev => [...prev, {
        id: `papyrus-${Date.now()}`,
        type: 'papyrus',
        content,
        timestamp: new Date(),
        actions
      }]);
      setIsTyping(false);
    }, 800);
  }, []);

  // Initialize welcome
  useEffect(() => {
    if (open && messages.length === 0) {
      papyrusSays(
        `Greetings, traveler! I am Papyrus, your guide through the realm of KHEPRA Protocol.

Like the ancient scribes who preserved wisdom on papyrus scrolls, I am here to illuminate your path through modern cybersecurity.

Shall we begin your journey?`,
        [
          { label: "Let's go!", action: 'start' },
          { label: "Tell me more about KHEPRA", action: 'explain' }
        ]
      );
    }
  }, [open, messages.length, papyrusSays]);

  const handleAction = async (action: string) => {
    switch (action) {
      case 'start':
        setMessages(prev => [...prev, {
          id: `user-${Date.now()}`,
          type: 'user',
          content: "Let's go!",
          timestamp: new Date()
        }]);
        setTimeout(() => {
          setPhase('profile');
          papyrusSays(
            `Excellent! The Sankofa bird teaches us to look back and gather wisdom before moving forward.

Let me learn a bit about you so I can personalize your experience. What should I call you?`,
          );
        }, 500);
        break;

      case 'explain':
        setMessages(prev => [...prev, {
          id: `user-${Date.now()}`,
          type: 'user',
          content: "Tell me more about KHEPRA",
          timestamp: new Date()
        }]);
        papyrusSays(
          `KHEPRA Protocol is a revolutionary cybersecurity framework that weaves together:

• Ancient African mathematical wisdom (Adinkra symbols)
• Quantum-safe cryptography
• Cultural threat intelligence
• Autonomous AI protection

Named after the sacred scarab of transformation, KHEPRA doesn't just defend - it evolves.

Ready to experience it yourself?`,
          [
            { label: "Yes, let's set up!", action: 'start' },
            { label: "What's unique about it?", action: 'unique' }
          ]
        );
        break;

      case 'unique':
        setMessages(prev => [...prev, {
          id: `user-${Date.now()}`,
          type: 'user',
          content: "What's unique about it?",
          timestamp: new Date()
        }]);
        papyrusSays(
          `What makes KHEPRA special is its cultural foundation.

Traditional security is cold, mechanical. KHEPRA encodes security policies using Adinkra symbols - ancient West African ideograms that carry deep meaning.

This isn't aesthetic decoration. These patterns create security logic that is:
• Intuitive for humans to understand
• Resistant to algorithmic attacks
• Mathematically rigorous

You're not just getting software. You're inheriting centuries of wisdom.`,
          [
            { label: "I'm convinced, let's start!", action: 'start' }
          ]
        );
        break;

      case 'skip_profile':
        setPhase('explore');
        papyrusSays(
          `No worries! You can always update your profile later.

I'm now your companion throughout SouHimBou AI. Whenever you need guidance, look for me in the corner of your screen.

What would you like to explore first?`,
          [
            { label: "Security Dashboard", action: 'goto_security' },
            { label: "Compliance Tools", action: 'goto_compliance' },
            { label: "Just explore on my own", action: 'finish' }
          ]
        );
        break;

      case 'goto_security':
      case 'goto_compliance':
      case 'finish':
        onComplete();
        break;

      default:
        break;
    }
  };

  const saveProfile = async () => {
    if (!user || !profileData.fullName.trim()) {
      toast({
        title: "Name required",
        description: "Please enter your name to continue.",
        variant: "destructive"
      });
      return;
    }

    setSavingProfile(true);
    try {
      const { error } = await supabase
        .from('profiles')
        .update({
          full_name: profileData.fullName.trim(),
          department: profileData.department.trim() || null,
          organization_name: profileData.organization.trim() || null,
          updated_at: new Date().toISOString()
        })
        .eq('user_id', user.id);

      if (error) throw error;

      setMessages(prev => [...prev, {
        id: `action-${Date.now()}`,
        type: 'action',
        content: `Profile saved: ${profileData.fullName}`,
        timestamp: new Date()
      }]);

      setPhase('explore');
      papyrusSays(
        `Wonderful to meet you, ${profileData.fullName.split(' ')[0]}!

Your profile is saved. I'll remember you across our sessions.

I'm now your permanent companion here. Whenever you need help, click my icon in the corner. I can:

• Answer questions about security
• Guide you through features
• Provide compliance recommendations
• Explain cultural symbols

Where shall we begin?`,
        [
          { label: "Show me the dashboard", action: 'goto_security' },
          { label: "Check my compliance status", action: 'goto_compliance' },
          { label: "I'll explore myself", action: 'finish' }
        ]
      );

    } catch (error: any) {
      toast({
        title: "Error saving profile",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setSavingProfile(false);
    }
  };

  const sendMessage = () => {
    if (!inputMessage.trim()) return;

    const userMsg = inputMessage.trim();
    setInputMessage('');

    setMessages(prev => [...prev, {
      id: `user-${Date.now()}`,
      type: 'user',
      content: userMsg,
      timestamp: new Date()
    }]);

    // Simple response logic for onboarding context
    const lower = userMsg.toLowerCase();
    if (lower.includes('help') || lower.includes('what can')) {
      papyrusSays(
        `I can help you with:
• Understanding KHEPRA Protocol features
• Setting up your security environment
• Navigating compliance requirements
• Explaining cultural symbols and their meanings

Just ask, and I shall illuminate the path.`
      );
    } else if (lower.includes('skip') || lower.includes('later')) {
      handleAction('skip_profile');
    } else {
      papyrusSays(
        `I hear you! Once you're in the dashboard, I can provide more detailed guidance on any topic.

For now, let's complete your quick setup so you can get the full experience.`,
        phase === 'profile' ? undefined : [
          { label: "Take me to dashboard", action: 'finish' }
        ]
      );
    }
  };

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl max-h-[85vh] p-0 overflow-hidden bg-gradient-to-b from-slate-900 to-slate-950 border-primary/30">
        {/* Header */}
        <div className="px-6 py-4 border-b border-primary/20 bg-slate-900/50">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 rounded-full bg-primary/20 flex items-center justify-center">
                <AdinkraSymbolDisplay
                  symbolName="Sankofa"
                  size="small"
                  showMatrix={false}
                  className="w-6 h-6"
                />
              </div>
              <div>
                <h2 className="font-semibold text-lg flex items-center gap-2">
                  <Brain className="h-4 w-4 text-primary" />
                  Papyrus Guide
                </h2>
                <p className="text-xs text-muted-foreground">Your AI companion</p>
              </div>
            </div>
            <Badge variant="outline" className="bg-primary/10 text-primary border-primary/30">
              <Wand2 className="h-3 w-3 mr-1" />
              {phase === 'welcome' ? 'Welcome' : phase === 'profile' ? 'Quick Setup' : 'Ready'}
            </Badge>
          </div>
          <Progress value={progress} className="mt-3 h-1" />
        </div>

        {/* Chat Area */}
        <ScrollArea className="flex-1 h-[400px]">
          <div className="p-4 space-y-4">
            {messages.map((msg) => (
              <div key={msg.id} className="space-y-2">
                {msg.type === 'papyrus' && (
                  <div className="flex gap-3">
                    <div className="w-8 h-8 rounded-full bg-primary/20 flex-shrink-0 flex items-center justify-center">
                      <Brain className="h-4 w-4 text-primary" />
                    </div>
                    <div className="flex-1 space-y-2">
                      <div className="bg-slate-800/50 rounded-lg rounded-tl-none p-3 border border-slate-700/50">
                        <p className="text-sm whitespace-pre-wrap">{msg.content}</p>
                      </div>
                      {msg.actions && (
                        <div className="flex flex-wrap gap-2">
                          {msg.actions.map((action, idx) => (
                            <Button
                              key={idx}
                              size="sm"
                              variant="outline"
                              className="bg-primary/10 border-primary/30 hover:bg-primary/20"
                              onClick={() => handleAction(action.action)}
                            >
                              {action.label}
                              <ChevronRight className="h-3 w-3 ml-1" />
                            </Button>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {msg.type === 'user' && (
                  <div className="flex justify-end">
                    <div className="bg-primary text-primary-foreground rounded-lg rounded-tr-none p-3 max-w-[80%]">
                      <p className="text-sm">{msg.content}</p>
                    </div>
                  </div>
                )}

                {msg.type === 'action' && (
                  <div className="flex justify-center">
                    <Badge variant="secondary" className="bg-green-500/10 text-green-400 border-green-500/30">
                      <CheckCircle2 className="h-3 w-3 mr-1" />
                      {msg.content}
                    </Badge>
                  </div>
                )}
              </div>
            ))}

            {isTyping && (
              <div className="flex gap-3">
                <div className="w-8 h-8 rounded-full bg-primary/20 flex-shrink-0 flex items-center justify-center">
                  <Brain className="h-4 w-4 text-primary animate-pulse" />
                </div>
                <div className="bg-slate-800/50 rounded-lg rounded-tl-none p-3 border border-slate-700/50">
                  <div className="flex space-x-1">
                    <div className="w-2 h-2 bg-primary/60 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                    <div className="w-2 h-2 bg-primary/60 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                    <div className="w-2 h-2 bg-primary/60 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                  </div>
                </div>
              </div>
            )}

            {/* Profile Form - inline in chat */}
            {phase === 'profile' && !isTyping && messages.length > 2 && (
              <div className="bg-slate-800/30 rounded-lg p-4 border border-slate-700/50 space-y-4 ml-11">
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <User className="h-4 w-4" />
                  Quick Profile Setup
                </div>

                <div className="space-y-3">
                  <div>
                    <Label htmlFor="fullName" className="text-xs">Your Name *</Label>
                    <Input
                      id="fullName"
                      value={profileData.fullName}
                      onChange={(e) => setProfileData(prev => ({ ...prev, fullName: e.target.value }))}
                      placeholder="Enter your full name"
                      className="mt-1 bg-slate-900/50 border-slate-700"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <Label htmlFor="department" className="text-xs">Department</Label>
                      <Input
                        id="department"
                        value={profileData.department}
                        onChange={(e) => setProfileData(prev => ({ ...prev, department: e.target.value }))}
                        placeholder="e.g. IT Security"
                        className="mt-1 bg-slate-900/50 border-slate-700"
                      />
                    </div>
                    <div>
                      <Label htmlFor="organization" className="text-xs">Organization</Label>
                      <Input
                        id="organization"
                        value={profileData.organization}
                        onChange={(e) => setProfileData(prev => ({ ...prev, organization: e.target.value }))}
                        placeholder="e.g. Acme Corp"
                        className="mt-1 bg-slate-900/50 border-slate-700"
                      />
                    </div>
                  </div>
                </div>

                <div className="flex justify-between pt-2">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleAction('skip_profile')}
                  >
                    Skip for now
                  </Button>
                  <Button
                    size="sm"
                    onClick={saveProfile}
                    disabled={savingProfile || !profileData.fullName.trim()}
                    className="bg-primary hover:bg-primary/90"
                  >
                    {savingProfile ? 'Saving...' : 'Continue'}
                    <ArrowRight className="h-3 w-3 ml-1" />
                  </Button>
                </div>
              </div>
            )}
          </div>
        </ScrollArea>

        {/* Input Area */}
        <div className="px-4 py-3 border-t border-slate-800 bg-slate-900/50">
          <div className="flex gap-2">
            <Input
              value={inputMessage}
              onChange={(e) => setInputMessage(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && sendMessage()}
              placeholder="Ask Papyrus anything..."
              className="flex-1 bg-slate-800/50 border-slate-700"
            />
            <Button
              size="icon"
              onClick={sendMessage}
              disabled={!inputMessage.trim() || isTyping}
            >
              <Send className="h-4 w-4" />
            </Button>
          </div>
          <p className="text-xs text-muted-foreground mt-2 text-center">
            <MessageSquare className="h-3 w-3 inline mr-1" />
            Papyrus will remain available after setup
          </p>
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default PapyrusOnboarding;
