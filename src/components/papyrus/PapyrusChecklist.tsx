import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { Progress } from '@/components/ui/progress';
import { Checkbox } from '@/components/ui/checkbox';
import { 
  Scroll, 
  CheckCircle2, 
  Clock, 
  AlertTriangle, 
  Zap, 
  Shield, 
  BookOpen,
  Sparkles,
  RefreshCw,
  Brain,
  Target
} from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import { useOrganizationContext } from '@/components/OrganizationProvider';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';
import { AdinkraSymbolDisplay } from '@/components/khepra/AdinkraSymbolDisplay';
import { useKhepraAuth } from '@/khepra/hooks/useKhepraAuth';

interface ChecklistItem {
  id: string;
  title: string;
  description: string;
  category: 'security' | 'compliance' | 'setup' | 'optimization' | 'khepra' | 'integrations' | 'ai';
  priority: 'low' | 'medium' | 'high' | 'critical';
  completed: boolean;
  aiGenerated: boolean;
  estimatedTime: string;
  actionUrl?: string;
  prerequisites?: string[];
}

interface PapyrusChecklistProps {
  embedded?: boolean;
  onItemComplete?: (itemId: string) => void;
}

export const PapyrusChecklist: React.FC<PapyrusChecklistProps> = ({ 
  embedded = false,
  onItemComplete 
}) => {
  const { user } = useAuth();
  const { currentOrganization } = useOrganizationContext();
  const { toast } = useToast();
  const { authState } = useKhepraAuth();
  
  const [items, setItems] = useState<ChecklistItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [activeCategory, setActiveCategory] = useState<string>('all');
  const [refreshing, setRefreshing] = useState(false);

  const categories = [
    { id: 'all', label: 'All Items', icon: <Scroll className="h-4 w-4" /> },
    { id: 'security', label: 'Security', icon: <Shield className="h-4 w-4" /> },
    { id: 'compliance', label: 'Compliance', icon: <CheckCircle2 className="h-4 w-4" /> },
    { id: 'setup', label: 'Setup', icon: <Target className="h-4 w-4" /> },
    { id: 'optimization', label: 'Optimization', icon: <Zap className="h-4 w-4" /> },
    { id: 'khepra', label: 'KHEPRA', icon: <Sparkles className="h-4 w-4" /> },
    { id: 'integrations', label: 'Integrations', icon: <Shield className="h-4 w-4" /> },
    { id: 'ai', label: 'AI Agents', icon: <Brain className="h-4 w-4" /> }
  ];

  const priorityColors = {
    low: 'bg-primary/20 text-primary border-primary/30',
    medium: 'bg-accent/20 text-accent-foreground border-accent/30',
    high: 'bg-destructive/20 text-destructive-foreground border-destructive/30',
    critical: 'bg-destructive/30 text-destructive-foreground border-destructive/50'
  };

  useEffect(() => {
    generatePersonalizedChecklist();
  }, [user, currentOrganization, authState]);

  const generatePersonalizedChecklist = async () => {
    if (!user || !currentOrganization) return;
    
    setLoading(true);
    try {
      const { data, error } = await supabase.functions.invoke('grok-ai-agent', {
        body: {
          message: 'Generate a personalized security and optimization checklist for my current environment',
          sessionId: `papyrus-${Date.now()}`,
          organizationId: currentOrganization.organization_id,
          userId: user.id,
          context: {
            requestType: 'checklist_generation',
            userRole: user.email,
            khepraEnabled: authState.isAuthenticated,
            culturalContext: authState.culturalContext || 'general'
          }
        }
      });

      if (error) throw error;

      // Parse AI response and convert to checklist items
      const generatedItems = parseAIResponse(data.response);
      
      // Add some base items that are always relevant
      const baseItems = getBaseChecklistItems();
      
      setItems([...baseItems, ...generatedItems]);
      
    } catch (error: any) {
      console.error('Error generating checklist:', error);
      setItems(getBaseChecklistItems());
      toast({
        title: "Papyrus Initialized",
        description: "Using default checklist. AI personalization unavailable.",
        variant: "default"
      });
    } finally {
      setLoading(false);
    }
  };

  const parseAIResponse = (response: string): ChecklistItem[] => {
    // Simple parser - in production this would be more sophisticated
    const aiItems: ChecklistItem[] = [];
    
    if (authState.isAuthenticated) {
      aiItems.push({
        id: 'khepra-setup',
        title: 'Complete KHEPRA Protocol Integration',
        description: `Leverage ${authState.culturalContext || 'cultural'} intelligence for enhanced security`,
        category: 'khepra',
        priority: 'high',
        completed: false,
        aiGenerated: true,
        estimatedTime: '15 min',
        actionUrl: '/khepra-protocol'
      });
      
      aiItems.push({
        id: 'integration-hub-setup',
        title: 'Configure Integration Hub with AI Assistance',
        description: 'Set up your security tool integrations with AI-powered configuration and KHEPRA Protocol enhancement',
        category: 'integrations',
        priority: 'high',
        completed: false,
        aiGenerated: true,
        estimatedTime: '20 min',
        actionUrl: '/?tab=integrations'
      });
      
      aiItems.push({
        id: 'ai-agent-integration',
        title: 'Enable AI Agent for Integration Management',
        description: 'Activate AI assistant for automated integration monitoring and optimization',
        category: 'ai',
        priority: 'medium',
        completed: false,
        aiGenerated: true,
        estimatedTime: '10 min',
        actionUrl: '/?tab=ai-asoc'
      });
    }

    // Add AI-suggested items based on response keywords
    if (response.toLowerCase().includes('mfa') || response.toLowerCase().includes('authentication')) {
      aiItems.push({
        id: 'ai-mfa-review',
        title: 'Review Multi-Factor Authentication Setup',
        description: 'AI detected potential MFA optimization opportunities',
        category: 'security',
        priority: 'medium',
        completed: false,
        aiGenerated: true,
        estimatedTime: '10 min',
        actionUrl: '/security-dashboard'
      });
    }

    return aiItems;
  };

  const getBaseChecklistItems = (): ChecklistItem[] => [
    {
      id: 'welcome-tour',
      title: 'Complete Platform Onboarding',
      description: 'Take the guided tour to understand all available features',
      category: 'setup',
      priority: 'high',
      completed: false,
      aiGenerated: false,
      estimatedTime: '20 min',
      actionUrl: '/dashboard'
    },
    {
      id: 'security-baseline',
      title: 'Establish Security Baseline',
      description: 'Configure your initial security settings and policies',
      category: 'security',
      priority: 'critical',
      completed: false,
      aiGenerated: false,
      estimatedTime: '30 min',
      actionUrl: '/security-dashboard'
    },
    {
      id: 'compliance-framework',
      title: 'Select Compliance Framework',
      description: 'Choose and configure CMMC, NIST, or other compliance standards',
      category: 'compliance',
      priority: 'high',
      completed: false,
      aiGenerated: false,
      estimatedTime: '25 min',
      actionUrl: '/security-dashboard'
    }
  ];

  const handleItemToggle = async (itemId: string) => {
    setItems(prev => prev.map(item => 
      item.id === itemId 
        ? { ...item, completed: !item.completed }
        : item
    ));
    
    onItemComplete?.(itemId);
    
    // Haptic feedback simulation
    if (navigator.vibrate) {
      navigator.vibrate(50);
    }
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    await generatePersonalizedChecklist();
    setRefreshing(false);
    
    toast({
      title: "Papyrus Refreshed",
      description: "Your personalized checklist has been updated",
    });
  };

  const filteredItems = activeCategory === 'all' 
    ? items 
    : items.filter(item => item.category === activeCategory);

  const completionPercentage = items.length > 0 
    ? Math.round((items.filter(item => item.completed).length / items.length) * 100)
    : 0;

  const criticalItems = items.filter(item => item.priority === 'critical' && !item.completed);

  return (
    <div className={`space-y-4 ${embedded ? 'h-full' : ''}`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <AdinkraSymbolDisplay 
              symbolName="Sankofa" 
              showMatrix={false} 
              showMeaning={false}
              className="w-6 h-6 flex-shrink-0"
            />
            <div className="min-w-0 flex-1">
              <h2 className={`font-bold truncate ${embedded ? 'text-lg' : 'text-2xl'}`}>
                Papyrus Wisdom
              </h2>
              <p className="text-xs text-muted-foreground truncate">
                AI-powered personalized guidance
              </p>
            </div>
          </div>
          {authState.isAuthenticated && (
            <Badge variant="outline" className="text-xs bg-primary/20 text-primary border-primary/30 flex-shrink-0">
              KHEPRA Enhanced
            </Badge>
          )}
        </div>
        
        <Button
          variant="ghost"
          size="sm"
          onClick={handleRefresh}
          disabled={refreshing}
          className="flex items-center space-x-1"
        >
          <RefreshCw className={`h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </Button>
      </div>

      {/* Progress Overview */}
      <Card className="card-cyber">
        <CardContent className="p-4">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Overall Progress</span>
              <span className="text-sm text-muted-foreground">{completionPercentage}%</span>
            </div>
            <Progress value={completionPercentage} className="h-2" />
            
            {criticalItems.length > 0 && (
              <div className="flex items-center space-x-2 text-xs">
                <AlertTriangle className="h-3 w-3 text-destructive" />
                <span className="text-destructive">
                  {criticalItems.length} critical item{criticalItems.length !== 1 ? 's' : ''} remaining
                </span>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Category Filter */}
      <div className="flex flex-wrap gap-1">
        {categories.map((category) => (
          <Button
            key={category.id}
            variant={activeCategory === category.id ? "default" : "outline"}
            size="sm"
            onClick={() => setActiveCategory(category.id)}
            className="flex items-center space-x-1 text-xs"
          >
            {category.icon}
            <span>{category.label}</span>
          </Button>
        ))}
      </div>

      {/* Checklist Items */}
      <ScrollArea className={embedded ? "h-96" : "h-[500px]"}>
        <div className="space-y-3 pr-4">
          {loading ? (
            <div className="text-center py-8">
              <Brain className="h-8 w-8 animate-pulse mx-auto mb-2 text-primary" />
              <p className="text-sm text-muted-foreground">
                AI is personalizing your guidance...
              </p>
            </div>
          ) : filteredItems.length === 0 ? (
            <div className="text-center py-8">
              <CheckCircle2 className="h-8 w-8 mx-auto mb-2 text-success" />
              <p className="text-sm text-muted-foreground">
                All items in this category are complete!
              </p>
            </div>
          ) : (
            filteredItems.map((item) => (
              <Card 
                key={item.id} 
                className={`card-cyber transition-all duration-200 hover:shadow-md ${
                  item.completed ? 'opacity-60' : ''
                }`}
              >
                <CardContent className="p-4">
                  <div className="flex items-start space-x-3">
                    <Checkbox
                      checked={item.completed}
                      onCheckedChange={() => handleItemToggle(item.id)}
                      className="mt-1"
                    />
                    
                     <div className="flex-1 space-y-2 min-w-0">
                      <div className="flex items-start justify-between gap-3">
                        <div className="space-y-1 min-w-0 flex-1">
                          <h4 className={`font-medium text-sm leading-tight ${
                            item.completed ? 'line-through text-muted-foreground' : ''
                          }`}>
                            {item.title}
                          </h4>
                          <p className="text-xs text-muted-foreground leading-relaxed">
                            {item.description}
                          </p>
                        </div>
                        
                         <div className="flex flex-col items-end gap-1 flex-shrink-0">
                          <Badge 
                            variant="outline" 
                            className={`text-xs whitespace-nowrap ${priorityColors[item.priority]}`}
                          >
                            {item.priority}
                          </Badge>
                          {item.aiGenerated && (
                            <Badge variant="outline" className="text-xs bg-primary/20 text-primary border-primary/30 whitespace-nowrap">
                              <Sparkles className="h-2 w-2 mr-1" />
                              AI
                            </Badge>
                          )}
                        </div>
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2 text-xs text-muted-foreground">
                          <Clock className="h-3 w-3" />
                          <span>{item.estimatedTime}</span>
                        </div>
                        
                        {item.actionUrl && !item.completed && (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-6 px-2 text-xs"
                            onClick={() => globalThis.location.href = item.actionUrl!}
                          >
                            Take Action
                          </Button>
                        )}
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </div>
      </ScrollArea>
    </div>
  );
};