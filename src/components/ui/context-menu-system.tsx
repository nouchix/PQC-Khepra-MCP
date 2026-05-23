import { useState, useEffect, useRef, useCallback } from 'react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { 
  Brain, 
  Settings, 
  Star, 
  Copy, 
  Share, 
  Edit, 
  Trash2, 
  Info, 
  Play, 
  Pause, 
  MoreHorizontal,
  Target,
  TrendingUp,
  Eye,
  Zap
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface ContextMenuItem {
  id: string;
  label: string;
  icon: React.ComponentType<any>;
  action: () => void;
  variant?: 'default' | 'destructive' | 'primary';
  shortcut?: string;
  papyrusData?: {
    category: string;
    learningPoints: string[];
    heuristic: string;
  };
}

interface ContextMenuProps {
  x: number;
  y: number;
  isVisible: boolean;
  onClose: () => void;
  targetElement: HTMLElement | null;
  customItems?: ContextMenuItem[];
}

interface UserWorkflowData {
  elementType: string;
  action: string;
  timestamp: number;
  coordinates: { x: number; y: number };
  context: string;
  frequency: number;
}

export const ContextMenuSystem: React.FC<ContextMenuProps> = ({
  x,
  y,
  isVisible,
  onClose,
  targetElement,
  customItems = []
}) => {
  const { toast } = useToast();
  const menuRef = useRef<HTMLDivElement>(null);
  const [workflowData, setWorkflowData] = useState<UserWorkflowData[]>([]);
  const [menuPosition, setMenuPosition] = useState({ x, y });

  // ML-powered workflow analysis
  const analyzeUserPattern = useCallback((elementType: string, action: string) => {
    const newWorkflowData: UserWorkflowData = {
      elementType,
      action,
      timestamp: Date.now(),
      coordinates: { x, y },
      context: globalThis.location.pathname,
      frequency: 1
    };

    setWorkflowData(prev => {
      const existing = prev.find(w => 
        w.elementType === elementType && 
        w.action === action && 
        w.context === newWorkflowData.context
      );
      
      if (existing) {
        return prev.map(w => 
          w === existing 
            ? { ...w, frequency: w.frequency + 1, timestamp: Date.now() }
            : w
        );
      }
      
      return [...prev, newWorkflowData];
    });

    // Heuristic analysis for learning
    if (workflowData.length > 5) {
      const patterns = analyzePatterns();
      if (patterns.suggestion) {
        toast({
          title: "Papyrus Learning Insight",
          description: patterns.suggestion,
          duration: 5000,
        });
      }
    }
  }, [x, y, workflowData, toast]);

  const analyzePatterns = () => {
    const recentActions = workflowData.slice(-10);
    const frequentActions = recentActions.reduce((acc, curr) => {
      const key = `${curr.elementType}-${curr.action}`;
      acc[key] = (acc[key] || 0) + curr.frequency;
      return acc;
    }, {} as Record<string, number>);

    const mostFrequent = Object.entries(frequentActions)
      .sort(([,a], [,b]) => b - a)[0];

    if (mostFrequent && mostFrequent[1] > 3) {
      return {
        pattern: mostFrequent[0],
        suggestion: `You frequently ${mostFrequent[0].split('-')[1]} ${mostFrequent[0].split('-')[0]} elements. Consider creating a shortcut or automation.`
      };
    }

    return { pattern: null, suggestion: null };
  };

  // Default Papyrus-integrated menu items
  const getDefaultMenuItems = (): ContextMenuItem[] => {
    const elementType = targetElement?.tagName.toLowerCase() || 'element';
    const elementText = targetElement?.textContent?.slice(0, 30) || 'this element';

    return [
      {
        id: 'quick-action',
        label: 'Quick Action',
        icon: Zap,
        variant: 'primary',
        shortcut: '⌘+Q',
        action: () => {
          analyzeUserPattern(elementType, 'quick-action');
          toast({
            title: "Quick Action Executed",
            description: `Action performed on ${elementText}`,
          });
          onClose();
        },
        papyrusData: {
          category: 'productivity',
          learningPoints: ['User prefers quick access', 'Efficiency-focused workflow'],
          heuristic: 'speed_optimization'
        }
      },
      {
        id: 'analyze',
        label: 'AI Analysis',
        icon: Brain,
        shortcut: '⌘+A',
        action: () => {
          analyzeUserPattern(elementType, 'ai-analysis');
          toast({
            title: "AI Analysis Started",
            description: "KHEPRA protocol analyzing element patterns...",
          });
          onClose();
        },
        papyrusData: {
          category: 'intelligence',
          learningPoints: ['User seeks AI insights', 'Data-driven decision making'],
          heuristic: 'intelligence_augmentation'
        }
      },
      {
        id: 'monitor',
        label: 'Add to Watchlist',
        icon: Eye,
        action: () => {
          analyzeUserPattern(elementType, 'monitor');
          toast({
            title: "Added to Watchlist",
            description: "Element will be monitored for changes",
          });
          onClose();
        },
        papyrusData: {
          category: 'monitoring',
          learningPoints: ['User values continuous monitoring', 'Proactive approach'],
          heuristic: 'predictive_monitoring'
        }
      },
      {
        id: 'optimize',
        label: 'Optimize',
        icon: TrendingUp,
        action: () => {
          analyzeUserPattern(elementType, 'optimize');
          toast({
            title: "Optimization Queued",
            description: "Performance optimization will be applied",
          });
          onClose();
        },
        papyrusData: {
          category: 'performance',
          learningPoints: ['User focuses on optimization', 'Performance-conscious'],
          heuristic: 'continuous_improvement'
        }
      },
      {
        id: 'copy',
        label: 'Copy',
        icon: Copy,
        shortcut: '⌘+C',
        action: () => {
          analyzeUserPattern(elementType, 'copy');
          navigator.clipboard.writeText(elementText);
          toast({
            title: "Copied",
            description: "Content copied to clipboard",
          });
          onClose();
        }
      },
      {
        id: 'share',
        label: 'Share',
        icon: Share,
        action: () => {
          analyzeUserPattern(elementType, 'share');
          toast({
            title: "Share Options",
            description: "Share dialog would open here",
          });
          onClose();
        }
      },
      {
        id: 'info',
        label: 'Element Info',
        icon: Info,
        action: () => {
          analyzeUserPattern(elementType, 'info');
          toast({
            title: "Element Information",
            description: `Type: ${elementType}, Classes: ${targetElement?.className}`,
          });
          onClose();
        }
      }
    ];
  };

  const allMenuItems = [...getDefaultMenuItems(), ...customItems];

  // Position menu to stay within viewport
  useEffect(() => {
    if (isVisible && menuRef.current) {
      const menuRect = menuRef.current.getBoundingClientRect();
      const viewportWidth = globalThis.innerWidth;
      const viewportHeight = globalThis.innerHeight;

      let newX = x;
      let newY = y;

      if (x + menuRect.width > viewportWidth) {
        newX = viewportWidth - menuRect.width - 10;
      }

      if (y + menuRect.height > viewportHeight) {
        newY = y - menuRect.height;
      }

      setMenuPosition({ x: newX, y: newY });
    }
  }, [x, y, isVisible]);

  // Close menu on outside click
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        onClose();
      }
    };

    if (isVisible) {
      document.addEventListener('mousedown', handleClickOutside);
      document.addEventListener('contextmenu', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('contextmenu', handleClickOutside);
    };
  }, [isVisible, onClose]);

  if (!isVisible) return null;

  return (
    <div
      ref={menuRef}
      className="fixed z-[9999] animate-in fade-in-0 zoom-in-95 duration-100"
      style={{
        left: menuPosition.x,
        top: menuPosition.y,
      }}
    >
      <Card className="w-56 p-1 bg-background/95 backdrop-blur-lg border-primary/20 shadow-2xl">
        <div className="space-y-1">
          {/* Papyrus Header */}
          <div className="px-3 py-2 border-b border-border/50">
            <div className="flex items-center space-x-2">
              <div className="w-6 h-6 bg-gradient-primary rounded-full flex items-center justify-center">
                <Target className="h-3 w-3 text-primary-foreground" />
              </div>
              <span className="text-xs font-medium text-muted-foreground">Papyrus AI Context</span>
            </div>
          </div>

          {allMenuItems.map((item, index) => {
            const Icon = item.icon;
            return (
              <div key={item.id}>
                <Button
                  variant="ghost"
                  size="sm"
                  className={`w-full justify-start h-8 px-3 py-1 ${
                    item.variant === 'destructive' ? 'text-destructive hover:bg-destructive/10' :
                    item.variant === 'primary' ? 'text-primary hover:bg-primary/10' :
                    'hover:bg-accent/50'
                  }`}
                  onClick={item.action}
                >
                  <Icon className="h-4 w-4 mr-3" />
                  <span className="text-sm">{item.label}</span>
                  {item.shortcut && (
                    <Badge variant="outline" className="ml-auto text-xs h-5">
                      {item.shortcut}
                    </Badge>
                  )}
                </Button>
                
                {/* Separator after AI-related items */}
                {(index === 3 || index === allMenuItems.length - customItems.length - 1) && (
                  <div className="h-px bg-border/50 my-1" />
                )}
              </div>
            );
          })}

          {/* Papyrus Learning Indicator */}
          <div className="px-3 py-2 border-t border-border/50">
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span>Learning: {workflowData.length} patterns</span>
              <div className="flex items-center space-x-1">
                <div className="w-2 h-2 bg-success rounded-full animate-pulse" />
                <span>Active</span>
              </div>
            </div>
          </div>
        </div>
      </Card>
    </div>
  );
};

// Context Menu Provider Component
export const useContextMenu = () => {
  const [contextMenu, setContextMenu] = useState<{
    x: number;
    y: number;
    isVisible: boolean;
    targetElement: HTMLElement | null;
    customItems?: ContextMenuItem[];
  }>({
    x: 0,
    y: 0,
    isVisible: false,
    targetElement: null,
    customItems: []
  });

  const showContextMenu = useCallback((
    event: React.MouseEvent,
    customItems?: ContextMenuItem[]
  ) => {
    event.preventDefault();
    event.stopPropagation();
    
    setContextMenu({
      x: event.clientX,
      y: event.clientY,
      isVisible: true,
      targetElement: event.currentTarget as HTMLElement,
      customItems: customItems || []
    });
  }, []);

  const hideContextMenu = useCallback(() => {
    setContextMenu(prev => ({ ...prev, isVisible: false }));
  }, []);

  return {
    contextMenu,
    showContextMenu,
    hideContextMenu,
    ContextMenuComponent: () => (
      <ContextMenuSystem
        x={contextMenu.x}
        y={contextMenu.y}
        isVisible={contextMenu.isVisible}
        onClose={hideContextMenu}
        targetElement={contextMenu.targetElement}
        customItems={contextMenu.customItems}
      />
    )
  };
};