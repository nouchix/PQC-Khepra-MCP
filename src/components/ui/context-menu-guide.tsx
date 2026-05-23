import { useState, useRef, useEffect } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { 
  HelpCircle, 
  ExternalLink, 
  BookOpen, 
  Play, 
  Settings,
  ChevronRight,
  Lightbulb,
  Zap
} from 'lucide-react';

interface GuideMenuItem {
  label: string;
  description: string;
  action: () => void;
  icon: React.ReactNode;
  type: 'action' | 'link' | 'guide';
}

interface ContextMenuGuideProps {
  feature: string;
  description: string;
  menuItems: GuideMenuItem[];
  children: React.ReactNode;
  className?: string;
}

export const ContextMenuGuide: React.FC<ContextMenuGuideProps> = ({
  feature,
  description,
  menuItems,
  children,
  className = ""
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [position, setPosition] = useState({ x: 0, y: 0 });
  const menuRef = useRef<HTMLDivElement>(null);

  const handleContextMenu = (e: React.MouseEvent) => {
    e.preventDefault();
    setPosition({ x: e.clientX, y: e.clientY });
    setIsOpen(true);
  };

  const handleClick = () => {
    setIsOpen(!isOpen);
  };

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [isOpen]);

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'action': return <Zap className="h-3 w-3" />;
      case 'link': return <ExternalLink className="h-3 w-3" />;
      case 'guide': return <BookOpen className="h-3 w-3" />;
      default: return <ChevronRight className="h-3 w-3" />;
    }
  };

  return (
    <>
      <div 
        className={`cursor-pointer group ${className}`}
        onContextMenu={handleContextMenu}
        onClick={handleClick}
      >
        {children}
        <div className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity">
          <Badge variant="outline" className="text-xs bg-primary/10 border-primary/30">
            <HelpCircle className="h-2 w-2 mr-1" />
            Guide
          </Badge>
        </div>
      </div>

      {isOpen && (
        <div
          ref={menuRef}
          className="fixed z-50 animate-scale-in"
          style={{
            left: Math.min(position.x, globalThis.innerWidth - 320),
            top: Math.min(position.y, globalThis.innerHeight - 200)
          }}
        >
          <Card className="w-80 shadow-lg border-primary/20 bg-card/95 backdrop-blur-sm">
            <CardContent className="p-4">
              <div className="mb-3">
                <div className="flex items-center space-x-2 mb-1">
                  <Lightbulb className="h-4 w-4 text-primary" />
                  <h3 className="font-semibold text-sm">{feature}</h3>
                </div>
                <p className="text-xs text-muted-foreground">{description}</p>
              </div>

              <div className="space-y-1">
                {menuItems.map((item, index) => (
                  <Button
                    key={index}
                    variant="ghost"
                    className="w-full justify-start text-left h-auto p-2 hover:bg-primary/5"
                    onClick={() => {
                      item.action();
                      setIsOpen(false);
                    }}
                  >
                    <div className="flex items-start space-x-2 w-full">
                      <div className="flex-shrink-0 mt-0.5">
                        {item.icon}
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-medium">{item.label}</span>
                          {getTypeIcon(item.type)}
                        </div>
                        <p className="text-xs text-muted-foreground mt-0.5">
                          {item.description}
                        </p>
                      </div>
                    </div>
                  </Button>
                ))}
              </div>

              <div className="mt-3 pt-2 border-t border-border/50">
                <p className="text-xs text-muted-foreground text-center">
                  💡 Right-click or tap for quick guidance
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </>
  );
};