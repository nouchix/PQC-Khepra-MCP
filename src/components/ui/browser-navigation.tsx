import { useState } from 'react';
import { useNavigate, useLocation } from '@/lib/router-compat';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  ChevronLeft, 
  ChevronRight, 
  RotateCcw, 
  Home, 
  Bookmark, 
  Settings, 
  HelpCircle, 
  ExternalLink,
  Plus,
  X,
  Star,
  Share,
  Download,
  Search,
  MoreHorizontal
} from 'lucide-react';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { Input } from '@/components/ui/input';

interface BrowserTab {
  id: string;
  title: string;
  path: string;
  isActive?: boolean;
  hasNotification?: boolean;
  notificationCount?: number;
}

interface BrowserNavigationProps {
  tabs: BrowserTab[];
  onTabChange?: (tabId: string) => void;
  onTabClose?: (tabId: string) => void;
  showAddTab?: boolean;
  title?: string;
  subtitle?: string;
  rightContent?: React.ReactNode;
}

export const BrowserNavigation: React.FC<BrowserNavigationProps> = ({
  tabs,
  onTabChange,
  onTabClose,
  showAddTab = true,
  title,
  subtitle,
  rightContent
}) => {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchValue, setSearchValue] = useState('');

  const handleBack = () => {
    globalThis.history.back();
  };

  const handleForward = () => {
    globalThis.history.forward();
  };

  const handleRefresh = () => {
    globalThis.location.reload();
  };

  const handleHome = () => {
    navigate('/dashboard');
  };

  const handleTabClick = (tab: BrowserTab) => {
    if (tab.path) {
      navigate(tab.path);
    }
    onTabChange?.(tab.id);
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchValue.trim()) {
      // Implement search functionality
      console.log('Searching for:', searchValue);
    }
  };

  const quickActions = [
    { label: 'Papyrus Guidance', icon: <HelpCircle className="h-4 w-4" />, action: () => navigate('/papyrus') },
    { label: 'Documentation', icon: <HelpCircle className="h-4 w-4" />, action: () => globalThis.open('/docs', '_blank') },
    { label: 'Support Center', icon: <ExternalLink className="h-4 w-4" />, action: () => globalThis.open('/support', '_blank') },
    { label: 'API Reference', icon: <ExternalLink className="h-4 w-4" />, action: () => globalThis.open('/api-docs', '_blank') },
    { label: 'System Status', icon: <ExternalLink className="h-4 w-4" />, action: () => globalThis.open('/status', '_blank') },
  ];

  const toolsMenu = [
    { label: 'Export Data', icon: <Download className="h-4 w-4" />, action: () => console.log('Export data') },
    { label: 'Share Page', icon: <Share className="h-4 w-4" />, action: () => console.log('Share page') },
    { label: 'Add Bookmark', icon: <Bookmark className="h-4 w-4" />, action: () => console.log('Add bookmark') },
    { label: 'Settings', icon: <Settings className="h-4 w-4" />, action: () => navigate('/settings') },
  ];

  return (
    <div className="bg-card border-b border-border/50 shadow-sm">
      {/* Top Navigation Bar */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-border/30">
        {/* Navigation Controls */}
        <div className="flex items-center space-x-2">
          <Button variant="ghost" size="sm" onClick={handleBack} className="h-8 w-8 p-0">
            <ChevronLeft className="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="sm" onClick={handleForward} className="h-8 w-8 p-0">
            <ChevronRight className="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="sm" onClick={handleRefresh} className="h-8 w-8 p-0">
            <RotateCcw className="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="sm" onClick={handleHome} className="h-8 w-8 p-0">
            <Home className="h-4 w-4" />
          </Button>
        </div>

        {/* Address/Search Bar */}
        <div className="flex-1 max-w-2xl mx-4">
          <form onSubmit={handleSearch} className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              value={searchValue}
              onChange={(e) => setSearchValue(e.target.value)}
              placeholder="Search features, documentation, or navigate to..."
              className="pl-10 h-8 bg-muted/50 border-border/50 focus:bg-background"
            />
          </form>
        </div>

        {/* Action Menu */}
        <div className="flex items-center space-x-2">
          <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
            <Star className="h-4 w-4" />
          </Button>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm" className="h-8 px-2">
                <HelpCircle className="h-4 w-4 mr-1" />
                Help
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56">
              {quickActions.map((action, index) => (
                <DropdownMenuItem key={index} onClick={action.action}>
                  {action.icon}
                  <span className="ml-2">{action.label}</span>
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56">
              {toolsMenu.map((tool, index) => (
                <DropdownMenuItem key={index} onClick={tool.action}>
                  {tool.icon}
                  <span className="ml-2">{tool.label}</span>
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      {/* Tab Bar */}
      <div className="flex items-center px-4 py-1 bg-muted/30">
        <div className="flex items-center space-x-1 flex-1 overflow-x-auto">
          {tabs.map((tab) => (
            <div
              key={tab.id}
              className={`flex items-center space-x-2 px-3 py-1.5 rounded-t-lg cursor-pointer transition-all duration-200 min-w-max group ${
                tab.isActive || location.pathname === tab.path
                  ? 'bg-background shadow-sm border-l border-r border-t border-border/50'
                  : 'hover:bg-background/50'
              }`}
              onClick={() => handleTabClick(tab)}
            >
              <span className="text-xs font-medium truncate max-w-32">{tab.title}</span>
              {tab.hasNotification && (
                <Badge variant="destructive" className="h-4 w-4 p-0 text-xs flex items-center justify-center">
                  {tab.notificationCount || '!'}
                </Badge>
              )}
              {onTabClose && tabs.length > 1 && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-4 w-4 p-0 opacity-0 group-hover:opacity-100 hover:bg-destructive/20"
                  onClick={(e) => {
                    e.stopPropagation();
                    onTabClose(tab.id);
                  }}
                >
                  <X className="h-2 w-2" />
                </Button>
              )}
            </div>
          ))}
          
          {showAddTab && (
            <Button variant="ghost" size="sm" className="h-6 w-6 p-0 ml-2">
              <Plus className="h-3 w-3" />
            </Button>
          )}
        </div>

        {/* Page Info & Right Content */}
        <div className="ml-4 flex items-center gap-4">
          {rightContent && (
            <div className="flex items-center">
              {rightContent}
            </div>
          )}
          {title && (
            <div className="text-right">
              <div className="text-xs font-medium text-foreground">{title}</div>
              {subtitle && (
                <div className="text-xs text-muted-foreground">{subtitle}</div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};