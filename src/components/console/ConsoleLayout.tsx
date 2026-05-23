import { useState } from 'react';
import { useAuth } from '@/hooks/useAuth';
import { useUserProfile } from '@/hooks/useUserProfile';
import { useOrganizationContext } from '@/components/OrganizationProvider';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Shield,
  Activity,
  Search,
  Bell,
  User,
  Menu,
  X,
  Globe,
  Lock,
  Brain,
  HelpCircle
} from 'lucide-react';
import { AdinkraSymbolDisplay } from '@/components/khepra/AdinkraSymbolDisplay';
import HeaderClock from '@/components/console/HeaderClock';
import SignOutDialog from '@/components/SignOutDialog';
import { FloatingAIAssistant } from '@/components/FloatingAIAssistant';
import { useNavigate } from '@/lib/router-compat';
import { BrowserNavigation } from '@/components/ui/browser-navigation';

interface ConsoleLayoutProps {
  children: React.ReactNode;
  currentSection?: string;
  browserNav?: {
    title?: string;
    subtitle?: string;
    tabs: { id: string; title: string; path: string; isActive?: boolean; hasNotification?: boolean; notificationCount?: number }[];
    showAddTab?: boolean;
    rightContent?: React.ReactNode;
  };
}

export const ConsoleLayout: React.FC<ConsoleLayoutProps> = ({
  children,
  currentSection = 'home',
  browserNav
}) => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const navigate = useNavigate();
  const { user, signOut } = useAuth();
  const { profile } = useUserProfile();
  const { currentOrganization } = useOrganizationContext();

  const navigationItems = [
    { id: 'stig-dashboard', label: 'STIG Dashboard', icon: Shield, path: '/stig-dashboard', symbol: 'Eban' },
    { id: 'asset-scanning', label: 'Asset Scanning', icon: Activity, path: '/asset-scanning', symbol: 'Sankofa' },
    { id: 'compliance-reports', label: 'Reports', icon: Globe, path: '/compliance-reports', symbol: 'Duafe' },
    { id: 'evidence-collection', label: 'Evidence', icon: Lock, path: '/evidence-collection', symbol: 'Nkyinkyim' },
    { id: 'billing', label: 'Billing', icon: Brain, path: '/billing', symbol: 'Fawohodie' },
    { id: 'help', label: 'Help & Support', icon: HelpCircle, path: '/vdp', symbol: 'Akoma' },
  ];

  const filteredNavItems = searchQuery
    ? navigationItems.filter(item =>
      item.label.toLowerCase().includes(searchQuery.toLowerCase())
    )
    : navigationItems;

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Top Navigation Bar */}
      <header className="h-16 bg-card border-b border-border flex items-center justify-between px-6 sticky top-0 z-50 backdrop-blur-sm" role="banner">
        <div className="flex items-center space-x-4">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setIsSidebarOpen(!isSidebarOpen)}
            className="lg:hidden"
            aria-label={isSidebarOpen ? 'Close sidebar' : 'Open sidebar'}
            aria-expanded={isSidebarOpen}
          >
            {isSidebarOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </Button>

          {/* Logo with Adinkra Animation */}
          <div className="flex items-center space-x-3">
            <div className="relative">
              <div className="w-8 h-8 bg-gradient-primary rounded-lg flex items-center justify-center animate-pulse-glow">
                <div className="w-6 h-6 text-primary-foreground font-bold">𝔸</div>
              </div>
              <div className="absolute -top-1 -right-1 w-3 h-3 bg-success rounded-full animate-pulse"></div>
            </div>
            <div>
              <h1 className="text-lg font-bold bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
                STIG Compliance Console
              </h1>
              <div className="flex items-center space-x-2">
                <Badge variant="secondary" className="text-xs">
                  {currentOrganization?.organization?.name || 'Default Organization'}
                </Badge>
                <Badge variant="outline" className="text-xs text-primary">
                  STIG Compliance
                </Badge>
              </div>
            </div>
          </div>
        </div>

        {/* Search Bar */}
        <div className="hidden md:flex items-center flex-1 max-w-md mx-8">
          <div className="relative w-full">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search services, resources..."
              aria-label="Search services and resources"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-input border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
            />
          </div>
        </div>

        {/* Top Right Controls */}
        <div className="flex items-center space-x-4">
          <div className="hidden lg:flex items-center space-x-4 text-sm text-muted-foreground">
            <div className="flex items-center space-x-1">
              <Activity className="h-4 w-4 text-success" />
              <span>System: Operational</span>
            </div>
            <div className="flex items-center space-x-1">
              <Globe className="h-4 w-4 text-primary" />
              <span>Region: US-East-1</span>
            </div>
            <HeaderClock />
          </div>

          <Button variant="ghost" size="sm" className="relative" aria-label="Notifications">
            <Bell className="h-5 w-5" />
          </Button>

          <div className="flex items-center space-x-2">
            <div className="w-8 h-8 bg-gradient-to-br from-primary to-accent rounded-full flex items-center justify-center">
              <User className="h-4 w-4 text-primary-foreground" />
            </div>
            <div className="hidden sm:block text-sm">
              <div className="font-medium">{user?.email}</div>
              <div className="text-xs text-muted-foreground">{profile?.role || 'user'}</div>
            </div>
          </div>

          <SignOutDialog onConfirm={() => signOut()} />
        </div>
      </header>

      <div className="flex h-[calc(100vh-4rem)]">
        {/* Sidebar */}
        <nav
          aria-label="Main navigation"
          className={`
            ${isSidebarOpen ? 'w-64' : 'w-16'} 
            bg-card border-r border-border transition-all duration-300 overflow-hidden
            ${isSidebarOpen ? 'lg:w-64' : 'lg:w-16'}
          `}
        >
          <div className="p-4 space-y-2">
            {filteredNavItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentSection === item.id;

              return (
                <div key={item.id} className="relative group">
                  <Button
                    variant={isActive ? "secondary" : "ghost"}
                    size="sm"
                    onClick={() => navigate(item.path)}
                    className={`
                      w-full justify-start relative overflow-hidden
                      ${isActive ? 'bg-primary/10 text-primary border border-primary/20' : ''}
                      ${!isSidebarOpen ? 'px-3' : ''}
                    `}
                  >
                    <Icon className="h-5 w-5 mr-3 flex-shrink-0" />
                    {isSidebarOpen && (
                      <span className="transition-opacity duration-200">
                        {item.label}
                      </span>
                    )}

                    {/* Adinkra Symbol Overlay */}
                    {isActive && (
                      <div className="absolute right-2 top-1/2 transform -translate-y-1/2 opacity-30">
                        <div className="w-4 h-4 text-primary animate-float">
                          <AdinkraSymbolDisplay
                            symbolName={item.symbol}
                            showMatrix={false}
                            showMeaning={false}
                            className="w-4 h-4"
                          />
                        </div>
                      </div>
                    )}
                  </Button>

                  {/* Tooltip for collapsed state */}
                  {!isSidebarOpen && (
                    <div className="absolute left-full ml-2 top-1/2 transform -translate-y-1/2 bg-popover border border-border rounded-md px-2 py-1 text-sm opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50">
                      {item.label}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Adinkra Wisdom Section */}
          {isSidebarOpen && (
            <div className="p-4 mt-8">
              <Card className="bg-gradient-to-br from-primary/5 to-accent/5 border-primary/20">
                <CardContent className="p-4">
                  <div className="text-center">
                    <div className="w-12 h-12 mx-auto mb-2 bg-gradient-primary rounded-lg flex items-center justify-center animate-pulse-glow">
                      <AdinkraSymbolDisplay
                        symbolName="Gye Nyame"
                        showMatrix={false}
                        showMeaning={false}
                        className="w-8 h-8 text-primary-foreground"
                      />
                    </div>
                    <p className="text-xs text-muted-foreground italic">
                      "Success depends upon preparedness"
                    </p>
                    <p className="text-xs text-primary mt-1 font-medium">
                      STIG Compliance Through Preparation
                    </p>
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </nav>

        {/* Main Content */}
        <main className="flex-1 overflow-auto bg-gradient-to-br from-background to-muted/20" role="main">
          {browserNav && (
            <BrowserNavigation
              tabs={browserNav.tabs}
              title={browserNav.title}
              subtitle={browserNav.subtitle}
              showAddTab={browserNav.showAddTab}
              rightContent={browserNav.rightContent}
            />
          )}

          {/* STIG Implementation Banner */}
          <div className="bg-gradient-to-r from-primary/20 to-accent/20 border-b border-primary/30 backdrop-blur-sm">
            <div className="px-6 py-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4">
                  <div className="flex items-center space-x-2">
                    <div className="w-10 h-10 bg-gradient-to-r from-primary to-accent rounded-lg flex items-center justify-center animate-pulse-glow">
                      <Shield className="h-6 w-6 text-white" />
                    </div>
                    <div>
                      <h2 className="text-lg font-bold text-primary">STIG-First Compliance Dashboard</h2>
                      <p className="text-sm text-muted-foreground">AI-powered CMMC-to-STIG implementation monitoring and automation</p>
                    </div>
                  </div>
                  <Badge variant="outline" className="bg-primary/10 text-primary border-primary/30">
                    STIG Compliance
                  </Badge>
                </div>
                <div className="flex items-center space-x-3">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => globalThis.location.reload()}
                  >
                    <Activity className="h-4 w-4 mr-2" />
                    Refresh
                  </Button>
                  <Button
                    onClick={() => navigate('/asset-scanning?runScan=true')}
                    className="bg-gradient-to-r from-primary to-accent hover:from-primary/80 hover:to-accent/80 text-white font-semibold"
                  >
                    <Shield className="h-4 w-4 mr-2" />
                    Run Scan
                  </Button>
                </div>
              </div>
            </div>
          </div>

          {children}
        </main>
      </div>

      {/* Floating AI Assistant */}
      <FloatingAIAssistant position="bottom-right" />
    </div>
  );
};