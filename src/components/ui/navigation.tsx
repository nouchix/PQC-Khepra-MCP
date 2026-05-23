import { Fragment } from 'react';
import { useNavigate, useLocation } from '@/lib/router-compat';
import { Button } from '@/components/ui/button';
import {
  ArrowLeft,
  Home,
  Shield,
  FileText,
  Bot,
  Crown,
  Zap,
  BarChart3,

  Plug,
  Briefcase,
  Phone
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface NavigationItem {
  id: string;
  label: string;
  path: string;
  icon: React.ComponentType<{ className?: string }>;
  requiresAuth?: boolean;
  requiresAdmin?: boolean;
}

const navigationItems: NavigationItem[] = [
  { id: 'dashboard', label: 'Dashboard', path: '/dashboard', icon: Home, requiresAuth: true },
  { id: 'security', label: 'Security', path: '/security', icon: Shield, requiresAuth: true },
  { id: 'integrations', label: 'Integrations', path: '/integrations', icon: Plug, requiresAuth: true },
  { id: 'business-dev', label: 'Business Development', path: '/business-development', icon: Briefcase, requiresAuth: true },
  { id: 'automation', label: 'Automation', path: '/automation', icon: Bot, requiresAuth: true },
  { id: 'khepra', label: 'KHEPRA Protocol', path: '/khepra', icon: Zap, requiresAuth: true },
  { id: 'billing', label: 'Billing', path: '/billing', icon: BarChart3, requiresAuth: true },
  { id: 'admin', label: 'Admin', path: '/admin', icon: Crown, requiresAuth: true, requiresAdmin: true },
  { id: 'contact-sales', label: 'Contact Sales', path: '/contact-sales', icon: Phone, requiresAuth: false },
  { id: 'legal', label: 'Legal', path: '/legal', icon: FileText, requiresAuth: true },
];

interface BackButtonProps {
  className?: string;
  customPath?: string;
  customLabel?: string;
}

export const BackButton: React.FC<BackButtonProps> = ({
  className,
  customPath,
  customLabel = "Back"
}) => {
  const navigate = useNavigate();

  const handleBack = () => {
    if (customPath) {
      navigate(customPath);
    } else {
      navigate(-1);
    }
  };

  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={handleBack}
      className={cn("mb-4 text-muted-foreground hover:text-foreground", className)}
    >
      <ArrowLeft className="h-4 w-4 mr-2" />
      {customLabel}
    </Button>
  );
};

interface SideNavigationProps {
  className?: string;
  userRole?: string;
  isAdmin?: boolean;
}

export const SideNavigation: React.FC<SideNavigationProps> = ({
  className,
  isAdmin = false
}) => {
  const location = useLocation();
  const navigate = useNavigate();

  const filteredItems = navigationItems.filter(item => {
    if (item.requiresAdmin && !isAdmin) return false;
    return true;
  });

  const isActive = (path: string) => {
    return location.pathname === path ||
      (path !== '/dashboard' && location.pathname.startsWith(path));
  };

  return (
    <nav className={cn("space-y-2", className)}>
      {filteredItems.map((item) => {
        const Icon = item.icon;
        const active = isActive(item.path);

        return (
          <Button
            key={item.id}
            variant={active ? "secondary" : "ghost"}
            size="sm"
            onClick={() => navigate(item.path)}
            className={cn(
              "w-full justify-start",
              active && "bg-primary/10 text-primary border-primary/20"
            )}
          >
            <Icon className="h-4 w-4 mr-3" />
            {item.label}
          </Button>
        );
      })}
    </nav>
  );
};

interface BreadcrumbProps {
  items: Array<{
    label: string;
    path?: string;
  }>;
  className?: string;
}

export const Breadcrumb: React.FC<BreadcrumbProps> = ({ items, className }) => {
  const navigate = useNavigate();

  return (
    <nav className={cn("flex items-center space-x-2 text-sm text-muted-foreground mb-4", className)}>
      {items.map((item, index) => (
        <Fragment key={item.label}>
          {index > 0 && <span>/</span>}
          {item.path ? (
            <button
              onClick={() => item.path && navigate(item.path)}
              className="hover:text-foreground transition-colors"
            >
              {item.label}
            </button>
          ) : (
            <span className="text-foreground">{item.label}</span>
          )}
        </Fragment>
      ))}
    </nav>
  );
};