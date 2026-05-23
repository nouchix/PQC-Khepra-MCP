
import { BackButton, SideNavigation, Breadcrumb } from '@/components/ui/navigation';
import { useUserProfile } from '@/hooks/useUserProfile';
import { Card, CardContent } from '@/components/ui/card';
import { FloatingAIAssistant } from '@/components/FloatingAIAssistant';

interface PageLayoutProps {
  children: React.ReactNode;
  title?: string;
  showBack?: boolean;
  customBackPath?: string;
  breadcrumbs?: Array<{ label: string; path?: string }>;
  showSidebar?: boolean;
  className?: string;
}

export const PageLayout: React.FC<PageLayoutProps> = ({
  children,
  title,
  showBack = true,
  customBackPath,
  breadcrumbs,
  showSidebar = true,
  className = ""
}) => {
  const { profile } = useUserProfile();

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted/20">
      <div className="container mx-auto px-4 py-6">
        <div className="flex gap-6">
          {/* Sidebar */}
          {showSidebar && (
            <div className="hidden lg:block w-64 space-y-4">
              <Card className="sticky top-6">
                <CardContent className="p-4">
                  <SideNavigation 
                    userRole={profile?.role}
                    isAdmin={profile?.master_admin || profile?.role === 'admin'}
                  />
                </CardContent>
              </Card>
            </div>
          )}

          {/* Main Content */}
          <div className={`flex-1 space-y-6 ${className}`}>
            {/* Navigation & Title */}
            <div className="space-y-4">
              {showBack && <BackButton customPath={customBackPath} />}
              {breadcrumbs && <Breadcrumb items={breadcrumbs} />}
              {title && (
                <h1 className="text-3xl font-bold bg-gradient-to-r from-primary to-primary/60 bg-clip-text text-transparent">
                  {title}
                </h1>
              )}
            </div>

            {/* Page Content */}
            {children}
          </div>
        </div>
      </div>
      
      {/* AI Assistant - Available on all pages */}
      <FloatingAIAssistant />
    </div>
  );
};