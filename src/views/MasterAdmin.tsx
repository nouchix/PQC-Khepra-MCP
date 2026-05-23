import { useEffect, useState } from "react";
import { useNavigate } from '@/lib/router-compat';
import { useAuth } from "@/hooks/useAuth";
import { useUserProfile } from "@/hooks/useUserProfile";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import UserTierManager from "@/components/admin/UserTierManager";
import { UnifiedAdminConsole } from "@/components/UnifiedAdminConsole";
import { UserManagement } from "@/components/UserManagement";
import { AuditLog } from "@/components/AuditLog";
import { Crown, Users, FileText, Scale, Activity, LogOut, Shield } from "lucide-react";

const MasterAdmin = () => {
  const { user, signOut } = useAuth();
  const { profile, loading: profileLoading } = useUserProfile();
  const navigate = useNavigate();

  // Check admin role using new secure role system
  const [hasAdminAccess, setHasAdminAccess] = useState(false);
  const [checkingAccess, setCheckingAccess] = useState(true);

  useEffect(() => {
    const checkAdminRole = async () => {
      if (!user) {
        navigate('/dashboard');
        return;
      }

      try {
        // Check user_roles table for master_admin status
        const { data: roleData, error: roleError } = await supabase
          .from('user_roles' as any)
          .select('is_master_admin')
          .eq('user_id', user.id)
          .maybeSingle();

        if (roleError) {
          console.error('Error checking user roles:', roleError);
        }

        let hasAccess = false;

        // Check user_roles table
        if ((roleData as any)?.is_master_admin) {
          hasAccess = true;
        }
        // Also check admin_roles table
        else {
          const { data: adminRoles } = await supabase
            .from('admin_roles')
            .select('role_type, is_active, expires_at')
            .eq('user_id', user.id)
            .eq('role_type', 'master_admin')
            .eq('is_active', true)
            .maybeSingle();

          if (adminRoles && (adminRoles.expires_at === null || new Date(adminRoles.expires_at) > new Date())) {
            hasAccess = true;
          }
        }

        setHasAdminAccess(hasAccess);
        
        if (!hasAccess) {
          navigate('/dashboard');
        }
      } catch (error) {
        console.error('Error checking admin access:', error);
        navigate('/dashboard');
      }
      
      setCheckingAccess(false);
    };

    if (!profileLoading) {
      checkAdminRole();
    }
  }, [profile, profileLoading, navigate, user]);

  if (profileLoading || checkingAccess) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 flex items-center justify-center">
        <div className="text-white">Loading...</div>
      </div>
    );
  }

  if (!hasAdminAccess) {
    return null;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 text-white">
      {/* Header */}
      <header className="border-b border-blue-500/20 bg-black/20 backdrop-blur-lg">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-4">
                <img 
                  src="/lovable-uploads/94f06ba5-2c93-4be0-a03f-e3fff4157ca6.png" 
                  alt="SouHimBou AI Logo" 
                  className="h-12 w-auto"
                />
                <div className="flex items-center space-x-2">
                  <h1 className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">
                    SouHimBou AI - Master Admin Console
                  </h1>
                  <span className="text-xs bg-red-600/20 text-red-400 px-2 py-1 rounded border border-red-500/30">
                    MASTER ADMIN
                  </span>
                </div>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <Button
                variant="outline"
                size="sm"
                onClick={() => navigate('/dashboard')}
                className="border-blue-500/30 text-blue-400 hover:bg-blue-500/20"
              >
                <Shield className="h-4 w-4 mr-2" />
                Platform Dashboard
              </Button>
              <div className="flex items-center space-x-2">
                <span className="text-sm text-gray-300">{user?.email}</span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => signOut()}
                  className="border-red-500/30 text-red-400 hover:bg-red-500/20"
                >
                  <LogOut className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-6 py-8">
        <div className="mb-6">
          <Card className="bg-gradient-to-r from-purple-600/20 to-blue-600/20 border border-purple-500/30">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2 text-white">
                <Crown className="h-6 w-6 text-yellow-400" />
                <span>Master Administrator Dashboard</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-300">
                Welcome to the Master Admin console. You have full access to all platform functions, 
                user management and system administration.
              </p>
            </CardContent>
          </Card>
        </div>

        <Tabs defaultValue="user-tiers" className="space-y-6">
          <TabsList className="bg-slate-800/50 border border-slate-700">
            <TabsTrigger value="user-tiers" className="flex items-center space-x-2">
              <Crown className="h-4 w-4" />
              <span>User Tier Management</span>
            </TabsTrigger>
            <TabsTrigger value="admin-console" className="flex items-center space-x-2">
              <Activity className="h-4 w-4" />
              <span>Admin Console</span>
            </TabsTrigger>
            <TabsTrigger value="users" className="flex items-center space-x-2">
              <Users className="h-4 w-4" />
              <span>User Management</span>
            </TabsTrigger>
            <TabsTrigger value="audit" className="flex items-center space-x-2">
              <FileText className="h-4 w-4" />
              <span>Audit Log</span>
            </TabsTrigger>
          </TabsList>

          <TabsContent value="user-tiers" className="space-y-6">
            <UserTierManager />
          </TabsContent>

          <TabsContent value="admin-console" className="space-y-6">
            <UnifiedAdminConsole />
          </TabsContent>

          <TabsContent value="users" className="space-y-6">
            <UserManagement />
          </TabsContent>


          <TabsContent value="audit" className="space-y-6">
            <AuditLog />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default MasterAdmin;