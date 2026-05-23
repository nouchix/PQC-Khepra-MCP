import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';
import { Crown, Shield, UserCheck, UserX, Calendar, Search } from 'lucide-react';

interface AdminRole {
  id: string;
  user_id: string;
  role_type: string;
  granted_by: string;
  granted_at: string;
  expires_at: string | null;
  is_active: boolean;
  metadata: any;
  user_email?: string;
  granted_by_email?: string;
}

const AdminRoleManager = () => {
  const [adminRoles, setAdminRoles] = useState<AdminRole[]>([]);
  const [loading, setLoading] = useState(true);
  const [newRoleEmail, setNewRoleEmail] = useState('');
  const [newRoleType, setNewRoleType] = useState<string>('security_admin');
  const [expirationDate, setExpirationDate] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const { toast } = useToast();

  const fetchAdminRoles = async () => {
    try {
      const { data, error } = await supabase
        .from('admin_roles')
        .select(`
          *,
          profiles!admin_roles_user_id_fkey(user_id, full_name),
          granted_by_profile:profiles!admin_roles_granted_by_fkey(user_id, full_name)
        `)
        .order('granted_at', { ascending: false });

      if (error) throw error;

      // Get user emails for display
      const rolesWithEmails = await Promise.all(
        (data || []).map(async (role) => {
          try {
            const { data: userData } = await supabase.auth.admin.getUserById(role.user_id);
            const { data: granterData } = role.granted_by 
              ? await supabase.auth.admin.getUserById(role.granted_by)
              : { data: null };
            
            return {
              ...role,
              user_email: userData.user?.email || 'Unknown',
              granted_by_email: granterData?.user?.email || 'System'
            };
          } catch {
            return {
              ...role,
              user_email: 'Unknown',
              granted_by_email: 'Unknown'
            };
          }
        })
      );

      setAdminRoles(rolesWithEmails);
    } catch (error: any) {
      toast({
        title: 'Error',
        description: 'Failed to fetch admin roles: ' + error.message,
        variant: 'destructive'
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAdminRoles();
  }, []);

  const handleGrantRole = async () => {
    if (!newRoleEmail || !newRoleType) {
      toast({
        title: 'Error',
        description: 'Please provide email and role type',
        variant: 'destructive'
      });
      return;
    }

    try {
      // Find user by email
      const { data: userData, error: userError } = await supabase
        .from('profiles')
        .select('user_id')
        .ilike('full_name', `%${newRoleEmail}%`)
        .maybeSingle();

      if (userError || !userData) {
        toast({
          title: 'Error',
          description: 'User not found with that email',
          variant: 'destructive'
        });
        return;
      }

      const roleData = {
        user_id: userData.user_id,
        role_type: newRoleType,
        expires_at: expirationDate || null,
        is_active: true,
        metadata: {
          granted_reason: 'Manual admin grant',
          granted_timestamp: new Date().toISOString()
        }
      };

      const { error } = await supabase
        .from('admin_roles')
        .insert(roleData);

      if (error) throw error;

      toast({
        title: 'Success',
        description: 'Admin role granted successfully',
        variant: 'default'
      });

      // Reset form
      setNewRoleEmail('');
      setNewRoleType('security_admin');
      setExpirationDate('');
      
      // Refresh the list
      fetchAdminRoles();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: 'Failed to grant admin role: ' + error.message,
        variant: 'destructive'
      });
    }
  };

  const handleRevokeRole = async (roleId: string) => {
    try {
      const { error } = await supabase
        .from('admin_roles')
        .update({ is_active: false })
        .eq('id', roleId);

      if (error) throw error;

      toast({
        title: 'Success',
        description: 'Admin role revoked successfully',
        variant: 'default'
      });

      fetchAdminRoles();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: 'Failed to revoke admin role: ' + error.message,
        variant: 'destructive'
      });
    }
  };

  const getRoleIcon = (roleType: string) => {
    switch (roleType) {
      case 'master_admin':
        return <Crown className="h-4 w-4 text-yellow-400" />;
      case 'system_admin':
        return <Shield className="h-4 w-4 text-blue-400" />;
      case 'security_admin':
        return <UserCheck className="h-4 w-4 text-green-400" />;
      default:
        return <UserCheck className="h-4 w-4" />;
    }
  };

  const getRoleColor = (roleType: string) => {
    switch (roleType) {
      case 'master_admin':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'system_admin':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'security_admin':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      default:
        return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  const filteredRoles = adminRoles.filter(role =>
    role.user_email?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    role.role_type.toLowerCase().includes(searchTerm.toLowerCase())
  );

  if (loading) {
    return (
      <Card className="bg-card/50 border-border">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Crown className="h-5 w-5 text-yellow-400" />
            <span>Admin Role Management</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center py-8">Loading admin roles...</div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Grant New Role Card */}
      <Card className="bg-card/50 border-border">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <UserCheck className="h-5 w-5 text-green-400" />
            <span>Grant Admin Role</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="space-y-2">
              <Label htmlFor="email">User Email</Label>
              <Input
                id="email"
                type="email"
                value={newRoleEmail}
                onChange={(e) => setNewRoleEmail(e.target.value)}
                placeholder="user@example.com"
                className="bg-input/50"
              />
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="role-type">Role Type</Label>
              <Select value={newRoleType} onValueChange={setNewRoleType}>
                <SelectTrigger className="bg-input/50">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="security_admin">Security Admin</SelectItem>
                  <SelectItem value="system_admin">System Admin</SelectItem>
                  <SelectItem value="master_admin">Master Admin</SelectItem>
                </SelectContent>
              </Select>
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="expiration">Expiration Date (Optional)</Label>
              <Input
                id="expiration"
                type="date"
                value={expirationDate}
                onChange={(e) => setExpirationDate(e.target.value)}
                className="bg-input/50"
              />
            </div>
          </div>
          
          <Button onClick={handleGrantRole} className="w-full">
            <UserCheck className="h-4 w-4 mr-2" />
            Grant Admin Role
          </Button>
        </CardContent>
      </Card>

      {/* Current Admin Roles */}
      <Card className="bg-card/50 border-border">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Crown className="h-5 w-5 text-yellow-400" />
            <span>Current Admin Roles</span>
          </CardTitle>
          <div className="flex items-center space-x-2">
            <Search className="h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search by email or role..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="max-w-sm bg-input/50"
            />
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {filteredRoles.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                No admin roles found
              </div>
            ) : (
              filteredRoles.map((role) => (
                <div
                  key={role.id}
                  className="flex items-center justify-between p-4 rounded-lg border border-border bg-muted/20"
                >
                  <div className="flex items-center space-x-4">
                    {getRoleIcon(role.role_type)}
                    <div>
                      <div className="font-medium">{role.user_email}</div>
                      <div className="text-sm text-muted-foreground">
                        Granted by: {role.granted_by_email}
                      </div>
                      <div className="text-xs text-muted-foreground">
                        <Calendar className="h-3 w-3 inline mr-1" />
                        {new Date(role.granted_at).toLocaleDateString()}
                        {role.expires_at && (
                          <span className="ml-2">
                            | Expires: {new Date(role.expires_at).toLocaleDateString()}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-2">
                    <Badge className={getRoleColor(role.role_type)}>
                      {role.role_type.replaceAll('_', ' ')}
                    </Badge>
                    
                    {role.is_active ? (
                      <Badge className="bg-green-500/20 text-green-400 border-green-500/30">
                        Active
                      </Badge>
                    ) : (
                      <Badge className="bg-red-500/20 text-red-400 border-red-500/30">
                        Revoked
                      </Badge>
                    )}
                    
                    {role.is_active && (
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => handleRevokeRole(role.id)}
                      >
                        <UserX className="h-4 w-4 mr-1" />
                        Revoke
                      </Button>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default AdminRoleManager;