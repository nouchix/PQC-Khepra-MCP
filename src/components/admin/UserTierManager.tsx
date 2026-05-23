import { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import { useUserTierManagement, UserTierInfo } from '@/hooks/useUserTierManagement';
import { useAuth, useUserRoles } from '@/hooks/useAuth';
import {
  Crown, 
  Users, 
  Shield, 
  AlertTriangle,
  CheckCircle,
  Clock
} from 'lucide-react';

const UserTierManager = () => {
  const { toast } = useToast();
  const { isMasterAdmin, switchUserTier, getAllUsers, loading } = useUserTierManagement();
  const { hasRole, isAdmin } = useUserRoles();
  const [users, setUsers] = useState<UserTierInfo[]>([]);
  const [usersLoading, setUsersLoading] = useState(false);
  const [selectedTiers, setSelectedTiers] = useState<Record<string, string>>({});

  const fetchUsers = async () => {
    if (!isMasterAdmin) return;
    
    setUsersLoading(true);
    try {
      const usersList = await getAllUsers();
      setUsers(usersList);
    } catch (error) {
      console.error('Error fetching users:', error);
      toast({
        title: "Error",
        description: "Failed to fetch users",
        variant: "destructive",
      });
    } finally {
      setUsersLoading(false);
    }
  };

  useEffect(() => {
    if (isMasterAdmin) {
      fetchUsers();
    }
  }, [isMasterAdmin]);

  const handleTierChange = async (userId: string, newTier: string) => {
    const success = await switchUserTier(userId, newTier);
    if (success) {
      // Refresh the users list
      fetchUsers();
      toast({
        title: "Success",
        description: `User tier updated to ${newTier}`,
      });
    }
  };

  const getTierBadge = (tier: string, isTrialActive?: boolean) => {
    switch (tier) {
      case 'enterprise':
        return <Badge className="bg-purple-600">Enterprise</Badge>;
      case 'professional':
        return <Badge className="bg-blue-600">Professional</Badge>;
      case 'basic':
        return <Badge variant="secondary">Basic</Badge>;
      case 'trial':
        return (
          <Badge variant={isTrialActive ? "default" : "destructive"}>
            Trial {isTrialActive ? '(Active)' : '(Expired)'}
          </Badge>
        );
      default:
        return <Badge variant="outline">Unknown</Badge>;
    }
  };

  const getRoleBadge = (role: string) => {
    switch (role) {
      case 'admin':
        return <Badge className="bg-orange-600">Admin</Badge>;
      case 'analyst':
        return <Badge className="bg-green-600">Analyst</Badge>;
      case 'operator':
        return <Badge className="bg-blue-600">Operator</Badge>;
      default:
        return <Badge variant="outline">Viewer</Badge>;
    }
  };

  const getTrialStatus = (user: any) => {
    if (!user.is_trial_active) return null;
    
    if (user.trial_ends_at) {
      const endDate = new Date(user.trial_ends_at);
      const now = new Date();
      const daysLeft = Math.ceil((endDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
      
      if (daysLeft <= 0) {
        return <span className="text-destructive text-sm">Trial Expired</span>;
      } else if (daysLeft <= 3) {
        return <span className="text-yellow-400 text-sm">Trial ends in {daysLeft} days</span>;
      } else {
        return <span className="text-green-400 text-sm">Trial ends in {daysLeft} days</span>;
      }
    }
    
    return <span className="text-blue-400 text-sm">Trial Active</span>;
  };

  // Check if user has admin privileges using secure role system
  if (!isMasterAdmin && !isAdmin()) {
    return (
      <Card className="card-cyber">
        <CardContent className="p-6">
          <div className="text-center">
            <Crown className="h-12 w-12 text-destructive mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-white mb-2">Admin Access Required</h3>
            <p className="text-muted-foreground">
              User tier management requires admin privileges.
            </p>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (usersLoading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="text-white">Loading users...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <Card className="card-cyber backdrop-blur-lg">
        <CardHeader className="border-b border-border/20">
          <div className="flex items-center space-x-3">
            <Crown className="h-8 w-8 text-primary" />
            <div>
              <CardTitle className="text-2xl bg-gradient-cyber bg-clip-text text-transparent">
                User Tier Management
              </CardTitle>
              <p className="text-muted-foreground">Master Admin: Switch user tiers for testing purposes</p>
            </div>
          </div>
        </CardHeader>

        <CardContent className="p-6">
          <div className="mb-6 p-4 bg-yellow-900/20 border border-yellow-600/30 rounded-lg">
            <div className="flex items-start space-x-2">
              <AlertTriangle className="h-5 w-5 text-yellow-400 mt-0.5" />
              <div>
                <h4 className="font-semibold text-yellow-400">Testing Environment</h4>
                <p className="text-sm text-yellow-300">
                  This interface allows the Master Admin to switch user tiers for testing platform capabilities. 
                  Use with caution in production environments.
                </p>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            {users.map((user) => (
              <Card key={user.user_id} className="card-glass">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-2">
                          <h3 className="font-semibold text-white">
                            {user.full_name || user.username || 'Unnamed User'}
                          </h3>
                          {getRoleBadge(user.role || 'viewer')}
                        </div>
                        <div className="flex items-center space-x-4 text-sm text-muted-foreground">
                          <span>Email: {user.email}</span>
                          <span>•</span>
                          <span>ID: {user.user_id}</span>
                        </div>
                        <div className="flex items-center space-x-4 mt-2">
                          {getTierBadge(user.plan_type || 'trial', user.is_trial_active)}
                          {getTrialStatus(user)}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Select
                        value={selectedTiers[user.user_id] || user.plan_type || 'trial'}
                        onValueChange={(value) => setSelectedTiers(prev => ({ ...prev, [user.user_id]: value }))}
                      >
                        <SelectTrigger className="w-40">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="trial">Trial</SelectItem>
                          <SelectItem value="basic">Basic</SelectItem>
                          <SelectItem value="professional">Professional</SelectItem>
                          <SelectItem value="enterprise">Enterprise</SelectItem>
                        </SelectContent>
                      </Select>
                      <Button
                        size="sm"
                        onClick={() => handleTierChange(user.user_id, selectedTiers[user.user_id] || user.plan_type || 'trial')}
                        disabled={loading}
                        className="bg-gradient-to-r from-blue-500 to-purple-500"
                      >
                        {loading ? (
                          <Clock className="h-4 w-4" />
                        ) : (
                          <>
                            <CheckCircle className="h-4 w-4 mr-1" />
                            Update
                          </>
                        )}
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
            {users.length === 0 && (
              <Card className="card-glass">
                <CardContent className="p-8 text-center">
                  <Users className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                  <h3 className="text-lg font-semibold text-white mb-2">No Users Found</h3>
                  <p className="text-muted-foreground">
                    No users are currently registered in the system.
                  </p>
                </CardContent>
              </Card>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Tier Information Card */}
      <Card className="card-cyber">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Shield className="h-5 w-5" />
            <span>Tier Capabilities</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-4 border border-border/20 rounded-lg">
              <h4 className="font-semibold text-white mb-2">Trial</h4>
              <ul className="text-sm text-muted-foreground space-y-1">
                <li>• 14-day access</li>
                <li>• Basic features</li>
                <li>• Limited analytics</li>
                <li>• Email support</li>
              </ul>
            </div>
            <div className="p-4 border border-border/20 rounded-lg">
              <h4 className="font-semibold text-white mb-2">Basic</h4>
              <ul className="text-sm text-muted-foreground space-y-1">
                <li>• Core features</li>
                <li>• Standard analytics</li>
                <li>• Email support</li>
                <li>• Basic integrations</li>
              </ul>
            </div>
            <div className="p-4 border border-border/20 rounded-lg">
              <h4 className="font-semibold text-white mb-2">Professional</h4>
              <ul className="text-sm text-muted-foreground space-y-1">
                <li>• Advanced features</li>
                <li>• Full analytics</li>
                <li>• Priority support</li>
                <li>• All integrations</li>
              </ul>
            </div>
            <div className="p-4 border border-border/20 rounded-lg">
              <h4 className="font-semibold text-white mb-2">Enterprise</h4>
              <ul className="text-sm text-muted-foreground space-y-1">
                <li>• All features</li>
                <li>• Custom analytics</li>
                <li>• 24/7 support</li>
                <li>• Custom integrations</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default UserTierManager;