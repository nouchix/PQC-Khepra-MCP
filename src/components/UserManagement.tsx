import { useState } from 'react';
import { useUserManagement } from '@/hooks/useUserManagement';
import { useUserProfile } from '@/hooks/useUserProfile';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { Users, UserPlus, Edit, Shield, Crown } from 'lucide-react';

const userFormSchema = z.object({
  email: z.string().email('Valid email is required'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  username: z.string().min(1, 'Username is required'),
  full_name: z.string().min(1, 'Full name is required'),
  security_clearance: z.enum(['UNCLASSIFIED', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET']),
  department: z.string().optional(),
  role: z.enum(['admin', 'analyst', 'operator', 'viewer']),
  master_admin: z.boolean().default(false),
});

type UserFormData = z.infer<typeof userFormSchema>;

export const UserManagement = () => {
  const { users, loading, updateUserProfile, createUserProfile } = useUserManagement();
  const { profile, canManageUsers } = useUserProfile();
  const [selectedUser, setSelectedUser] = useState<any>(null);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);

  const form = useForm<UserFormData>({
    resolver: zodResolver(userFormSchema),
    defaultValues: {
      username: '',
      full_name: '',
      security_clearance: 'UNCLASSIFIED',
      department: '',
      role: 'viewer',
      master_admin: false,
    },
  });

  const createForm = useForm<UserFormData>({
    resolver: zodResolver(userFormSchema),
    defaultValues: {
      email: '',
      password: '',
      username: '',
      full_name: '',
      security_clearance: 'UNCLASSIFIED',
      department: 'Engineering',
      role: 'analyst',
      master_admin: false,
    },
  });

  const onEditUser = (user: any) => {
    setSelectedUser(user);
    form.reset({
      username: user.username || '',
      full_name: user.full_name || '',
      security_clearance: user.security_clearance || 'UNCLASSIFIED',
      department: user.department || '',
      role: user.role || 'viewer',
      master_admin: user.master_admin || false,
    });
    setEditDialogOpen(true);
  };

  const onSubmit = async (data: UserFormData) => {
    if (!selectedUser) return;

    const success = await updateUserProfile(selectedUser.user_id, data);
    if (success) {
      setEditDialogOpen(false);
      setSelectedUser(null);
      form.reset();
    }
  };

  const onCreateSubmit = async (data: UserFormData) => {
    const success = await createUserProfile({
      email: data.email,
      password: data.password,
      username: data.username,
      full_name: data.full_name,
      security_clearance: data.security_clearance,
      department: data.department,
      role: data.role,
      master_admin: data.master_admin,
    });
    
    if (success) {
      setCreateDialogOpen(false);
      createForm.reset();
    }
  };

  const getRoleBadgeVariant = (role: string) => {
    switch (role) {
      case 'admin': return 'destructive';
      case 'analyst': return 'default';
      case 'operator': return 'secondary';
      default: return 'outline';
    }
  };

  const getClearanceBadgeVariant = (clearance: string) => {
    switch (clearance) {
      case 'TOP_SECRET': return 'destructive';
      case 'SECRET': return 'default';
      case 'CONFIDENTIAL': return 'secondary';
      default: return 'outline';
    }
  };

  if (!canManageUsers()) {
    return (
      <div className="flex items-center justify-center p-8">
        <Card className="w-full max-w-md bg-slate-800/50 border-slate-700">
          <CardContent className="flex flex-col items-center justify-center p-6">
            <Shield className="h-16 w-16 text-red-400 mb-4" />
            <h3 className="text-lg font-semibold text-white mb-2">Access Denied</h3>
            <p className="text-slate-400 text-center">
              You don't have permission to access user management features.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Users className="h-6 w-6 text-cyan-400" />
              <div>
                <CardTitle className="text-white">User Management</CardTitle>
                <CardDescription className="text-slate-400">
                  Manage user accounts, roles, and permissions
                </CardDescription>
              </div>
            </div>
            <Button
              size="sm"
              className="bg-cyan-600 hover:bg-cyan-700"
              onClick={() => setCreateDialogOpen(true)}
            >
              <UserPlus className="h-4 w-4 mr-2" />
              Add User
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center p-8">
              <div className="text-slate-400">Loading users...</div>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="border-slate-700">
                  <TableHead className="text-slate-300">User</TableHead>
                  <TableHead className="text-slate-300">Role</TableHead>
                  <TableHead className="text-slate-300">Clearance</TableHead>
                  <TableHead className="text-slate-300">Department</TableHead>
                  <TableHead className="text-slate-300">Status</TableHead>
                  <TableHead className="text-slate-300">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((user) => (
                  <TableRow key={user.id} className="border-slate-700">
                    <TableCell>
                      <div className="flex items-center space-x-3">
                        <div>
                          <div className="font-medium text-white flex items-center space-x-2">
                            <span>{user.full_name || user.username || 'Unknown'}</span>
                            {user.master_admin && (
                              <Crown className="h-4 w-4 text-yellow-400" />
                            )}
                          </div>
                          <div className="text-sm text-slate-400">@{user.username}</div>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant={getRoleBadgeVariant(user.role || 'viewer')}>
                        {user.role || 'viewer'}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant={getClearanceBadgeVariant(user.security_clearance || 'UNCLASSIFIED')}>
                        {user.security_clearance || 'UNCLASSIFIED'}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-slate-300">
                      {user.department || 'Unassigned'}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-green-400 border-green-400">
                        Active
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => onEditUser(user)}
                        className="text-cyan-400 hover:text-cyan-300"
                      >
                        <Edit className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Dialog open={editDialogOpen} onOpenChange={setEditDialogOpen}>
        <DialogContent className="bg-slate-800 border-slate-700">
          <DialogHeader>
            <DialogTitle className="text-white">Edit User Profile</DialogTitle>
            <DialogDescription className="text-slate-400">
              Update user information, role, and permissions.
            </DialogDescription>
          </DialogHeader>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <FormField
                  control={form.control}
                  name="username"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="text-slate-300">Username</FormLabel>
                      <FormControl>
                        <Input {...field} className="bg-slate-700 border-slate-600 text-white" />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="full_name"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="text-slate-300">Full Name</FormLabel>
                      <FormControl>
                        <Input {...field} className="bg-slate-700 border-slate-600 text-white" />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <FormField
                  control={form.control}
                  name="role"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="text-slate-300">Role</FormLabel>
                      <Select onValueChange={field.onChange} defaultValue={field.value}>
                        <FormControl>
                          <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                            <SelectValue placeholder="Select role" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="viewer">Viewer</SelectItem>
                          <SelectItem value="operator">Operator</SelectItem>
                          <SelectItem value="analyst">Analyst</SelectItem>
                          <SelectItem value="admin">Admin</SelectItem>
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="security_clearance"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="text-slate-300">Security Clearance</FormLabel>
                      <Select onValueChange={field.onChange} defaultValue={field.value}>
                        <FormControl>
                          <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                            <SelectValue placeholder="Select clearance" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="UNCLASSIFIED">UNCLASSIFIED</SelectItem>
                          <SelectItem value="CONFIDENTIAL">CONFIDENTIAL</SelectItem>
                          <SelectItem value="SECRET">SECRET</SelectItem>
                          <SelectItem value="TOP_SECRET">TOP SECRET</SelectItem>
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              <FormField
                control={form.control}
                name="department"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-slate-300">Department</FormLabel>
                    <FormControl>
                      <Input {...field} className="bg-slate-700 border-slate-600 text-white" />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              {profile?.master_admin && (
                <FormField
                  control={form.control}
                  name="master_admin"
                  render={({ field }) => (
                    <FormItem className="flex flex-row items-center justify-between rounded-lg border border-slate-600 p-4">
                      <div className="space-y-0.5">
                        <FormLabel className="text-base text-slate-300">Master Admin</FormLabel>
                        <div className="text-sm text-slate-400">
                          Grant master administrator privileges
                        </div>
                      </div>
                      <FormControl>
                        <Switch
                          checked={field.value}
                          onCheckedChange={field.onChange}
                        />
                      </FormControl>
                    </FormItem>
                  )}
                />
              )}

              <div className="flex justify-end space-x-2 pt-4">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setEditDialogOpen(false)}
                  className="border-slate-600 text-slate-300"
                >
                  Cancel
                </Button>
                <Button type="submit" className="bg-cyan-600 hover:bg-cyan-700">
                  Save Changes
                </Button>
              </div>
            </form>
          </Form>
        </DialogContent>
      </Dialog>

      {/* Create User Dialog */}
      <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
        <DialogContent className="bg-slate-800 border-slate-700">
          <DialogHeader>
            <DialogTitle className="text-white">Create New User</DialogTitle>
            <DialogDescription className="text-slate-400">
              Add a new engineer account for beta testing.
            </DialogDescription>
          </DialogHeader>
          <Form {...createForm}>
            <form onSubmit={createForm.handleSubmit(onCreateSubmit)} className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <FormField
                  control={createForm.control}
                  name="email"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="text-slate-300">Email</FormLabel>
                      <FormControl>
                        <Input {...field} type="email" className="bg-slate-700 border-slate-600 text-white" placeholder="engineer@secred.com" />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={createForm.control}
                  name="password"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="text-slate-300">Password</FormLabel>
                      <FormControl>
                        <Input {...field} type="password" className="bg-slate-700 border-slate-600 text-white" placeholder="temp123!@#" />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <FormField
                  control={createForm.control}
                  name="username"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="text-slate-300">Username</FormLabel>
                      <FormControl>
                        <Input {...field} className="bg-slate-700 border-slate-600 text-white" placeholder="engineer1" />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={createForm.control}
                  name="full_name"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="text-slate-300">Full Name</FormLabel>
                      <FormControl>
                        <Input {...field} className="bg-slate-700 border-slate-600 text-white" placeholder="Engineer One" />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <FormField
                  control={createForm.control}
                  name="role"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="text-slate-300">Role</FormLabel>
                      <Select onValueChange={field.onChange} defaultValue={field.value}>
                        <FormControl>
                          <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                            <SelectValue placeholder="Select role" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="viewer">Viewer</SelectItem>
                          <SelectItem value="operator">Operator</SelectItem>
                          <SelectItem value="analyst">Analyst</SelectItem>
                          <SelectItem value="admin">Admin</SelectItem>
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={createForm.control}
                  name="security_clearance"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="text-slate-300">Security Clearance</FormLabel>
                      <Select onValueChange={field.onChange} defaultValue={field.value}>
                        <FormControl>
                          <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                            <SelectValue placeholder="Select clearance" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="UNCLASSIFIED">UNCLASSIFIED</SelectItem>
                          <SelectItem value="CONFIDENTIAL">CONFIDENTIAL</SelectItem>
                          <SelectItem value="SECRET">SECRET</SelectItem>
                          <SelectItem value="TOP_SECRET">TOP SECRET</SelectItem>
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              <FormField
                control={createForm.control}
                name="department"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-slate-300">Department</FormLabel>
                    <FormControl>
                      <Input {...field} className="bg-slate-700 border-slate-600 text-white" placeholder="Engineering" />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <div className="flex justify-end space-x-2 pt-4">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setCreateDialogOpen(false)}
                  className="border-slate-600 text-slate-300"
                >
                  Cancel
                </Button>
                <Button type="submit" className="bg-cyan-600 hover:bg-cyan-700">
                  Create User
                </Button>
              </div>
            </form>
          </Form>
        </DialogContent>
      </Dialog>
    </div>
  );
};