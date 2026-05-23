import { useState, useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useUserProfile } from '@/hooks/useUserProfile';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { FileText, Filter, Search, Calendar, User, Activity } from 'lucide-react';
import { format } from 'date-fns';

interface AuditLogEntry {
  id: string;
  user_id: string | null;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  details: any;
  ip_address: unknown | null;
  user_agent: string | null;
  created_at: string;
  profiles?: {
    username: string | null;
    full_name: string | null;
  };
}

export const AuditLog = () => {
  const { profile, canViewAllUsers } = useUserProfile();
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<'all' | 'user' | 'admin'>('all');
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    fetchAuditLogs();
  }, []);

  const fetchAuditLogs = async () => {
    try {
      setLoading(true);
      let query = supabase
        .from('audit_logs')
        .select(`*`)
        .order('created_at', { ascending: false })
        .limit(100);

      // If user is not admin, only show their own logs
      if (!canViewAllUsers()) {
        query = query.eq('user_id', profile?.user_id);
      }

      const { data: logsData, error } = await query;

      if (error) {
        console.error('Error fetching audit logs:', error);
        return;
      }

      // Fetch user profiles separately for logs that have user_ids
      const userIds = [...new Set(logsData?.map(log => log.user_id).filter(Boolean))];
      let profilesData: any[] = [];
      
      if (userIds.length > 0) {
        const { data: profiles } = await supabase
          .from('profiles')
          .select('user_id, username, full_name')
          .in('user_id', userIds);
        profilesData = profiles || [];
      }

      // Combine logs with profile data
      const logsWithProfiles = logsData?.map(log => ({
        ...log,
        profiles: log.user_id ? profilesData.find(p => p.user_id === log.user_id) : null
      })) || [];

      setLogs(logsWithProfiles as AuditLogEntry[]);
    } catch (error) {
      console.error('Error in fetchAuditLogs:', error);
    } finally {
      setLoading(false);
    }
  };

  const getActionBadgeVariant = (action: string) => {
    if (action.includes('login') || action.includes('signin')) return 'default';
    if (action.includes('logout') || action.includes('signout')) return 'secondary';
    if (action.includes('create') || action.includes('insert')) return 'default';
    if (action.includes('update') || action.includes('modify')) return 'outline';
    if (action.includes('delete') || action.includes('remove')) return 'destructive';
    return 'outline';
  };

  const filteredLogs = logs.filter(log => {
    const matchesSearch = searchTerm === '' || 
      log.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.resource_type?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.profiles?.username?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.profiles?.full_name?.toLowerCase().includes(searchTerm.toLowerCase());

    if (filter === 'all') return matchesSearch;
    if (filter === 'user') return matchesSearch && log.user_id === profile?.user_id;
    if (filter === 'admin') return matchesSearch && log.action.includes('admin');
    
    return matchesSearch;
  });

  return (
    <div className="space-y-6">
      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <FileText className="h-6 w-6 text-cyan-400" />
              <div>
                <CardTitle className="text-white">Audit Log</CardTitle>
                <CardDescription className="text-slate-400">
                  {canViewAllUsers() ? 'System-wide activity log' : 'Your activity log'}
                </CardDescription>
              </div>
            </div>
            <div className="flex items-center space-x-2">
              <div className="flex items-center space-x-2">
                <Search className="h-4 w-4 text-slate-400" />
                <Input
                  placeholder="Search logs..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-64 bg-slate-700 border-slate-600 text-white"
                />
              </div>
              {canViewAllUsers() && (
                <Select value={filter} onValueChange={(value: any) => setFilter(value)}>
                  <SelectTrigger className="w-32 bg-slate-700 border-slate-600 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All</SelectItem>
                    <SelectItem value="user">My Actions</SelectItem>
                    <SelectItem value="admin">Admin Actions</SelectItem>
                  </SelectContent>
                </Select>
              )}
              <Button
                variant="outline"
                size="sm"
                onClick={fetchAuditLogs}
                className="border-slate-600 text-slate-300"
              >
                <Activity className="h-4 w-4 mr-2" />
                Refresh
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center p-8">
              <div className="text-slate-400">Loading audit logs...</div>
            </div>
          ) : (
            <ScrollArea className="h-[600px]">
              <Table>
                <TableHeader>
                  <TableRow className="border-slate-700">
                    <TableHead className="text-slate-300">Timestamp</TableHead>
                    <TableHead className="text-slate-300">User</TableHead>
                    <TableHead className="text-slate-300">Action</TableHead>
                    <TableHead className="text-slate-300">Resource</TableHead>
                    <TableHead className="text-slate-300">IP Address</TableHead>
                    <TableHead className="text-slate-300">Details</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredLogs.map((log) => (
                    <TableRow key={log.id} className="border-slate-700">
                      <TableCell className="text-slate-300 font-mono text-sm">
                        <div className="flex items-center space-x-2">
                          <Calendar className="h-4 w-4 text-slate-500" />
                          <span>{format(new Date(log.created_at), 'MMM dd, HH:mm:ss')}</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center space-x-2">
                          <User className="h-4 w-4 text-slate-500" />
                          <div>
                            <div className="text-white text-sm">
                              {log.profiles?.full_name || log.profiles?.username || 'System'}
                            </div>
                            {log.profiles?.username && (
                              <div className="text-slate-400 text-xs">@{log.profiles.username}</div>
                            )}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={getActionBadgeVariant(log.action)}>
                          {log.action}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-slate-300">
                        {log.resource_type && (
                          <div className="text-sm">
                            <span className="text-cyan-400">{log.resource_type}</span>
                            {log.resource_id && (
                              <div className="text-slate-500 text-xs font-mono">
                                {log.resource_id.substring(0, 8)}...
                              </div>
                            )}
                          </div>
                        )}
                      </TableCell>
                      <TableCell className="text-slate-400 font-mono text-sm">
                        {log.ip_address ? String(log.ip_address) : 'N/A'}
                      </TableCell>
                      <TableCell className="text-slate-400 text-sm max-w-xs">
                        {log.details && (
                          <div className="truncate">
                            {typeof log.details === 'object' 
                              ? JSON.stringify(log.details).substring(0, 50) + '...'
                              : log.details.toString().substring(0, 50) + '...'
                            }
                          </div>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                  {filteredLogs.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center text-slate-400 py-8">
                        No audit logs found
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </ScrollArea>
          )}
        </CardContent>
      </Card>
    </div>
  );
};