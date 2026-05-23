import { useState, useEffect } from 'react';
import { useUserProfile } from '@/hooks/useUserProfile';
import { useSecurityClearance, SecurityClearanceLevel } from '@/hooks/useSecurityClearance';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';
import { useUserRoles } from '@/hooks/useAuth';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Shield, Users, Clock, CheckCircle, XCircle, AlertTriangle } from 'lucide-react';

interface ClearanceRequest {
  id: string;
  user_id: string;
  current_clearance: string;
  requested_clearance: string;
  justification: string;
  status: 'pending' | 'approved' | 'denied';
  created_at: string;
  reviewed_at?: string;
  reviewed_by?: string;
  profiles?: {
    username: string;
    full_name: string;
  };
}

export const SecurityClearanceManager = () => {
  const { profile, isAdmin: isProfileAdmin } = useUserProfile();
  const { currentClearance } = useSecurityClearance();
  const { toast } = useToast();
  const { isAdmin: hasAdminRole, hasRole } = useUserRoles();
  
  // Use secure role system instead of profile-based check
  const isAdmin = () => hasAdminRole() || profile?.master_admin || false;

  const [clearanceRequests, setClearanceRequests] = useState<ClearanceRequest[]>([]);
  const [loading, setLoading] = useState(false);
  const [requestDialogOpen, setRequestDialogOpen] = useState(false);
  const [selectedClearance, setSelectedClearance] = useState<SecurityClearanceLevel>('CONFIDENTIAL');
  const [justification, setJustification] = useState('');

  const clearanceLevels: SecurityClearanceLevel[] = ['UNCLASSIFIED', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'];

  const fetchClearanceRequests = async () => {
    if (!isAdmin()) return;

    try {
      setLoading(true);
      const { data, error } = await supabase
        .from('audit_logs')
        .select(`
          id,
          user_id,
          details,
          created_at
        `)
        .eq('action', 'security_clearance_elevation_request')
        .order('created_at', { ascending: false })
        .limit(50);

      if (error) throw error;

      const requests = data?.map(log => ({
        id: log.id,
        user_id: log.user_id,
        current_clearance: (log.details as any)?.current_clearance || 'UNCLASSIFIED',
        requested_clearance: (log.details as any)?.requested_clearance || 'CONFIDENTIAL',
        justification: (log.details as any)?.justification || '',
        status: (log.details as any)?.status || 'pending',
        created_at: log.created_at,
        reviewed_at: (log.details as any)?.reviewed_at,
        reviewed_by: (log.details as any)?.reviewed_by,
        profiles: { username: 'Unknown', full_name: 'Unknown User' }
      })) || [];

      setClearanceRequests(requests);
    } catch (error) {
      console.error('Error fetching clearance requests:', error);
      toast({
        title: "Error",
        description: "Failed to fetch clearance requests",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const handleRequestSubmit = async () => {
    if (!profile || !justification.trim()) return;

    try {
      setLoading(true);
      
      const { error } = await supabase.from('audit_logs').insert({
        user_id: profile.user_id,
        action: 'security_clearance_elevation_request',
        resource_type: 'security_clearance',
        resource_id: profile.id,
        details: {
          current_clearance: currentClearance,
          requested_clearance: selectedClearance,
          justification: justification.trim(),
          status: 'pending',
          timestamp: new Date().toISOString()
        }
      });

      if (error) throw error;

      toast({
        title: "Request Submitted",
        description: "Your security clearance elevation request has been submitted for review"
      });

      setRequestDialogOpen(false);
      setJustification('');
      fetchClearanceRequests();
    } catch (error) {
      console.error('Error submitting request:', error);
      toast({
        title: "Error",
        description: "Failed to submit clearance request",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const handleRequestReview = async (requestId: string, status: 'approved' | 'denied', targetUserId: string, newClearance: string) => {
    if (!isAdmin()) return;

    try {
      setLoading(true);

      // Update the audit log with review decision
      const { error: auditError } = await supabase
        .from('audit_logs')
        .update({
          details: {
            status,
            reviewed_at: new Date().toISOString(),
            reviewed_by: profile?.user_id
          } as any
        })
        .eq('id', requestId);

      if (auditError) throw auditError;

      // If approved, update the user's security clearance
      if (status === 'approved') {
        const { error: profileError } = await supabase
          .from('profiles')
          .update({ security_clearance: newClearance })
          .eq('user_id', targetUserId);

        if (profileError) throw profileError;
      }

      toast({
        title: "Request Reviewed",
        description: `Clearance request has been ${status}`
      });

      fetchClearanceRequests();
    } catch (error) {
      console.error('Error reviewing request:', error);
      toast({
        title: "Error",
        description: "Failed to review clearance request",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isAdmin()) {
      fetchClearanceRequests();
    }
  }, [isAdmin]);

  const getClearanceBadgeVariant = (clearance: string) => {
    switch (clearance) {
      case 'TOP_SECRET': return 'destructive';
      case 'SECRET': return 'secondary';
      case 'CONFIDENTIAL': return 'outline';
      default: return 'default';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'approved': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'denied': return <XCircle className="h-4 w-4 text-red-500" />;
      default: return <Clock className="h-4 w-4 text-yellow-500" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Current Status Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Security Clearance Status
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Current Clearance Level</p>
              <Badge variant={getClearanceBadgeVariant(currentClearance)} className="mt-1">
                {currentClearance}
              </Badge>
            </div>
            
            {currentClearance !== 'TOP_SECRET' && (
              <Dialog open={requestDialogOpen} onOpenChange={setRequestDialogOpen}>
                <DialogTrigger asChild>
                  <Button variant="outline" className="flex items-center gap-2">
                    <Shield className="h-4 w-4" />
                    Request Elevation
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Security Clearance Elevation Request</DialogTitle>
                  </DialogHeader>
                  <div className="space-y-4">
                    <div>
                      <Label htmlFor="clearance-level">Requested Clearance Level</Label>
                      <Select value={selectedClearance} onValueChange={(value) => setSelectedClearance(value as SecurityClearanceLevel)}>
                        <SelectTrigger>
                          <SelectValue placeholder="Select clearance level" />
                        </SelectTrigger>
                        <SelectContent>
                          {clearanceLevels
                            .filter(level => level !== currentClearance)
                            .map(level => (
                              <SelectItem key={level} value={level}>
                                {level}
                              </SelectItem>
                            ))}
                        </SelectContent>
                      </Select>
                    </div>
                    
                    <div>
                      <Label htmlFor="justification">Justification</Label>
                      <Textarea
                        id="justification"
                        placeholder="Please provide a detailed justification for your clearance elevation request..."
                        value={justification}
                        onChange={(e) => setJustification(e.target.value)}
                        rows={4}
                      />
                    </div>
                    
                    <div className="flex justify-end gap-2">
                      <Button variant="outline" onClick={() => setRequestDialogOpen(false)}>
                        Cancel
                      </Button>
                      <Button 
                        onClick={handleRequestSubmit}
                        disabled={!justification.trim() || loading}
                      >
                        Submit Request
                      </Button>
                    </div>
                  </div>
                </DialogContent>
              </Dialog>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Admin Panel */}
      {isAdmin() && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Users className="h-5 w-5" />
              Clearance Requests Management
            </CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="flex items-center justify-center p-8">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
              </div>
            ) : clearanceRequests.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <AlertTriangle className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No clearance requests found</p>
              </div>
            ) : (
              <div className="space-y-4">
                {clearanceRequests.map((request) => (
                  <div key={request.id} className="border rounded-lg p-4">
                    <div className="flex items-start justify-between">
                      <div className="space-y-2">
                        <div className="flex items-center gap-2">
                          {getStatusIcon(request.status)}
                          <span className="font-medium">
                            {request.profiles?.full_name || request.profiles?.username || 'Unknown User'}
                          </span>
                        </div>
                        
                        <div className="flex items-center gap-2">
                          <Badge variant={getClearanceBadgeVariant(request.current_clearance)}>
                            {request.current_clearance}
                          </Badge>
                          <span className="text-muted-foreground">→</span>
                          <Badge variant={getClearanceBadgeVariant(request.requested_clearance)}>
                            {request.requested_clearance}
                          </Badge>
                        </div>
                        
                        <p className="text-sm text-muted-foreground">
                          {request.justification}
                        </p>
                        
                        <p className="text-xs text-muted-foreground">
                          Requested: {new Date(request.created_at).toLocaleDateString()}
                        </p>
                      </div>
                      
                      {request.status === 'pending' && (
                        <div className="flex gap-2">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleRequestReview(request.id, 'approved', request.user_id, request.requested_clearance)}
                            disabled={loading}
                          >
                            <CheckCircle className="h-4 w-4 mr-1" />
                            Approve
                          </Button>
                          <Button
                            size="sm"
                            variant="destructive"
                            onClick={() => handleRequestReview(request.id, 'denied', request.user_id, request.requested_clearance)}
                            disabled={loading}
                          >
                            <XCircle className="h-4 w-4 mr-1" />
                            Deny
                          </Button>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
};