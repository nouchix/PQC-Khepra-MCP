"use client";
import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';
import { CheckCircle, XCircle, Clock, AlertTriangle, User } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface ApprovalRequest {
  id: string;
  type: 'remediation' | 'configuration' | 'policy_change';
  title: string;
  description: string;
  requestedBy: string;
  requestedAt: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  status: 'pending' | 'approved' | 'rejected' | 'escalated';
  approvers: string[];
  requiredApprovals: number;
  currentApprovals: number;
  estimatedImpact: string;
  riskLevel: string;
}

export const ApprovalWorkflow = () => {
  const { toast } = useToast();
  const [selectedRequest, setSelectedRequest] = useState<ApprovalRequest | null>(null);
  const [approvalComment, setApprovalComment] = useState('');

  // No approval_requests (or equivalent) table exists in this project's
  // schema yet, so there is nothing real to fetch from Supabase. Rather
  // than fabricate pending approval requests, report an honest empty state
  // until a real backend for this workflow is implemented.
  const [approvalRequests, setApprovalRequests] = useState<ApprovalRequest[]>([]);

  const handleApproval = (requestId: string, action: 'approve' | 'reject') => {
    setApprovalRequests(prev => prev.map(req => {
      if (req.id === requestId) {
        const newApprovals = action === 'approve' ? req.currentApprovals + 1 : req.currentApprovals;
        const newStatus = action === 'reject' ? 'rejected' : 
                         newApprovals >= req.requiredApprovals ? 'approved' : 'pending';
        
        return {
          ...req,
          currentApprovals: newApprovals,
          status: newStatus as any
        };
      }
      return req;
    }));

    toast({
      title: action === 'approve' ? 'Request Approved' : 'Request Rejected',
      description: `Approval workflow updated successfully.`,
    });

    setSelectedRequest(null);
    setApprovalComment('');
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'critical': return 'destructive';
      case 'high': return 'destructive';
      case 'medium': return 'secondary';
      case 'low': return 'outline';
      default: return 'outline';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'approved': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'rejected': return <XCircle className="h-4 w-4 text-red-500" />;
      case 'escalated': return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      default: return <Clock className="h-4 w-4 text-blue-500" />;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold">Approval Workflow</h2>
        <Badge variant="outline" className="px-3 py-1">
          {approvalRequests.filter(r => r.status === 'pending').length} Pending Approvals
        </Badge>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Approval Requests List */}
        <div className="space-y-4">
          <h3 className="text-lg font-semibold">Pending Requests</h3>
          {approvalRequests.length === 0 && (
            <Card>
              <CardContent className="flex items-center justify-center h-32 text-muted-foreground text-sm">
                No approval requests. This workflow is not yet connected to a real backend.
              </CardContent>
            </Card>
          )}
          {approvalRequests.map((request) => (
            <Card 
              key={request.id} 
              className={`cursor-pointer transition-all hover:shadow-md ${
                selectedRequest?.id === request.id ? 'ring-2 ring-primary' : ''
              }`}
              onClick={() => setSelectedRequest(request)}
            >
              <CardHeader className="pb-3">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2">
                    {getStatusIcon(request.status)}
                    <CardTitle className="text-sm">{request.title}</CardTitle>
                  </div>
                  <Badge variant={getPriorityColor(request.priority)}>
                    {request.priority.toUpperCase()}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-3">
                  {request.description}
                </p>
                <div className="flex items-center gap-4 text-xs text-muted-foreground">
                  <div className="flex items-center gap-1">
                    <User className="h-3 w-3" />
                    {request.requestedBy}
                  </div>
                  <div>
                    Approvals: {request.currentApprovals}/{request.requiredApprovals}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Approval Details Panel */}
        <div>
          {selectedRequest ? (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  {getStatusIcon(selectedRequest.status)}
                  Approval Details
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <h4 className="font-medium mb-2">{selectedRequest.title}</h4>
                  <p className="text-sm text-muted-foreground">
                    {selectedRequest.description}
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs font-medium text-muted-foreground">Priority</label>
                    <Badge variant={getPriorityColor(selectedRequest.priority)} className="mt-1">
                      {selectedRequest.priority.toUpperCase()}
                    </Badge>
                  </div>
                  <div>
                    <label className="text-xs font-medium text-muted-foreground">Risk Level</label>
                    <p className="text-sm">{selectedRequest.riskLevel}</p>
                  </div>
                </div>

                <div>
                  <label className="text-xs font-medium text-muted-foreground">Estimated Impact</label>
                  <p className="text-sm">{selectedRequest.estimatedImpact}</p>
                </div>

                <div>
                  <label className="text-xs font-medium text-muted-foreground">Required Approvers</label>
                  <div className="flex gap-2 mt-1">
                    {selectedRequest.approvers.map((approver) => (
                      <Badge key={approver} variant="outline">
                        {approver}
                      </Badge>
                    ))}
                  </div>
                </div>

                <div>
                  <label className="text-xs font-medium text-muted-foreground">Approval Progress</label>
                  <div className="mt-1">
                    <div className="w-full bg-secondary rounded-full h-2">
                      <div 
                        className="bg-primary h-2 rounded-full transition-all" 
                        style={{ 
                          width: `${(selectedRequest.currentApprovals / selectedRequest.requiredApprovals) * 100}%` 
                        }}
                      />
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      {selectedRequest.currentApprovals} of {selectedRequest.requiredApprovals} approvals received
                    </p>
                  </div>
                </div>

                {selectedRequest.status === 'pending' && (
                  <div className="space-y-3 pt-4 border-t">
                    <div>
                      <label className="text-sm font-medium">Approval Comment</label>
                      <Textarea 
                        placeholder="Add your approval comments..."
                        value={approvalComment}
                        onChange={(e) => setApprovalComment(e.target.value)}
                        className="mt-1"
                      />
                    </div>
                    <div className="flex gap-2">
                      <Button 
                        onClick={() => handleApproval(selectedRequest.id, 'approve')}
                        className="flex-1"
                      >
                        <CheckCircle className="h-4 w-4 mr-2" />
                        Approve
                      </Button>
                      <Button 
                        onClick={() => handleApproval(selectedRequest.id, 'reject')}
                        variant="destructive"
                        className="flex-1"
                      >
                        <XCircle className="h-4 w-4 mr-2" />
                        Reject
                      </Button>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="flex items-center justify-center h-64 text-muted-foreground">
                Select an approval request to view details
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
};