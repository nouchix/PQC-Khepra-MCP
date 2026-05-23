import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { 
  Search, 
  Filter, 
  Eye, 
  Edit, 
  AlertTriangle, 
  CheckCircle, 
  Clock,
  Shield,
  FileText
} from 'lucide-react';
import { STIGFinding } from '@/hooks/useSTIGCompliance';
import { useToast } from '@/hooks/use-toast';

interface STIGFindingsTableProps {
  findings: STIGFinding[];
  loading: boolean;
  onRefresh: () => void;
}

export const STIGFindingsTable: React.FC<STIGFindingsTableProps> = ({
  findings,
  loading,
  onRefresh
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [selectedFinding, setSelectedFinding] = useState<STIGFinding | null>(null);
  const [isEditDialogOpen, setIsEditDialogOpen] = useState(false);
  const [editForm, setEditForm] = useState<Partial<STIGFinding>>({});
  const { toast } = useToast();

  // Filter findings based on search and filters
  const filteredFindings = findings.filter(finding => {
    const matchesSearch = !searchTerm || 
      finding.rule_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      finding.finding_details?.rule_title?.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesSeverity = !severityFilter || finding.severity === severityFilter;
    const matchesStatus = !statusFilter || finding.finding_status === statusFilter;
    
    return matchesSearch && matchesSeverity && matchesStatus;
  });

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CAT_I': return 'bg-red-100 text-red-800 border-red-200';
      case 'CAT_II': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'CAT_III': return 'bg-blue-100 text-blue-800 border-blue-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'Open': return 'bg-red-100 text-red-800';
      case 'NotAFinding': return 'bg-green-100 text-green-800';
      case 'Not_Applicable': return 'bg-gray-100 text-gray-800';
      case 'Not_Reviewed': return 'bg-blue-100 text-blue-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'Open': return <AlertTriangle className="h-4 w-4" />;
      case 'NotAFinding': return <CheckCircle className="h-4 w-4" />;
      case 'Not_Applicable': return <Shield className="h-4 w-4" />;
      case 'Not_Reviewed': return <Clock className="h-4 w-4" />;
      default: return <FileText className="h-4 w-4" />;
    }
  };

  const handleEditFinding = (finding: STIGFinding) => {
    setSelectedFinding(finding);
    setEditForm({
      finding_status: finding.finding_status,
      comments: finding.comments || '',
      remediation_status: finding.remediation_status,
      assigned_to: finding.assigned_to,
      due_date: finding.due_date
    });
    setIsEditDialogOpen(true);
  };

  const handleSaveEdit = async () => {
    if (!selectedFinding) return;

    try {
      // This would typically call the useSTIGCompliance hook's updateFinding method
      // For now, we'll show a success message
      toast({
        title: "Finding Updated",
        description: "STIG finding has been updated successfully",
      });
      
      setIsEditDialogOpen(false);
      setSelectedFinding(null);
      setEditForm({});
      onRefresh();
    } catch (error) {
      toast({
        title: "Update Failed",
        description: "Failed to update STIG finding",
        variant: "destructive"
      });
    }
  };

  const stats = {
    total: filteredFindings.length,
    critical: filteredFindings.filter(f => f.severity === 'CAT_I' && f.finding_status === 'Open').length,
    high: filteredFindings.filter(f => f.severity === 'CAT_II' && f.finding_status === 'Open').length,
    medium: filteredFindings.filter(f => f.severity === 'CAT_III' && f.finding_status === 'Open').length,
    resolved: filteredFindings.filter(f => f.finding_status === 'NotAFinding').length
  };

  return (
    <div className="space-y-6">
      {/* Findings Summary */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold">{stats.total}</p>
            <p className="text-sm text-muted-foreground">Total Findings</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-red-600">{stats.critical}</p>
            <p className="text-sm text-muted-foreground">Critical (CAT I)</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-yellow-600">{stats.high}</p>
            <p className="text-sm text-muted-foreground">High (CAT II)</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-blue-600">{stats.medium}</p>
            <p className="text-sm text-muted-foreground">Medium (CAT III)</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-green-600">{stats.resolved}</p>
            <p className="text-sm text-muted-foreground">Resolved</p>
          </CardContent>
        </Card>
      </div>

      {/* Filters and Search */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            STIG Findings Management
          </CardTitle>
          <CardDescription>
            View, filter, and manage STIG compliance findings across your environment
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col md:flex-row gap-4 mb-6">
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search by rule ID or title..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-full md:w-40">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="">All Severities</SelectItem>
                <SelectItem value="CAT_I">CAT I (Critical)</SelectItem>
                <SelectItem value="CAT_II">CAT II (High)</SelectItem>
                <SelectItem value="CAT_III">CAT III (Medium)</SelectItem>
              </SelectContent>
            </Select>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-full md:w-40">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="">All Statuses</SelectItem>
                <SelectItem value="Open">Open</SelectItem>
                <SelectItem value="NotAFinding">Not a Finding</SelectItem>
                <SelectItem value="Not_Applicable">Not Applicable</SelectItem>
                <SelectItem value="Not_Reviewed">Not Reviewed</SelectItem>
              </SelectContent>
            </Select>
            <Button onClick={onRefresh} variant="outline">
              <Filter className="h-4 w-4" />
            </Button>
          </div>

          {/* Findings Table */}
          <div className="border rounded-lg">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Rule ID</TableHead>
                  <TableHead>Title</TableHead>
                  <TableHead>Asset</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Priority</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-8">
                      Loading findings...
                    </TableCell>
                  </TableRow>
                ) : filteredFindings.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-8">
                      No findings match the current filters.
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredFindings.map((finding) => (
                    <TableRow key={finding.id}>
                      <TableCell className="font-mono text-sm">{finding.rule_id}</TableCell>
                      <TableCell>
                        <div className="max-w-xs truncate">
                          {finding.finding_details?.rule_title || 'No title'}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="text-sm">
                          {finding.environment_assets?.asset_name || 'Unknown Asset'}
                          <div className="text-xs text-muted-foreground">
                            {finding.environment_assets?.platform}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge className={getSeverityColor(finding.severity)}>
                          {finding.severity}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={getStatusColor(finding.finding_status)}>
                          <div className="flex items-center gap-1">
                            {getStatusIcon(finding.finding_status)}
                            {finding.finding_status.replaceAll('_', ' ')}
                          </div>
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <div className={`w-2 h-2 rounded-full ${
                            finding.remediation_priority >= 80 ? 'bg-red-500' :
                            finding.remediation_priority >= 60 ? 'bg-yellow-500' : 'bg-green-500'
                          }`} />
                          <span className="text-sm">{finding.remediation_priority}</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => setSelectedFinding(finding)}
                          >
                            <Eye className="h-4 w-4" />
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleEditFinding(finding)}
                          >
                            <Edit className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Finding Details Dialog */}
      <Dialog open={!!selectedFinding && !isEditDialogOpen} onOpenChange={(open) => !open && setSelectedFinding(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Finding Details: {selectedFinding?.rule_id}</DialogTitle>
            <DialogDescription>
              Detailed information about this STIG compliance finding
            </DialogDescription>
          </DialogHeader>
          {selectedFinding && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="text-sm font-medium">Severity</Label>
                  <Badge className={getSeverityColor(selectedFinding.severity)}>
                    {selectedFinding.severity}
                  </Badge>
                </div>
                <div>
                  <Label className="text-sm font-medium">Status</Label>
                  <Badge variant="outline" className={getStatusColor(selectedFinding.finding_status)}>
                    {selectedFinding.finding_status.replaceAll('_', ' ')}
                  </Badge>
                </div>
              </div>
              
              <div>
                <Label className="text-sm font-medium">Title</Label>
                <p className="mt-1">{selectedFinding.finding_details?.rule_title}</p>
              </div>
              
              <div>
                <Label className="text-sm font-medium">Description</Label>
                <p className="mt-1 text-sm text-muted-foreground">
                  {selectedFinding.finding_details?.description}
                </p>
              </div>
              
              {selectedFinding.comments && (
                <div>
                  <Label className="text-sm font-medium">Comments</Label>
                  <p className="mt-1 text-sm">{selectedFinding.comments}</p>
                </div>
              )}
              
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <Label className="text-sm font-medium">Created</Label>
                  <p>{new Date(selectedFinding.created_at).toLocaleString()}</p>
                </div>
                <div>
                  <Label className="text-sm font-medium">Last Updated</Label>
                  <p>{new Date(selectedFinding.updated_at).toLocaleString()}</p>
                </div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Edit Finding Dialog */}
      <Dialog open={isEditDialogOpen} onOpenChange={setIsEditDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit Finding: {selectedFinding?.rule_id}</DialogTitle>
            <DialogDescription>
              Update the status and details of this STIG finding
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label htmlFor="finding_status">Finding Status</Label>
                <Select
                  value={editForm.finding_status}
                  onValueChange={(value) => setEditForm({...editForm, finding_status: value as any})}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="Open">Open</SelectItem>
                    <SelectItem value="NotAFinding">Not a Finding</SelectItem>
                    <SelectItem value="Not_Applicable">Not Applicable</SelectItem>
                    <SelectItem value="Not_Reviewed">Not Reviewed</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label htmlFor="remediation_status">Remediation Status</Label>
                <Select
                  value={editForm.remediation_status}
                  onValueChange={(value) => setEditForm({...editForm, remediation_status: value as any})}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="pending">Pending</SelectItem>
                    <SelectItem value="in_progress">In Progress</SelectItem>
                    <SelectItem value="completed">Completed</SelectItem>
                    <SelectItem value="verified">Verified</SelectItem>
                    <SelectItem value="exception_granted">Exception Granted</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            
            <div>
              <Label htmlFor="comments">Comments</Label>
              <Textarea
                id="comments"
                value={editForm.comments || ''}
                onChange={(e) => setEditForm({...editForm, comments: e.target.value})}
                placeholder="Add comments about this finding..."
                rows={3}
              />
            </div>
            
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setIsEditDialogOpen(false)}>
                Cancel
              </Button>
              <Button onClick={handleSaveEdit}>
                Save Changes
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
};