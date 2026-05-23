import { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { 
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import { 
  Network, 
  Plus, 
  Edit, 
  Trash2, 
  Shield,
  AlertTriangle,
  CheckCircle2,
  Monitor,
  Lock,
  Eye
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';
import { useOrganization } from '@/hooks/useOrganization';

interface NetworkSegment {
  id: string;
  segment_name: string;
  segment_type: string;
  network_ranges: any;
  access_policies: any;
  monitoring_level: string;
  isolation_rules: any;
  allowed_protocols: any;
  micro_segmentation_enabled: boolean;
  created_at: string;
  updated_at: string;
}

const ZeroTrustNetworkSegmentation = () => {
  const [segments, setSegments] = useState<NetworkSegment[]>([]);
  const [loading, setLoading] = useState(false);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [newSegment, setNewSegment] = useState({
    segment_name: '',
    segment_type: 'semi_trusted' as const,
    network_ranges: [''],
    monitoring_level: 'standard' as const,
    allowed_protocols: ['HTTPS', 'SSH'],
    micro_segmentation_enabled: false
  });

  const { toast } = useToast();
  const { user } = useAuth();
  const { currentOrganization } = useOrganization();

  useEffect(() => {
    if (currentOrganization) {
      loadNetworkSegments();
    }
  }, [currentOrganization]);

  const loadNetworkSegments = async () => {
    if (!currentOrganization) return;

    setLoading(true);
    try {
      const { data, error } = await supabase
        .from('zero_trust_network_segments')
        .select('*')
        .eq('organization_id', currentOrganization.id)
        .order('created_at', { ascending: false });

      if (error) throw error;
      setSegments(data || []);
    } catch (error: any) {
      console.error('Error loading network segments:', error);
      toast({
        title: "Error Loading Segments",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const createSegment = async () => {
    if (!currentOrganization || !user) return;

    // Validate network ranges
    const validRanges = newSegment.network_ranges.filter(range => 
      range.trim() && isValidCIDR(range.trim())
    );

    if (validRanges.length === 0) {
      toast({
        title: "Invalid Network Ranges",
        description: "Please provide at least one valid CIDR network range.",
        variant: "destructive"
      });
      return;
    }

    setLoading(true);
    try {
      const { error } = await supabase
        .from('zero_trust_network_segments')
        .insert([{
          organization_id: currentOrganization.id,
          segment_name: newSegment.segment_name,
          segment_type: newSegment.segment_type,
          network_ranges: validRanges,
          monitoring_level: newSegment.monitoring_level,
          allowed_protocols: newSegment.allowed_protocols,
          micro_segmentation_enabled: newSegment.micro_segmentation_enabled,
          access_policies: getDefaultAccessPolicies(newSegment.segment_type),
          isolation_rules: getDefaultIsolationRules(newSegment.segment_type)
        }]);

      if (error) throw error;

      toast({
        title: "Network Segment Created",
        description: `Segment "${newSegment.segment_name}" has been created.`,
        variant: "default"
      });

      setShowCreateDialog(false);
      setNewSegment({
        segment_name: '',
        segment_type: 'semi_trusted',
        network_ranges: [''],
        monitoring_level: 'standard',
        allowed_protocols: ['HTTPS', 'SSH'],
        micro_segmentation_enabled: false
      });
      loadNetworkSegments();
    } catch (error: any) {
      console.error('Error creating segment:', error);
      toast({
        title: "Error Creating Segment",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const toggleMicroSegmentation = async (segment: NetworkSegment) => {
    setLoading(true);
    try {
      const { error } = await supabase
        .from('zero_trust_network_segments')
        .update({ micro_segmentation_enabled: !segment.micro_segmentation_enabled })
        .eq('id', segment.id);

      if (error) throw error;

      toast({
        title: "Micro-segmentation Updated",
        description: `Micro-segmentation has been ${!segment.micro_segmentation_enabled ? 'enabled' : 'disabled'}.`,
        variant: "default"
      });

      loadNetworkSegments();
    } catch (error: any) {
      console.error('Error updating segment:', error);
      toast({
        title: "Error Updating Segment",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const deleteSegment = async (segment: NetworkSegment) => {
    if (!confirm(`Are you sure you want to delete the segment "${segment.segment_name}"?`)) return;

    setLoading(true);
    try {
      const { error } = await supabase
        .from('zero_trust_network_segments')
        .delete()
        .eq('id', segment.id);

      if (error) throw error;

      toast({
        title: "Segment Deleted",
        description: `Segment "${segment.segment_name}" has been deleted.`,
        variant: "default"
      });

      loadNetworkSegments();
    } catch (error: any) {
      console.error('Error deleting segment:', error);
      toast({
        title: "Error Deleting Segment",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const isValidCIDR = (cidr: string): boolean => {
    const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    return cidrRegex.test(cidr);
  };

  const getDefaultAccessPolicies = (type: string) => {
    const policies = {
      trusted: {
        default_action: 'allow',
        require_authentication: false,
        logging_level: 'minimal'
      },
      semi_trusted: {
        default_action: 'conditional',
        require_authentication: true,
        logging_level: 'standard'
      },
      untrusted: {
        default_action: 'deny',
        require_authentication: true,
        logging_level: 'enhanced'
      },
      quarantine: {
        default_action: 'deny',
        require_authentication: true,
        logging_level: 'maximum',
        admin_override_required: true
      }
    };
    return policies[type as keyof typeof policies] || policies.semi_trusted;
  };

  const getDefaultIsolationRules = (type: string) => {
    const rules = {
      trusted: {
        inter_segment_communication: 'allow',
        internet_access: 'allow',
        admin_access: 'allow'
      },
      semi_trusted: {
        inter_segment_communication: 'conditional',
        internet_access: 'filtered',
        admin_access: 'allow'
      },
      untrusted: {
        inter_segment_communication: 'deny',
        internet_access: 'deny',
        admin_access: 'conditional'
      },
      quarantine: {
        inter_segment_communication: 'deny',
        internet_access: 'deny',
        admin_access: 'deny'
      }
    };
    return rules[type as keyof typeof rules] || rules.semi_trusted;
  };

  const getSegmentTypeColor = (type: string) => {
    const colors = {
      trusted: 'bg-green-500/10 text-green-400 border-green-500/20',
      semi_trusted: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
      untrusted: 'bg-red-500/10 text-red-400 border-red-500/20',
      quarantine: 'bg-purple-500/10 text-purple-400 border-purple-500/20'
    };
    return colors[type as keyof typeof colors] || colors.semi_trusted;
  };

  const getSegmentTypeIcon = (type: string) => {
    switch (type) {
      case 'trusted': return <CheckCircle2 className="h-4 w-4" />;
      case 'semi_trusted': return <Shield className="h-4 w-4" />;
      case 'untrusted': return <AlertTriangle className="h-4 w-4" />;
      case 'quarantine': return <Lock className="h-4 w-4" />;
      default: return <Network className="h-4 w-4" />;
    }
  };

  const getMonitoringBadge = (level: string) => {
    const variants = {
      minimal: 'outline',
      standard: 'secondary',
      enhanced: 'default',
      maximum: 'destructive'
    };
    return { variant: variants[level as keyof typeof variants] || 'outline', label: level };
  };

  const updateNetworkRange = (index: number, value: string) => {
    const updatedRanges = [...newSegment.network_ranges];
    updatedRanges[index] = value;
    setNewSegment(prev => ({ ...prev, network_ranges: updatedRanges }));
  };

  const addNetworkRange = () => {
    setNewSegment(prev => ({ 
      ...prev, 
      network_ranges: [...prev.network_ranges, ''] 
    }));
  };

  const removeNetworkRange = (index: number) => {
    if (newSegment.network_ranges.length > 1) {
      const updatedRanges = newSegment.network_ranges.filter((_, i) => i !== index);
      setNewSegment(prev => ({ ...prev, network_ranges: updatedRanges }));
    }
  };

  return (
    <div className="space-y-6">
      <Card className="card-cyber">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center space-x-2">
              <Network className="h-5 w-5" />
              <span>Network Segmentation</span>
            </CardTitle>
            <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
              <DialogTrigger asChild>
                <Button>
                  <Plus className="h-4 w-4 mr-2" />
                  Create Segment
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-lg">
                <DialogHeader>
                  <DialogTitle>Create Network Segment</DialogTitle>
                  <DialogDescription>
                    Define a new network segment with security policies and isolation rules.
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-4">
                  <div>
                    <Label htmlFor="segment-name">Segment Name</Label>
                    <Input
                      id="segment-name"
                      placeholder="Enter segment name"
                      value={newSegment.segment_name}
                      onChange={(e) => setNewSegment(prev => ({ ...prev, segment_name: e.target.value }))}
                    />
                  </div>
                  
                  <div>
                    <Label htmlFor="segment-type">Security Level</Label>
                    <Select
                      value={newSegment.segment_type}
                      onValueChange={(value: any) => setNewSegment(prev => ({ ...prev, segment_type: value }))}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="trusted">Trusted</SelectItem>
                        <SelectItem value="semi_trusted">Semi-Trusted</SelectItem>
                        <SelectItem value="untrusted">Untrusted</SelectItem>
                        <SelectItem value="quarantine">Quarantine</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div>
                    <Label>Network Ranges (CIDR)</Label>
                    {newSegment.network_ranges.map((range, index) => (
                      <div key={index} className="flex items-center space-x-2 mt-2">
                        <Input
                          placeholder="10.0.0.0/24"
                          value={range}
                          onChange={(e) => updateNetworkRange(index, e.target.value)}
                        />
                        {newSegment.network_ranges.length > 1 && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => removeNetworkRange(index)}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        )}
                      </div>
                    ))}
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={addNetworkRange}
                      className="mt-2"
                    >
                      <Plus className="h-4 w-4 mr-2" />
                      Add Range
                    </Button>
                  </div>

                  <div>
                    <Label htmlFor="monitoring-level">Monitoring Level</Label>
                    <Select
                      value={newSegment.monitoring_level}
                      onValueChange={(value: any) => setNewSegment(prev => ({ ...prev, monitoring_level: value }))}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="minimal">Minimal</SelectItem>
                        <SelectItem value="standard">Standard</SelectItem>
                        <SelectItem value="enhanced">Enhanced</SelectItem>
                        <SelectItem value="maximum">Maximum</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="flex items-center space-x-2">
                    <Switch
                      checked={newSegment.micro_segmentation_enabled}
                      onCheckedChange={(checked) => setNewSegment(prev => ({ ...prev, micro_segmentation_enabled: checked }))}
                    />
                    <Label>Enable Micro-segmentation</Label>
                  </div>

                  <div className="flex justify-end space-x-2">
                    <Button
                      variant="outline"
                      onClick={() => setShowCreateDialog(false)}
                    >
                      Cancel
                    </Button>
                    <Button
                      onClick={createSegment}
                      disabled={loading || !newSegment.segment_name}
                    >
                      Create Segment
                    </Button>
                  </div>
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {segments.length === 0 ? (
              <div className="text-center py-8">
                <Network className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                <h3 className="text-lg font-semibold mb-2">No Network Segments</h3>
                <p className="text-muted-foreground mb-4">
                  Create network segments to implement Zero Trust network security.
                </p>
                <Button onClick={() => setShowCreateDialog(true)}>
                  <Plus className="h-4 w-4 mr-2" />
                  Create First Segment
                </Button>
              </div>
            ) : (
              segments.map((segment) => (
                <Card key={segment.id} className="border-muted">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <div className={`p-2 rounded-lg border ${getSegmentTypeColor(segment.segment_type)}`}>
                          {getSegmentTypeIcon(segment.segment_type)}
                        </div>
                        <div>
                          <h3 className="font-semibold">{segment.segment_name}</h3>
                          <div className="flex items-center space-x-2 text-sm text-muted-foreground">
                            <span className="capitalize">{segment.segment_type.replaceAll('_', ' ')}</span>
                            <span>•</span>
                            <span>{segment.network_ranges.length} ranges</span>
                            {segment.micro_segmentation_enabled && (
                              <>
                                <span>•</span>
                                <span className="text-primary">Micro-segmented</span>
                              </>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Badge variant={getMonitoringBadge(segment.monitoring_level).variant as any}>
                          <Eye className="h-3 w-3 mr-1" />
                          {getMonitoringBadge(segment.monitoring_level).label}
                        </Badge>
                        <Switch
                          checked={segment.micro_segmentation_enabled}
                          onCheckedChange={() => toggleMicroSegmentation(segment)}
                          disabled={loading}
                        />
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => deleteSegment(segment)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                    
                    <div className="mt-3 pt-3 border-t border-muted">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                        <div>
                          <span className="font-medium">Network Ranges:</span>
                          <div className="mt-1">
                            {segment.network_ranges.map((range, index) => (
                              <code key={index} className="bg-muted px-2 py-1 rounded text-xs mr-2">
                                {range}
                              </code>
                            ))}
                          </div>
                        </div>
                        <div>
                          <span className="font-medium">Allowed Protocols:</span>
                          <div className="mt-1">
                            {segment.allowed_protocols.map((protocol, index) => (
                              <Badge key={index} variant="outline" className="mr-1 text-xs">
                                {protocol}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default ZeroTrustNetworkSegmentation;