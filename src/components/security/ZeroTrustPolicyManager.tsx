import { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
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
  Shield, 
  Plus, 
  Edit, 
  Trash2, 
  Settings,
  Lock,
  Network,
  Eye,
  AlertTriangle
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';
import { useOrganization } from '@/hooks/useOrganization';

interface ZeroTrustPolicy {
  id: string;
  policy_name: string;
  policy_type: string;
  policy_config: any;
  enabled: boolean;
  enforcement_level: string;
  risk_threshold: number;
  conditions: any;
  actions: any;
  created_at: string;
  updated_at: string;
}

const ZeroTrustPolicyManager = () => {
  const [policies, setPolicies] = useState<ZeroTrustPolicy[]>([]);
  const [loading, setLoading] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<ZeroTrustPolicy | null>(null);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [newPolicy, setNewPolicy] = useState({
    policy_name: '',
    policy_type: 'device_trust' as const,
    enforcement_level: 'monitor' as const,
    risk_threshold: 50,
    enabled: true
  });

  const { toast } = useToast();
  const { user } = useAuth();
  const { currentOrganization } = useOrganization();

  useEffect(() => {
    if (currentOrganization) {
      loadPolicies();
    }
  }, [currentOrganization]);

  const loadPolicies = async () => {
    if (!currentOrganization) return;

    setLoading(true);
    try {
      const { data, error } = await supabase
        .from('zero_trust_policies')
        .select('*')
        .eq('organization_id', currentOrganization.id)
        .order('created_at', { ascending: false });

      if (error) throw error;
      setPolicies(data || []);
    } catch (error: any) {
      console.error('Error loading policies:', error);
      toast({
        title: "Error Loading Policies",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const createPolicy = async () => {
    if (!currentOrganization || !user) return;

    setLoading(true);
    try {
      const { error } = await supabase
        .from('zero_trust_policies')
        .insert([{
          organization_id: currentOrganization.id,
          policy_name: newPolicy.policy_name,
          policy_type: newPolicy.policy_type,
          enforcement_level: newPolicy.enforcement_level,
          risk_threshold: newPolicy.risk_threshold,
          enabled: newPolicy.enabled,
          policy_config: getDefaultPolicyConfig(newPolicy.policy_type),
          conditions: getDefaultConditions(newPolicy.policy_type),
          actions: getDefaultActions(newPolicy.enforcement_level),
          created_by: user.id
        }]);

      if (error) throw error;

      toast({
        title: "Policy Created",
        description: `Zero Trust policy "${newPolicy.policy_name}" has been created.`,
        variant: "default"
      });

      setShowCreateDialog(false);
      setNewPolicy({
        policy_name: '',
        policy_type: 'device_trust',
        enforcement_level: 'monitor',
        risk_threshold: 50,
        enabled: true
      });
      loadPolicies();
    } catch (error: any) {
      console.error('Error creating policy:', error);
      toast({
        title: "Error Creating Policy",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const togglePolicy = async (policy: ZeroTrustPolicy) => {
    setLoading(true);
    try {
      const { error } = await supabase
        .from('zero_trust_policies')
        .update({ enabled: !policy.enabled })
        .eq('id', policy.id);

      if (error) throw error;

      toast({
        title: "Policy Updated",
        description: `Policy "${policy.policy_name}" has been ${!policy.enabled ? 'enabled' : 'disabled'}.`,
        variant: "default"
      });

      loadPolicies();
    } catch (error: any) {
      console.error('Error updating policy:', error);
      toast({
        title: "Error Updating Policy",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const deletePolicy = async (policy: ZeroTrustPolicy) => {
    if (!confirm(`Are you sure you want to delete the policy "${policy.policy_name}"?`)) return;

    setLoading(true);
    try {
      const { error } = await supabase
        .from('zero_trust_policies')
        .delete()
        .eq('id', policy.id);

      if (error) throw error;

      toast({
        title: "Policy Deleted",
        description: `Policy "${policy.policy_name}" has been deleted.`,
        variant: "default"
      });

      loadPolicies();
    } catch (error: any) {
      console.error('Error deleting policy:', error);
      toast({
        title: "Error Deleting Policy",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const getDefaultPolicyConfig = (type: string) => {
    const configs = {
      device_trust: {
        require_mfa: true,
        allowed_os: ['Windows', 'macOS', 'Linux'],
        require_encryption: true,
        max_device_age_months: 24
      },
      network_access: {
        allowed_ip_ranges: [],
        require_vpn: true,
        geo_restrictions: [],
        time_restrictions: {}
      },
      data_protection: {
        encryption_required: true,
        dlp_enabled: true,
        classification_levels: ['public', 'internal', 'confidential', 'restricted']
      },
      identity_verification: {
        mfa_required: true,
        session_timeout_minutes: 480,
        concurrent_sessions_limit: 3
      },
      application_security: {
        code_signing_required: true,
        vulnerability_scanning: true,
        runtime_protection: true
      }
    };
    return configs[type as keyof typeof configs] || {};
  };

  const getDefaultConditions = (type: string) => {
    const conditions = {
      device_trust: {
        device_compliance: true,
        security_posture: 'good',
        last_scan_within_days: 7
      },
      network_access: {
        source_network: 'trusted',
        location_verified: true,
        threat_score_below: 30
      },
      data_protection: {
        data_classification: 'any',
        user_clearance_level: 'required'
      },
      identity_verification: {
        user_risk_score_below: 50,
        recent_suspicious_activity: false
      },
      application_security: {
        application_signed: true,
        vulnerability_score_below: 40
      }
    };
    return conditions[type as keyof typeof conditions] || {};
  };

  const getDefaultActions = (enforcement: string) => {
    const actions = {
      monitor: {
        log_event: true,
        send_alert: false,
        block_access: false
      },
      warn: {
        log_event: true,
        send_alert: true,
        block_access: false,
        show_warning: true
      },
      block: {
        log_event: true,
        send_alert: true,
        block_access: true,
        require_admin_override: true
      }
    };
    return actions[enforcement as keyof typeof actions] || actions.monitor;
  };

  const getPolicyIcon = (type: string) => {
    const icons = {
      device_trust: Shield,
      network_access: Network,
      data_protection: Lock,
      identity_verification: Eye,
      application_security: Settings
    };
    const Icon = icons[type as keyof typeof icons] || Shield;
    return <Icon className="h-4 w-4" />;
  };

  const getEnforcementVariant = (level: string) => {
    const variants = {
      monitor: 'outline',
      warn: 'secondary',
      block: 'destructive'
    };
    return variants[level as keyof typeof variants] || 'outline';
  };

  return (
    <div className="space-y-6">
      <Card className="card-cyber">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center space-x-2">
              <Settings className="h-5 w-5" />
              <span>Zero Trust Policy Management</span>
            </CardTitle>
            <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
              <DialogTrigger asChild>
                <Button>
                  <Plus className="h-4 w-4 mr-2" />
                  Create Policy
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-md">
                <DialogHeader>
                  <DialogTitle>Create Zero Trust Policy</DialogTitle>
                  <DialogDescription>
                    Define a new security policy for continuous verification.
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-4">
                  <div>
                    <Label htmlFor="policy-name">Policy Name</Label>
                    <Input
                      id="policy-name"
                      placeholder="Enter policy name"
                      value={newPolicy.policy_name}
                      onChange={(e) => setNewPolicy(prev => ({ ...prev, policy_name: e.target.value }))}
                    />
                  </div>
                  <div>
                    <Label htmlFor="policy-type">Policy Type</Label>
                    <Select
                      value={newPolicy.policy_type}
                      onValueChange={(value: any) => setNewPolicy(prev => ({ ...prev, policy_type: value }))}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="device_trust">Device Trust</SelectItem>
                        <SelectItem value="network_access">Network Access</SelectItem>
                        <SelectItem value="data_protection">Data Protection</SelectItem>
                        <SelectItem value="identity_verification">Identity Verification</SelectItem>
                        <SelectItem value="application_security">Application Security</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label htmlFor="enforcement-level">Enforcement Level</Label>
                    <Select
                      value={newPolicy.enforcement_level}
                      onValueChange={(value: any) => setNewPolicy(prev => ({ ...prev, enforcement_level: value }))}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="monitor">Monitor Only</SelectItem>
                        <SelectItem value="warn">Warn Users</SelectItem>
                        <SelectItem value="block">Block Access</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label htmlFor="risk-threshold">Risk Threshold (%)</Label>
                    <Input
                      id="risk-threshold"
                      type="number"
                      min="0"
                      max="100"
                      value={newPolicy.risk_threshold}
                      onChange={(e) => setNewPolicy(prev => ({ ...prev, risk_threshold: Number.parseInt(e.target.value) }))}
                    />
                  </div>
                  <div className="flex justify-end space-x-2">
                    <Button
                      variant="outline"
                      onClick={() => setShowCreateDialog(false)}
                    >
                      Cancel
                    </Button>
                    <Button
                      onClick={createPolicy}
                      disabled={loading || !newPolicy.policy_name}
                    >
                      Create Policy
                    </Button>
                  </div>
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {policies.length === 0 ? (
              <div className="text-center py-8">
                <Shield className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                <h3 className="text-lg font-semibold mb-2">No Policies Configured</h3>
                <p className="text-muted-foreground mb-4">
                  Create your first Zero Trust policy to start continuous security verification.
                </p>
                <Button onClick={() => setShowCreateDialog(true)}>
                  <Plus className="h-4 w-4 mr-2" />
                  Create First Policy
                </Button>
              </div>
            ) : (
              policies.map((policy) => (
                <Card key={policy.id} className="border-muted">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <div className="p-2 bg-primary/10 rounded-lg">
                          {getPolicyIcon(policy.policy_type)}
                        </div>
                        <div>
                          <h3 className="font-semibold">{policy.policy_name}</h3>
                          <p className="text-sm text-muted-foreground capitalize">
                            {policy.policy_type.replaceAll('_', ' ')} • Risk threshold: {policy.risk_threshold}%
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Badge variant={getEnforcementVariant(policy.enforcement_level) as any}>
                          {policy.enforcement_level}
                        </Badge>
                        <Switch
                          checked={policy.enabled}
                          onCheckedChange={() => togglePolicy(policy)}
                          disabled={loading}
                        />
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setEditingPolicy(policy)}
                        >
                          <Edit className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => deletePolicy(policy)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
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

export default ZeroTrustPolicyManager;