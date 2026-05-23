import { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { 
  Shield, 
  Smartphone, 
  Key, 
  AlertTriangle, 
  CheckCircle2,
  Clock,
  MapPin,
  Monitor,
  Trash2,
  Plus
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';
import MFASetup from './MFASetup';

interface TrustedDevice {
  id: string;
  name: string;
  fingerprint: string;
  last_used: string;
  location: string;
  trusted_until: string;
}

interface MFAPolicy {
  enforce_for_all: boolean;
  require_for_admin: boolean;
  max_trusted_devices: number;
  device_trust_duration_days: number;
  require_periodic_reverification: boolean;
  emergency_bypass_enabled: boolean;
}

export const EnhancedMFAManager = () => {
  const [trustedDevices, setTrustedDevices] = useState<TrustedDevice[]>([]);
  const [mfaPolicy, setMfaPolicy] = useState<MFAPolicy>({
    enforce_for_all: false,
    require_for_admin: true,
    max_trusted_devices: 3,
    device_trust_duration_days: 30,
    require_periodic_reverification: true,
    emergency_bypass_enabled: false
  });
  const [emergencyAccessCodes, setEmergencyAccessCodes] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('setup');
  
  const { toast } = useToast();
  const { user } = useAuth();

  useEffect(() => {
    if (user) {
      loadTrustedDevices();
      loadMFAPolicy();
      loadEmergencyAccessCodes();
    }
  }, [user]);

  const loadTrustedDevices = async () => {
    if (!user) return;
    
    try {
      const { data, error } = await supabase
        .from('security_devices')
        .select('*')
        .eq('user_id', user.id)
        .eq('is_trusted', true);

      if (error) throw error;
      
      // Map security_devices to TrustedDevice format
      const devices: TrustedDevice[] = (data || []).map(device => ({
        id: device.id,
        name: device.device_name,
        fingerprint: device.device_fingerprint,
        last_used: device.last_used,
        location: device.location_info || 'Unknown',
        trusted_until: device.trusted_until || new Date().toISOString()
      }));
      
      setTrustedDevices(devices);
    } catch (error) {
      console.error('Error loading trusted devices:', error);
    }
  };

  const loadMFAPolicy = async () => {
    try {
      // Get current user's organizations
      const { data: orgData } = await supabase.from('user_organizations')
        .select('organization_id')
        .eq('user_id', user?.id)
        .limit(1)
        .single();
        
      if (!orgData) return;
      
      const { data, error } = await supabase
        .from('organization_settings')
        .select('mfa_policy')
        .eq('organization_id', orgData.organization_id)
        .single();

      if (error && error.code !== 'PGRST116') throw error;
      
      if (data?.mfa_policy) {
        setMfaPolicy(data.mfa_policy as unknown as MFAPolicy);
      }
    } catch (error) {
      console.error('Error loading MFA policy:', error);
    }
  };

  const loadEmergencyAccessCodes = async () => {
    if (!user) return;
    
    try {
      const { data, error } = await supabase
        .from('profiles')
        .select('emergency_access_codes')
        .eq('user_id', user.id)
        .single();

      if (error) throw error;
      
      setEmergencyAccessCodes(data?.emergency_access_codes || []);
    } catch (error) {
      console.error('Error loading emergency access codes:', error);
    }
  };

  const addTrustedDevice = async () => {
    if (!user) return;
    
    setLoading(true);
    try {
      const deviceFingerprint = generateDeviceFingerprint();
      const newDevice: TrustedDevice = {
        id: crypto.randomUUID(),
        name: `${navigator.platform} - ${navigator.userAgent.substring(0, 50)}...`,
        fingerprint: deviceFingerprint,
        last_used: new Date().toISOString(),
        location: 'Current Location', // Could integrate with geolocation
        trusted_until: new Date(Date.now() + mfaPolicy.device_trust_duration_days * 24 * 60 * 60 * 1000).toISOString()
      };

      // Insert into security_devices table
      const { error: insertError } = await supabase
        .from('security_devices')
        .insert({
          user_id: user.id,
          device_name: newDevice.name,
          device_fingerprint: newDevice.fingerprint,
          device_type: 'web_browser',
          location_info: newDevice.location,
          is_trusted: true,
          trusted_until: newDevice.trusted_until,
          risk_score: 0
        });
        
      if (insertError) throw insertError;

      setTrustedDevices([...trustedDevices, newDevice].slice(-mfaPolicy.max_trusted_devices));
      
      // Log security event
      await supabase.from('audit_logs').insert([{
        action: 'device_trusted',
        resource_type: 'mfa_security',
        details: {
          device_id: newDevice.id,
          device_name: newDevice.name,
          fingerprint: deviceFingerprint
        }
      }]);

      toast({
        title: "Device Added",
        description: "Current device has been added to trusted devices.",
        variant: "default"
      });
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const removeTrustedDevice = async (deviceId: string) => {
    if (!user) return;
    
    setLoading(true);
    try {
      // Delete from security_devices table
      const { error: deleteError } = await supabase
        .from('security_devices')
        .delete()
        .eq('id', deviceId)
        .eq('user_id', user.id);
        
      if (deleteError) throw deleteError;

      setTrustedDevices(trustedDevices.filter(d => d.id !== deviceId));
      
      // Log security event
      await supabase.from('audit_logs').insert([{
        action: 'device_untrusted',
        resource_type: 'mfa_security',
        details: { device_id: deviceId }
      }]);

      toast({
        title: "Device Removed",
        description: "Device has been removed from trusted devices.",
        variant: "default"
      });
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const generateEmergencyAccessCodes = async () => {
    if (!user) return;
    
    setLoading(true);
    try {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
      const codes = Array.from({ length: 5 }, () => {
        const randomBytes = crypto.getRandomValues(new Uint8Array(8));
        return Array.from(randomBytes).map(b => chars[b % chars.length]).join('');
      });
      
      await supabase
        .from('profiles')
        .update({ emergency_access_codes: codes })
        .eq('user_id', user.id);

      setEmergencyAccessCodes(codes);
      
      // Log security event
      await supabase.from('audit_logs').insert([{
        action: 'emergency_codes_generated',
        resource_type: 'mfa_security',
        details: { codes_count: codes.length }
      }]);

      toast({
        title: "Emergency Codes Generated",
        description: "New emergency access codes have been created.",
        variant: "default"
      });
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const updateMFAPolicy = async (updates: Partial<MFAPolicy>) => {
    setLoading(true);
    try {
      // Get current user's organizations
      const { data: orgData } = await supabase.from('user_organizations')
        .select('organization_id')
        .eq('user_id', user?.id)
        .limit(1)
        .single();
        
      if (!orgData) throw new Error('No organization found');
      
      const newPolicy = { ...mfaPolicy, ...updates };
      
      await supabase
        .from('organization_settings')
        .upsert({ 
          organization_id: orgData.organization_id,
          mfa_policy: newPolicy 
        }, { onConflict: 'organization_id' });

      setMfaPolicy(newPolicy);
      
      // Log security event
      await supabase.from('audit_logs').insert([{
        action: 'mfa_policy_updated',
        resource_type: 'mfa_security',
        details: { policy_changes: updates }
      }]);

      toast({
        title: "Policy Updated",
        description: "MFA policy has been updated successfully.",
        variant: "default"
      });
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const generateDeviceFingerprint = (): string => {
    const fingerprint = {
      userAgent: navigator.userAgent,
      language: navigator.language,
      platform: navigator.platform,
      cookieEnabled: navigator.cookieEnabled,
      screen: `${screen.width}x${screen.height}`,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
    };
    
    let hash = 0;
    const str = JSON.stringify(fingerprint);
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return hash.toString(16);
  };

  return (
    <div className="space-y-6">
      <Card className="card-cyber">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Shield className="h-5 w-5 text-primary" />
            <span>Enhanced Multi-Factor Authentication</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="setup">Setup</TabsTrigger>
              <TabsTrigger value="devices">Trusted Devices</TabsTrigger>
              <TabsTrigger value="emergency">Emergency Access</TabsTrigger>
              <TabsTrigger value="policy">Policy</TabsTrigger>
            </TabsList>

            <TabsContent value="setup" className="mt-6">
              <MFASetup />
            </TabsContent>

            <TabsContent value="devices" className="mt-6">
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <h3 className="text-lg font-semibold">Trusted Devices</h3>
                  <Button 
                    onClick={addTrustedDevice}
                    disabled={loading || trustedDevices.length >= mfaPolicy.max_trusted_devices}
                    size="sm"
                  >
                    <Plus className="h-4 w-4 mr-2" />
                    Trust This Device
                  </Button>
                </div>
                
                <div className="grid gap-4">
                  {trustedDevices.map((device) => (
                    <Card key={device.id} className="border">
                      <CardContent className="p-4">
                        <div className="flex justify-between items-start">
                          <div className="space-y-2">
                            <div className="flex items-center space-x-2">
                              <Monitor className="h-4 w-4 text-muted-foreground" />
                              <span className="font-medium">{device.name}</span>
                            </div>
                            <div className="flex items-center space-x-4 text-sm text-muted-foreground">
                              <div className="flex items-center space-x-1">
                                <Clock className="h-3 w-3" />
                                <span>Last used: {new Date(device.last_used).toLocaleDateString()}</span>
                              </div>
                              <div className="flex items-center space-x-1">
                                <MapPin className="h-3 w-3" />
                                <span>{device.location}</span>
                              </div>
                            </div>
                            <div className="flex items-center space-x-2">
                              <Badge variant="secondary">
                                Trusted until: {new Date(device.trusted_until).toLocaleDateString()}
                              </Badge>
                            </div>
                          </div>
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={() => removeTrustedDevice(device.id)}
                            disabled={loading}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                  
                  {trustedDevices.length === 0 && (
                    <div className="text-center py-8 text-muted-foreground">
                      <Monitor className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No trusted devices configured</p>
                      <p className="text-sm">Add this device to skip MFA challenges</p>
                    </div>
                  )}
                </div>
              </div>
            </TabsContent>

            <TabsContent value="emergency" className="mt-6">
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <h3 className="text-lg font-semibold">Emergency Access Codes</h3>
                  <Button 
                    onClick={generateEmergencyAccessCodes}
                    disabled={loading}
                    variant="outline"
                  >
                    <Key className="h-4 w-4 mr-2" />
                    Generate New Codes
                  </Button>
                </div>
                
                {emergencyAccessCodes.length > 0 && (
                  <div className="space-y-2">
                    <div className="flex items-center space-x-2 mb-2">
                      <AlertTriangle className="h-4 w-4 text-warning" />
                      <span className="text-sm text-warning font-medium">
                        Store these codes securely - each can only be used once
                      </span>
                    </div>
                    <div className="grid grid-cols-1 gap-2">
                      {emergencyAccessCodes.map((code, index) => (
                        <Badge key={index} variant="secondary" className="font-mono p-2 text-center">
                          {code}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
                
                {emergencyAccessCodes.length === 0 && (
                  <div className="text-center py-8 text-muted-foreground">
                    <Key className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No emergency access codes generated</p>
                    <p className="text-sm">Generate codes for emergency access when MFA is unavailable</p>
                  </div>
                )}
              </div>
            </TabsContent>

            <TabsContent value="policy" className="mt-6">
              <div className="space-y-6">
                <h3 className="text-lg font-semibold">MFA Enforcement Policy</h3>
                
                <div className="grid gap-4">
                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label className="text-base">Enforce MFA for all users</Label>
                      <p className="text-sm text-muted-foreground">
                        Require all users to enable multi-factor authentication
                      </p>
                    </div>
                    <Switch
                      checked={mfaPolicy.enforce_for_all}
                      onCheckedChange={(checked) => updateMFAPolicy({ enforce_for_all: checked })}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label className="text-base">Require MFA for administrators</Label>
                      <p className="text-sm text-muted-foreground">
                        Always require MFA for users with admin privileges
                      </p>
                    </div>
                    <Switch
                      checked={mfaPolicy.require_for_admin}
                      onCheckedChange={(checked) => updateMFAPolicy({ require_for_admin: checked })}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label className="text-base">Periodic re-verification</Label>
                      <p className="text-sm text-muted-foreground">
                        Require users to re-verify their MFA setup periodically
                      </p>
                    </div>
                    <Switch
                      checked={mfaPolicy.require_periodic_reverification}
                      onCheckedChange={(checked) => updateMFAPolicy({ require_periodic_reverification: checked })}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label className="text-base">Emergency bypass</Label>
                      <p className="text-sm text-muted-foreground">
                        Allow emergency access codes to bypass MFA
                      </p>
                    </div>
                    <Switch
                      checked={mfaPolicy.emergency_bypass_enabled}
                      onCheckedChange={(checked) => updateMFAPolicy({ emergency_bypass_enabled: checked })}
                    />
                  </div>
                </div>

                <div className="pt-4 border-t">
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <Label className="text-muted-foreground">Max Trusted Devices</Label>
                      <p className="font-medium">{mfaPolicy.max_trusted_devices}</p>
                    </div>
                    <div>
                      <Label className="text-muted-foreground">Device Trust Duration</Label>
                      <p className="font-medium">{mfaPolicy.device_trust_duration_days} days</p>
                    </div>
                  </div>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default EnhancedMFAManager;