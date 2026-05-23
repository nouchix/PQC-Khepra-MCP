import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { 
  Shield, 
  Smartphone, 
  Monitor, 
  Tablet, 
  Trash2, 
  Plus,
  Clock,
  MapPin
} from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';
import { toast } from 'sonner';

interface TrustedDevice {
  id: string;
  device_fingerprint: string;
  device_name: string | null;
  trusted_at: string;
  last_used: string;
  ip_address: unknown;
  user_agent: string | null;
  is_active: boolean;
  expires_at: string | null;
}

export const DeviceTrustManager = () => {
  const { user } = useAuth();
  const [devices, setDevices] = useState<TrustedDevice[]>([]);
  const [loading, setLoading] = useState(false);
  const [showAddForm, setShowAddForm] = useState(false);
  const [newDeviceName, setNewDeviceName] = useState('');

  const loadTrustedDevices = async () => {
    if (!user) return;

    try {
      const { data, error } = await supabase
        .from('trusted_devices')
        .select('*')
        .eq('user_id', user.id)
        .eq('is_active', true)
        .order('last_used', { ascending: false });

      if (error) throw error;
      setDevices(data || []);
    } catch (error) {
      console.error('Error loading trusted devices:', error);
      toast.error('Failed to load trusted devices');
    }
  };

  const generateDeviceFingerprint = (): string => {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    if (ctx) {
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillText('Device fingerprint', 2, 2);
    }
    
    const fingerprint = [
      navigator.userAgent,
      navigator.language,
      screen.width + 'x' + screen.height,
      new Date().getTimezoneOffset(),
      canvas.toDataURL(),
      navigator.platform,
      navigator.cookieEnabled,
    ].join('|');
    
    return btoa(fingerprint).substring(0, 32);
  };

  const trustCurrentDevice = async () => {
    if (!user || !newDeviceName.trim()) {
      toast.error('Please enter a device name');
      return;
    }

    setLoading(true);
    try {
      const deviceFingerprint = generateDeviceFingerprint();
      
      const { error } = await supabase
        .from('trusted_devices')
        .upsert({
          user_id: user.id,
          device_fingerprint: deviceFingerprint,
          device_name: newDeviceName.trim(),
          user_agent: navigator.userAgent,
          trusted_at: new Date().toISOString(),
          last_used: new Date().toISOString(),
          expires_at: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(), // 90 days
          is_active: true
        });

      if (error) throw error;

      toast.success('Current device added to trusted devices');
      setNewDeviceName('');
      setShowAddForm(false);
      loadTrustedDevices();
    } catch (error) {
      console.error('Error trusting device:', error);
      toast.error('Failed to add device to trusted list');
    } finally {
      setLoading(false);
    }
  };

  const revokeDevice = async (deviceId: string) => {
    setLoading(true);
    try {
      const { error } = await supabase
        .from('trusted_devices')
        .update({ is_active: false })
        .eq('id', deviceId);

      if (error) throw error;

      toast.success('Device trust revoked successfully');
      loadTrustedDevices();
    } catch (error) {
      console.error('Error revoking device:', error);
      toast.error('Failed to revoke device trust');
    } finally {
      setLoading(false);
    }
  };

  const getDeviceIcon = (userAgent: string | null) => {
    if (!userAgent) return <Monitor className="w-5 h-5" />;
    
    if (userAgent.includes('Mobile') || userAgent.includes('Android') || userAgent.includes('iPhone')) {
      return <Smartphone className="w-5 h-5" />;
    }
    if (userAgent.includes('iPad') || userAgent.includes('Tablet')) {
      return <Tablet className="w-5 h-5" />;
    }
    return <Monitor className="w-5 h-5" />;
  };

  const isCurrentDevice = (deviceFingerprint: string): boolean => {
    return generateDeviceFingerprint() === deviceFingerprint;
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  useEffect(() => {
    if (user) {
      loadTrustedDevices();
    }
  }, [user]);

  if (!user) {
    return null;
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-lg font-medium flex items-center gap-2">
          <Shield className="w-5 h-5" />
          Trusted Devices
        </CardTitle>
        <Button 
          variant="outline" 
          size="sm"
          onClick={() => setShowAddForm(!showAddForm)}
        >
          <Plus className="w-4 h-4 mr-1" />
          Trust This Device
        </Button>
      </CardHeader>
      <CardContent className="space-y-4">
        <Alert>
          <Shield className="w-4 h-4" />
          <AlertDescription className="text-sm">
            Trusted devices don't require additional verification when you sign in. 
            Only add devices you personally own and control.
          </AlertDescription>
        </Alert>

        {showAddForm && (
          <div className="p-4 border rounded-lg space-y-3 bg-muted/50">
            <h4 className="font-medium">Add Current Device to Trusted List</h4>
            <div className="space-y-2">
              <Label htmlFor="deviceName">Device Name</Label>
              <Input
                id="deviceName"
                placeholder="e.g., My MacBook Pro, Work Laptop, Personal Phone"
                value={newDeviceName}
                onChange={(e) => setNewDeviceName(e.target.value)}
              />
            </div>
            <div className="flex gap-2">
              <Button 
                onClick={trustCurrentDevice} 
                disabled={loading || !newDeviceName.trim()}
                size="sm"
              >
                Add Device
              </Button>
              <Button 
                variant="outline" 
                onClick={() => setShowAddForm(false)}
                size="sm"
              >
                Cancel
              </Button>
            </div>
          </div>
        )}

        <div className="space-y-3">
          {devices.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Shield className="w-12 h-12 mx-auto mb-2 opacity-50" />
              <p>No trusted devices found</p>
              <p className="text-sm">Add your current device to the trusted list above</p>
            </div>
          ) : (
            devices.map((device) => (
              <div key={device.id} className="flex items-center justify-between p-3 border rounded-lg">
                <div className="flex items-center gap-3">
                  {getDeviceIcon(device.user_agent)}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="font-medium truncate">
                        {device.device_name || 'Unnamed Device'}
                      </p>
                      {isCurrentDevice(device.device_fingerprint) && (
                        <Badge variant="secondary" className="text-xs">
                          Current Device
                        </Badge>
                      )}
                    </div>
                    <div className="flex items-center gap-4 text-sm text-muted-foreground">
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        Last used: {formatDate(device.last_used)}
                      </span>
                      {device.ip_address && (
                        <span className="flex items-center gap-1">
                          <MapPin className="w-3 h-3" />
                          {String(device.ip_address)}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
                
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => revokeDevice(device.id)}
                  disabled={loading}
                  className="text-red-600 hover:text-red-700 hover:bg-red-50"
                >
                  <Trash2 className="w-4 h-4" />
                </Button>
              </div>
            ))
          )}
        </div>

        {devices.length > 0 && (
          <div className="text-xs text-muted-foreground">
            <p>• Trusted devices expire after 90 days of inactivity</p>
            <p>• Remove devices you no longer use or control</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
};