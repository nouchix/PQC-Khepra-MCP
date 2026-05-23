import { useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import {
  Smartphone,
  Monitor,
  Shield,
  AlertTriangle,
  CheckCircle,
  MapPin,
  Clock
} from 'lucide-react';

interface DeviceInfo {
  type: 'mobile' | 'desktop' | 'tablet';
  os: string;
  browser: string;
  location: string;
  lastSeen: Date;
  trusted: boolean;
}

interface DeviceVerificationDialogProps {
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  readonly device: DeviceInfo;
  readonly onVerify: (deviceName: string, trustDevice: boolean) => void;
  readonly onDeny: () => void;
}

export function DeviceVerificationDialog({
  open,
  onOpenChange,
  device,
  onVerify,
  onDeny
}: DeviceVerificationDialogProps) {
  const [deviceName, setDeviceName] = useState(
    `${device.os} ${device.type === 'mobile' ? 'Phone' : 'Computer'}`
  );
  const [trustDevice, setTrustDevice] = useState(false);

  const getDeviceIcon = () => {
    switch (device.type) {
      case 'mobile':
        return <Smartphone className="h-8 w-8 text-blue-500" />;
      case 'tablet':
        return <Smartphone className="h-8 w-8 text-blue-500" />;
      default:
        return <Monitor className="h-8 w-8 text-blue-500" />;
    }
  };

  const handleVerify = () => {
    onVerify(deviceName, trustDevice);
    onOpenChange(false);
  };

  const handleDeny = () => {
    onDeny();
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle className="flex items-center space-x-2">
            <Shield className="h-5 w-5" />
            <span>Device Verification Required</span>
          </DialogTitle>
          <DialogDescription>
            A new device is attempting to access your account. Please verify if this is you.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6">
          {/* Device Info */}
          <div className="flex items-start space-x-4 p-4 border rounded-lg">
            <div className="flex-shrink-0">
              {getDeviceIcon()}
            </div>
            <div className="flex-1 space-y-2">
              <div className="flex items-center space-x-2">
                <h3 className="font-medium">{device.os} {device.browser}</h3>
                <Badge variant={device.trusted ? "default" : "secondary"}>
                  {device.trusted ? "Known Device" : "New Device"}
                </Badge>
              </div>

              <div className="space-y-1 text-sm text-muted-foreground">
                <div className="flex items-center space-x-2">
                  <MapPin className="h-3 w-3" />
                  <span>{device.location}</span>
                </div>
                <div className="flex items-center space-x-2">
                  <Clock className="h-3 w-3" />
                  <span>Last seen: {device.lastSeen.toLocaleString()}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Security Alert */}
          {!device.trusted && (
            <Alert>
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>
                This device is not recognized. If this wasn't you, deny access and change your password immediately.
              </AlertDescription>
            </Alert>
          )}

          {/* Device Name Input */}
          <div className="space-y-2">
            <Label htmlFor="device-name">Device Name</Label>
            <Input
              id="device-name"
              value={deviceName}
              onChange={(e) => setDeviceName(e.target.value)}
              placeholder="Enter a name for this device"
            />
            <p className="text-xs text-muted-foreground">
              Give this device a memorable name for future reference
            </p>
          </div>

          {/* Trust Options */}
          <div className="space-y-3">
            <div className="flex items-center space-x-2">
              <input
                type="radio"
                id="trust-session"
                name="trust-level"
                checked={!trustDevice}
                onChange={() => setTrustDevice(false)}
                className="h-4 w-4"
              />
              <Label htmlFor="trust-session" className="flex-1">
                <div className="font-medium">Trust for this session only</div>
                <div className="text-sm text-muted-foreground">
                  Verify this device each time you sign in
                </div>
              </Label>
            </div>

            <div className="flex items-center space-x-2">
              <input
                type="radio"
                id="trust-device"
                name="trust-level"
                checked={trustDevice}
                onChange={() => setTrustDevice(true)}
                className="h-4 w-4"
              />
              <Label htmlFor="trust-device" className="flex-1">
                <div className="font-medium">Trust this device</div>
                <div className="text-sm text-muted-foreground">
                  Don't ask again on this device for 30 days
                </div>
              </Label>
            </div>
          </div>

          {/* Verification Actions */}
          <div className="bg-muted/50 p-4 rounded-lg">
            <div className="flex items-center space-x-2 mb-2">
              <CheckCircle className="h-4 w-4 text-green-500" />
              <span className="font-medium text-sm">Is this you?</span>
            </div>
            <p className="text-xs text-muted-foreground">
              Only approve if you recognize this device and location.
              When in doubt, deny access and change your password.
            </p>
          </div>
        </div>

        <DialogFooter className="flex justify-between">
          <Button
            onClick={handleDeny}
            variant="destructive"
            className="flex items-center space-x-2"
          >
            <AlertTriangle className="h-4 w-4" />
            <span>Deny Access</span>
          </Button>

          <Button
            onClick={handleVerify}
            className="flex items-center space-x-2"
          >
            <Shield className="h-4 w-4" />
            <span>Verify & Continue</span>
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}