import { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { InputOTP, InputOTPGroup, InputOTPSlot } from '@/components/ui/input-otp';
import { Alert, AlertDescription } from '@/components/ui/alert';
import {
  Shield,
  Smartphone,
  Key,
  CheckCircle,
  AlertTriangle,
  RefreshCw,
  Copy,
  Download
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { useMFA } from '@/hooks/useMFA';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';

interface MFASetupProps {
  onComplete?: (success: boolean) => void;
}

type SetupStep = 'check' | 'setup' | 'scan' | 'verify' | 'backup' | 'complete';

export const MFASetup = ({ onComplete }: MFASetupProps) => {
  const [step, setStep] = useState<SetupStep>('check');
  const [verificationCode, setVerificationCode] = useState('');
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const { user } = useAuth();
  const { toast } = useToast();

  const {
    isEnabled,
    isLoading,
    enrollmentData,
    error,
    checkMFAStatus,
    startEnrollment,
    verifyCode,
    cancelEnrollment,
    disableMFA,
    generateBackupCodes,
    clearError
  } = useMFA();

  useEffect(() => {
    checkMFAStatus().then(({ isEnabled: enabled }) => {
      setStep(enabled ? 'complete' : 'setup');
    });
  }, [checkMFAStatus]);

  const handleStartSetup = async () => {
    clearError();
    const enrollment = await startEnrollment();
    if (enrollment) {
      setStep('scan');
    }
  };

  const handleVerifyCode = async () => {
    if (verificationCode.length !== 6) return;

    const success = await verifyCode(verificationCode);
    if (success) {
      // Generate backup codes
      const codes = generateBackupCodes();
      setBackupCodes(codes);

      // Save backup codes to profile
      if (user) {
        const hashedCodes = codes.map(code => {
          let hash = 0;
          for (let i = 0; i < code.length; i++) {
            const char = code.codePointAt(i) || 0;
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
          }
          return hash.toString(16);
        });

        await supabase
          .from('profiles')
          .update({
            mfa_enabled: true,
            mfa_backup_codes: hashedCodes
          })
          .eq('user_id', user.id);
      }

      setStep('backup');
    }
  };

  const handleCompleteSetup = () => {
    setStep('complete');
    onComplete?.(true);
  };

  const handleDisableMFA = async () => {
    const success = await disableMFA();
    if (success) {
      setStep('setup');
      setBackupCodes([]);
      setVerificationCode('');
    }
  };

  const handleRestart = () => {
    cancelEnrollment();
    setVerificationCode('');
    clearError();
    setStep('setup');
  };

  const copyBackupCodes = () => {
    const codesText = backupCodes.join('\n');
    navigator.clipboard.writeText(codesText);
    toast({
      title: "Copied to Clipboard",
      description: "Backup codes have been copied to your clipboard.",
    });
  };

  const downloadBackupCodes = () => {
    const codesText = `SouHimBou AI MFA Backup Codes\nGenerated: ${new Date().toISOString()}\n\n${backupCodes.join('\n')}\n\nKeep these codes secure and use them only if you lose access to your authenticator app.`;
    const blob = new Blob([codesText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'mfa-backup-codes.txt';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);

    toast({
      title: "Download Started",
      description: "Backup codes file has been downloaded.",
    });
  };

  // Show loading state during initial check
  if (step === 'check') {
    return (
      <Card className="card-cyber">
        <CardContent className="flex items-center justify-center py-8">
          <div className="flex items-center space-x-2">
            <div className="w-4 h-4 border-2 border-primary border-t-transparent rounded-full animate-spin"></div>
            <span>Checking MFA status...</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  // Show enabled state
  if (step === 'complete' && isEnabled) {
    return (
      <Card className="card-cyber">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <CheckCircle className="h-5 w-5 text-success" />
            <span>MFA Enabled</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-muted-foreground">
            Two-factor authentication is currently enabled for your account.
          </p>
          <Button
            onClick={handleDisableMFA}
            variant="destructive"
            disabled={isLoading}
          >
            {isLoading ? 'Disabling...' : 'Disable MFA'}
          </Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="card-cyber">
      <CardHeader>
        <CardTitle className="flex items-center space-x-2">
          <Shield className="h-5 w-5 text-primary" />
          <span>Multi-Factor Authentication</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {error && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription className="flex items-center justify-between">
              <span>{error}</span>
              <Button
                variant="outline"
                size="sm"
                onClick={handleRestart}
                className="ml-2"
              >
                <RefreshCw className="h-3 w-3 mr-1" />
                Restart
              </Button>
            </AlertDescription>
          </Alert>
        )}

        {step === 'setup' && (
          <div className="space-y-4">
            <div className="flex items-center space-x-2">
              <Smartphone className="h-4 w-4 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">
                Add an extra layer of security to your account
              </p>
            </div>

            <div className="space-y-2">
              <h4 className="font-semibold">Before you start:</h4>
              <ul className="text-sm text-muted-foreground space-y-1">
                <li>• Install an authenticator app (Google Authenticator, Authy, Microsoft Authenticator)</li>
                <li>• Ensure your device is secure and backed up</li>
                <li>• Have a secure place to store backup codes</li>
              </ul>
            </div>

            <Button
              onClick={handleStartSetup}
              disabled={isLoading}
              className="w-full"
            >
              {isLoading ? (
                <div className="flex items-center space-x-2">
                  <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin"></div>
                  <span>Setting up...</span>
                </div>
              ) : (
                'Setup MFA'
              )}
            </Button>
          </div>
        )}

        {step === 'scan' && enrollmentData && (
          <div className="space-y-6">
            <div className="text-center">
              <h4 className="font-semibold mb-4">Step 1: Scan QR Code</h4>
              <div className="bg-white p-4 rounded-lg inline-block mb-4">
                <img
                  src={enrollmentData.qrCode}
                  alt="MFA QR Code"
                  className="w-48 h-48"
                />
              </div>
              <div className="space-y-2">
                <p className="text-sm text-muted-foreground">
                  Scan this QR code with your authenticator app, or enter the secret manually:
                </p>
                <div className="bg-muted p-3 rounded-lg">
                  <code className="text-xs break-all">
                    {enrollmentData.secret}
                  </code>
                </div>
              </div>
            </div>

            <Button
              onClick={() => setStep('verify')}
              className="w-full"
            >
              I've Added the Account
            </Button>

            <Button
              variant="outline"
              onClick={handleRestart}
              className="w-full"
              disabled={isLoading}
            >
              Cancel Setup
            </Button>
          </div>
        )}

        {step === 'verify' && (
          <div className="space-y-6">
            <div className="text-center">
              <h4 className="font-semibold mb-4">Step 2: Verify Setup</h4>
              <p className="text-sm text-muted-foreground mb-4">
                Enter the 6-digit code from your authenticator app to complete setup:
              </p>
            </div>

            <div className="space-y-4">
              <div className="flex justify-center">
                <InputOTP
                  value={verificationCode}
                  onChange={setVerificationCode}
                  maxLength={6}
                  className="gap-2"
                >
                  <InputOTPGroup>
                    <InputOTPSlot index={0} />
                    <InputOTPSlot index={1} />
                    <InputOTPSlot index={2} />
                    <InputOTPSlot index={3} />
                    <InputOTPSlot index={4} />
                    <InputOTPSlot index={5} />
                  </InputOTPGroup>
                </InputOTP>
              </div>

              <div className="flex space-x-2">
                <Button
                  onClick={handleVerifyCode}
                  disabled={isLoading || verificationCode.length !== 6}
                  className="flex-1"
                >
                  {isLoading ? 'Verifying...' : 'Verify & Enable MFA'}
                </Button>
                <Button
                  variant="outline"
                  onClick={() => setStep('scan')}
                  disabled={isLoading}
                >
                  Back
                </Button>
              </div>
            </div>
          </div>
        )}

        {step === 'backup' && (
          <div className="space-y-6">
            <div className="text-center">
              <CheckCircle className="h-12 w-12 text-success mx-auto mb-4" />
              <h4 className="font-semibold mb-2">MFA Successfully Enabled!</h4>
              <p className="text-sm text-muted-foreground">
                Your account is now protected with two-factor authentication.
              </p>
            </div>

            <div className="space-y-4">
              <div className="flex items-center space-x-2">
                <Key className="h-4 w-4 text-warning" />
                <h5 className="font-semibold">Backup Codes</h5>
              </div>

              <Alert>
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  <strong>Important:</strong> Save these backup codes in a secure location.
                  Each code can only be used once and will help you regain access if you lose your authenticator app.
                </AlertDescription>
              </Alert>

              <div className="bg-muted p-4 rounded-lg">
                <div className="grid grid-cols-2 gap-2 mb-4">
                  {backupCodes.map((code) => (
                    <Badge key={`backup-code-${code}`} variant="secondary" className="font-mono text-sm justify-center">
                      {code}
                    </Badge>
                  ))}
                </div>

                <div className="flex space-x-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={copyBackupCodes}
                    className="flex-1"
                  >
                    <Copy className="h-3 w-3 mr-1" />
                    Copy Codes
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={downloadBackupCodes}
                    className="flex-1"
                  >
                    <Download className="h-3 w-3 mr-1" />
                    Download
                  </Button>
                </div>
              </div>

              <Button
                onClick={handleCompleteSetup}
                className="w-full"
              >
                Complete Setup
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default MFASetup;