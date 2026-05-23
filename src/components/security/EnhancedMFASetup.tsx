import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import {
  Shield,
  Smartphone,
  Key,
  AlertTriangle,
  CheckCircle,
  Copy,
  RefreshCw
} from 'lucide-react';
import { useMFA } from '@/hooks/useMFA';
import { useAuth } from '@/hooks/useAuth';
import { toast } from 'sonner';

export const EnhancedMFASetup = () => {
  const { user } = useAuth();
  const {
    isEnabled,
    isLoading,
    factors,
    enrollmentData,
    error,
    checkMFAStatus,
    startEnrollment,
    verifyCode,
    disableMFA,
    generateBackupCodes
  } = useMFA();

  const [verificationCode, setVerificationCode] = useState('');
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [showBackupCodes, setShowBackupCodes] = useState(false);

  const handleStartEnrollment = async () => {
    try {
      await startEnrollment();
      if (enrollmentData?.qrCode) {
        toast.success('Scan the QR code with your authenticator app');
      }
    } catch (error) {
      console.error(error);
      toast.error('Failed to start MFA enrollment');
    }
  };

  const handleVerifyAndEnable = async () => {
    if (!verificationCode.trim()) {
      toast.error('Please enter the verification code');
      return;
    }

    try {
      await verifyCode(verificationCode);
      toast.success('MFA enabled successfully!');
      setVerificationCode('');

      // Generate backup codes after successful enrollment
      const codes = generateBackupCodes();
      if (codes) {
        setBackupCodes(codes);
        setShowBackupCodes(true);
      }
    } catch (error) {
      console.error(error);
      toast.error('Invalid verification code');
    }
  };

  const handleDisableMFA = async () => {
    try {
      await disableMFA();
      toast.success('MFA disabled successfully');
      setBackupCodes([]);
      setShowBackupCodes(false);
    } catch (error) {
      console.error(error);
      toast.error('Failed to disable MFA');
    }
  };

  const copyBackupCodes = () => {
    const codesText = backupCodes.join('\n');
    navigator.clipboard.writeText(codesText);
    toast.success('Backup codes copied to clipboard');
  };

  const getSecurityScore = (): number => {
    let score = 0;
    if (isEnabled) score += 60;
    if (backupCodes.length > 0) score += 20;
    if (factors.length > 0) score += 20;
    return score;
  };

  const getSecurityLevel = (score: number): { level: string; color: string } => {
    if (score >= 80) return { level: 'Excellent', color: 'text-green-600' };
    if (score >= 60) return { level: 'Good', color: 'text-blue-600' };
    if (score >= 40) return { level: 'Fair', color: 'text-yellow-600' };
    return { level: 'Poor', color: 'text-red-600' };
  };

  useEffect(() => {
    if (user) {
      checkMFAStatus();
    }
  }, [user]);

  const securityScore = getSecurityScore();
  const securityLevel = getSecurityLevel(securityScore);

  return (
    <div className="space-y-6">
      {/* Security Score Overview */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="w-5 h-5" />
            Account Security Score
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium">Security Level</span>
            <Badge variant="outline" className={securityLevel.color}>
              {securityLevel.level}
            </Badge>
          </div>
          <Progress value={securityScore} className="h-2 mb-4" />
          <div className="grid grid-cols-3 gap-4 text-sm">
            <div className="text-center">
              <div className="font-medium">MFA Status</div>
              <div className={isEnabled ? 'text-green-600' : 'text-red-600'}>
                {isEnabled ? 'Enabled' : 'Disabled'}
              </div>
            </div>
            <div className="text-center">
              <div className="font-medium">Backup Codes</div>
              <div className={backupCodes.length > 0 ? 'text-green-600' : 'text-yellow-600'}>
                {backupCodes.length > 0 ? 'Generated' : 'Not Generated'}
              </div>
            </div>
            <div className="text-center">
              <div className="font-medium">Factors</div>
              <div className="text-muted-foreground">
                {factors.length} Active
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* MFA Setup */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Smartphone className="w-5 h-5" />
            Multi-Factor Authentication (MFA)
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {isEnabled ? (
            <div className="space-y-4">
              <Alert>
                <CheckCircle className="w-4 h-4" />
                <AlertDescription>
                  <strong>MFA is enabled.</strong> Your account has an additional layer of
                  security. You'll need to enter a code from your authenticator app when signing in.
                </AlertDescription>
              </Alert>

              <div className="flex justify-between items-center p-3 border rounded-lg">
                <div>
                  <p className="font-medium">Authenticator App</p>
                  <p className="text-sm text-muted-foreground">
                    {factors.length} factor(s) configured
                  </p>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleDisableMFA}
                  disabled={isLoading}
                >
                  Disable MFA
                </Button>
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              <Alert>
                <AlertTriangle className="w-4 h-4" />
                <AlertDescription>
                  <strong>Security Recommendation:</strong> Enable MFA to add an extra layer
                  of security to your account. This helps protect against unauthorized access
                  even if your password is compromised.
                </AlertDescription>
              </Alert>

              {enrollmentData ? (
                <div className="space-y-4">
                  {enrollmentData.qrCode && (
                    <div className="text-center">
                      <div
                        className="inline-block p-4 bg-white rounded-lg border"
                        dangerouslySetInnerHTML={{
                          // Basic sanitization to prevent XSS from compromised QR code generation
                          __html: enrollmentData.qrCode
                            .replaceAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gim, "")
                            .replaceAll(/javascript:/gim, "")
                            .replaceAll(/ on\w+="[^"]*"/gim, "")
                            .replaceAll(/ on\w+='[^']*'/gim, "")
                        }}
                      />
                      <p className="text-sm text-muted-foreground mt-2">
                        Scan this QR code with your authenticator app
                      </p>
                      {enrollmentData.secret && (
                        <details className="mt-2">
                          <summary className="text-sm cursor-pointer">
                            Can't scan? Enter manually
                          </summary>
                          <code className="text-xs bg-muted p-2 rounded block mt-1">
                            {enrollmentData.secret}
                          </code>
                        </details>
                      )}
                    </div>
                  )}

                  <div className="space-y-2">
                    <label className="text-sm font-medium" htmlFor="verification-code">
                      Enter verification code from your app:
                    </label>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        placeholder="000000"
                        value={verificationCode}
                        onChange={(e) => setVerificationCode(e.target.value.replaceAll(/\D/g, '').slice(0, 6))}
                        className="flex-1 px-3 py-2 border rounded-md text-center font-mono"
                        maxLength={6}
                      />
                      <Button
                        onClick={handleVerifyAndEnable}
                        disabled={verificationCode.length !== 6 || isLoading}
                      >
                        Verify & Enable
                      </Button>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-center py-4">
                  <Button
                    onClick={handleStartEnrollment}
                    disabled={isLoading}
                    className="w-full"
                  >
                    {isLoading ? (
                      <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                    ) : (
                      <Key className="w-4 h-4 mr-2" />
                    )}
                    Set Up MFA
                  </Button>
                </div>
              )}
            </div>
          )}

          {error && (
            <Alert variant="destructive">
              <AlertTriangle className="w-4 h-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* Backup Codes */}
      {showBackupCodes && backupCodes.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Key className="w-5 h-5" />
              Backup Recovery Codes
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <Alert>
              <AlertTriangle className="w-4 h-4" />
              <AlertDescription>
                <strong>Important:</strong> Save these backup codes in a secure location.
                You can use them to access your account if you lose your authenticator device.
                Each code can only be used once.
              </AlertDescription>
            </Alert>

            <div className="bg-muted p-4 rounded-lg">
              <div className="grid grid-cols-2 gap-2 font-mono text-sm">
                {backupCodes.map((code) => (
                  <div key={code} className="bg-white p-2 rounded border text-center">
                    {code}
                  </div>
                ))}
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={copyBackupCodes}
                className="mt-3 w-full"
              >
                <Copy className="w-4 h-4 mr-2" />
                Copy All Codes
              </Button>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};