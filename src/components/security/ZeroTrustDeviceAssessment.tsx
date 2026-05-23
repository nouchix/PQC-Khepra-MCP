import { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { 
  Smartphone, 
  Monitor, 
  Laptop, 
  Shield, 
  AlertTriangle,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Eye,
  Lock
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';
import { useOrganization } from '@/hooks/useOrganization';
import { useSessionSecurity } from '@/hooks/useSessionSecurity';

interface DeviceAssessment {
  id: string;
  user_id: string;
  device_fingerprint: string;
  assessment_timestamp: string;
  trust_score: number;
  risk_factors: any;
  compliance_status: any;
  security_posture: any;
  network_context: any;
  behavioral_score: number;
  validation_result: string;
  remediation_required: boolean;
  remediation_actions: any;
}

const ZeroTrustDeviceAssessment = () => {
  const [assessments, setAssessments] = useState<DeviceAssessment[]>([]);
  const [currentDeviceAssessment, setCurrentDeviceAssessment] = useState<DeviceAssessment | null>(null);
  const [loading, setLoading] = useState(false);
  const [assessing, setAssessing] = useState(false);

  const { toast } = useToast();
  const { user } = useAuth();
  const { currentOrganization } = useOrganization();
  const { deviceFingerprint, sessionState } = useSessionSecurity();

  useEffect(() => {
    if (currentOrganization) {
      loadDeviceAssessments();
      assessCurrentDevice();
    }
  }, [currentOrganization, deviceFingerprint]);

  const loadDeviceAssessments = async () => {
    if (!currentOrganization) return;

    setLoading(true);
    try {
      const { data, error } = await supabase
        .from('zero_trust_device_assessments')
        .select('*')
        .eq('organization_id', currentOrganization.id)
        .order('assessment_timestamp', { ascending: false })
        .limit(20);

      if (error) throw error;
      setAssessments(data || []);
    } catch (error: any) {
      console.error('Error loading device assessments:', error);
      toast({
        title: "Error Loading Assessments",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const assessCurrentDevice = async () => {
    if (!currentOrganization || !user || !deviceFingerprint) return;

    setAssessing(true);
    try {
      // Perform device assessment
      const assessment = await performDeviceAssessment();
      
      // Store assessment in database
      const { data, error } = await supabase
        .from('zero_trust_device_assessments')
        .insert([{
          organization_id: currentOrganization.id,
          user_id: user.id,
          device_fingerprint: deviceFingerprint,
          trust_score: assessment.trustScore,
          risk_factors: assessment.riskFactors,
          compliance_status: assessment.complianceStatus,
          security_posture: assessment.securityPosture,
          network_context: assessment.networkContext,
          behavioral_score: assessment.behavioralScore,
          validation_result: assessment.validationResult,
          remediation_required: assessment.remediationRequired,
          remediation_actions: assessment.remediationActions
        }])
        .select()
        .single();

      if (error) throw error;
      
      setCurrentDeviceAssessment(data);
      loadDeviceAssessments();

      if (assessment.trustScore < 70) {
        toast({
          title: "Device Trust Score Low",
          description: `Your device scored ${assessment.trustScore}%. Review security recommendations.`,
          variant: "destructive"
        });
      }

    } catch (error: any) {
      console.error('Error assessing device:', error);
      toast({
        title: "Error Assessing Device",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setAssessing(false);
    }
  };

  const performDeviceAssessment = async () => {
    // Simulate comprehensive device assessment
    const assessment = {
      trustScore: 85,
      behavioralScore: 78,
      validationResult: 'passed' as const,
      remediationRequired: false,
      remediationActions: [] as string[],
      riskFactors: {},
      complianceStatus: {},
      securityPosture: {},
      networkContext: {}
    };

    // Browser security checks
    const browserChecks = {
      secure_context: globalThis.isSecureContext,
      private_browsing: false, // Would need more advanced detection
      extensions_detected: navigator.plugins?.length > 3,
      cookies_enabled: navigator.cookieEnabled,
      javascript_enabled: true,
      storage_available: typeof(Storage) !== "undefined"
    };

    // Network context
    const networkContext = {
      connection_type: (navigator as any).connection?.effectiveType || 'unknown',
      ip_address: sessionState.ipAddress,
      estimated_bandwidth: (navigator as any).connection?.downlink || 0,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
    };

    // Security posture
    const securityPosture = {
      screen_recording_possible: !!navigator.mediaDevices,
      clipboard_access: !!navigator.clipboard,
      notification_permission: Notification.permission,
      location_permission: 'unknown', // Would require permission request
      camera_available: !!navigator.mediaDevices?.getUserMedia,
      microphone_available: !!navigator.mediaDevices?.getUserMedia
    };

    // Compliance status
    const complianceStatus = {
      browser_updated: true, // Would need to check version
      security_extensions: false, // Would need extension detection
      antivirus_detected: false, // Not detectable from browser
      firewall_enabled: false, // Not detectable from browser
      encryption_supported: 'crypto' in window
    };

    // Calculate trust score based on factors
    let trustScore = 100;
    
    if (!browserChecks.secure_context) trustScore -= 20;
    if (!browserChecks.cookies_enabled) trustScore -= 10;
    if (browserChecks.extensions_detected) trustScore -= 5;
    if (networkContext.connection_type === 'slow-2g') trustScore -= 10;
    if (!complianceStatus.encryption_supported) trustScore -= 15;
    
    // Risk factors
    const riskFactors = {
      insecure_context: !browserChecks.secure_context,
      many_extensions: browserChecks.extensions_detected,
      slow_connection: networkContext.connection_type === 'slow-2g',
      unknown_network: networkContext.ip_address === 'unknown'
    };

    // Determine validation result
    let validationResult: 'passed' | 'failed' | 'conditional' = 'passed';
    if (trustScore < 50) {
      validationResult = 'failed';
    } else if (trustScore < 80) {
      validationResult = 'conditional';
    }

    // Remediation actions
    const remediationActions: string[] = [];
    if (!browserChecks.secure_context) {
      remediationActions.push('Use HTTPS connection');
    }
    if (browserChecks.extensions_detected) {
      remediationActions.push('Review browser extensions');
    }
    if (!complianceStatus.encryption_supported) {
      remediationActions.push('Update to modern browser');
    }

    return {
      trustScore: Math.max(0, Math.min(100, trustScore)),
      behavioralScore: Math.max(0, Math.min(100, trustScore)), // Derived from browser security checks above
      validationResult,
      remediationRequired: remediationActions.length > 0,
      remediationActions,
      riskFactors,
      complianceStatus,
      securityPosture,
      networkContext
    };
  };

  const getTrustScoreColor = (score: number) => {
    if (score >= 80) return 'text-success';
    if (score >= 60) return 'text-warning';
    return 'text-destructive';
  };

  const getTrustScoreBadge = (score: number) => {
    if (score >= 80) return { variant: 'default' as const, label: 'Trusted' };
    if (score >= 60) return { variant: 'secondary' as const, label: 'Conditional' };
    return { variant: 'destructive' as const, label: 'Untrusted' };
  };

  const getValidationIcon = (result: string) => {
    switch (result) {
      case 'passed': return <CheckCircle2 className="h-4 w-4 text-success" />;
      case 'conditional': return <AlertTriangle className="h-4 w-4 text-warning" />;
      case 'failed': return <XCircle className="h-4 w-4 text-destructive" />;
      default: return <Shield className="h-4 w-4" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Current Device Assessment */}
      <Card className="card-cyber">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center space-x-2">
              <Smartphone className="h-5 w-5" />
              <span>Current Device Assessment</span>
            </CardTitle>
            <Button
              onClick={assessCurrentDevice}
              disabled={assessing}
              variant="outline"
            >
              <RefreshCw className={`h-4 w-4 mr-2 ${assessing ? 'animate-spin' : ''}`} />
              {assessing ? 'Assessing...' : 'Reassess Device'}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {currentDeviceAssessment ? (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="space-y-4">
                <div>
                  <h4 className="font-semibold mb-2">Trust Score</h4>
                  <div className={`text-3xl font-bold ${getTrustScoreColor(currentDeviceAssessment.trust_score)}`}>
                    {currentDeviceAssessment.trust_score}%
                  </div>
                  <Progress value={currentDeviceAssessment.trust_score} className="mt-2" />
                  <Badge 
                    variant={getTrustScoreBadge(currentDeviceAssessment.trust_score).variant}
                    className="mt-2"
                  >
                    {getTrustScoreBadge(currentDeviceAssessment.trust_score).label}
                  </Badge>
                </div>
                <div>
                  <h4 className="font-semibold mb-2">Validation Result</h4>
                  <div className="flex items-center space-x-2">
                    {getValidationIcon(currentDeviceAssessment.validation_result)}
                    <span className="capitalize">{currentDeviceAssessment.validation_result}</span>
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                <div>
                  <h4 className="font-semibold mb-2">Behavioral Score</h4>
                  <div className="text-2xl font-bold">{currentDeviceAssessment.behavioral_score}%</div>
                  <Progress value={currentDeviceAssessment.behavioral_score} className="mt-2" />
                </div>
                <div>
                  <h4 className="font-semibold mb-2">Device Fingerprint</h4>
                  <code className="text-xs bg-muted p-2 rounded block">
                    {currentDeviceAssessment.device_fingerprint.substring(0, 16)}...
                  </code>
                </div>
              </div>

              <div className="space-y-4">
                <div>
                  <h4 className="font-semibold mb-2">Remediation Required</h4>
                  <Badge variant={currentDeviceAssessment.remediation_required ? "destructive" : "default"}>
                    {currentDeviceAssessment.remediation_required ? 'Yes' : 'No'}
                  </Badge>
                </div>
                {currentDeviceAssessment.remediation_actions.length > 0 && (
                  <div>
                    <h4 className="font-semibold mb-2">Recommended Actions</h4>
                    <ul className="text-sm space-y-1">
                      {currentDeviceAssessment.remediation_actions.map((action, index) => (
                        <li key={index} className="flex items-center space-x-2">
                          <AlertTriangle className="h-3 w-3 text-warning" />
                          <span>{action}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="text-center py-8">
              <Smartphone className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <h3 className="text-lg font-semibold mb-2">No Assessment Available</h3>
              <p className="text-muted-foreground mb-4">
                Assess your current device to get a trust score and security recommendations.
              </p>
              <Button onClick={assessCurrentDevice} disabled={assessing}>
                <Shield className="h-4 w-4 mr-2" />
                {assessing ? 'Assessing...' : 'Assess This Device'}
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Recent Assessments */}
      <Card className="card-cyber">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Eye className="h-5 w-5" />
            <span>Recent Device Assessments</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {assessments.length === 0 ? (
              <div className="text-center py-4">
                <p className="text-muted-foreground">No device assessments found.</p>
              </div>
            ) : (
              assessments.map((assessment) => (
                <Card key={assessment.id} className="border-muted">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <div className="p-2 bg-primary/10 rounded-lg">
                          <Monitor className="h-4 w-4" />
                        </div>
                        <div>
                          <div className="flex items-center space-x-2">
                            <span className="font-semibold">Trust Score: {assessment.trust_score}%</span>
                            {getValidationIcon(assessment.validation_result)}
                          </div>
                          <p className="text-sm text-muted-foreground">
                            {new Date(assessment.assessment_timestamp).toLocaleDateString()} • 
                            Behavioral: {assessment.behavioral_score}%
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Badge variant={getTrustScoreBadge(assessment.trust_score).variant}>
                          {getTrustScoreBadge(assessment.trust_score).label}
                        </Badge>
                        {assessment.remediation_required && (
                          <Badge variant="destructive">
                            Action Required
                          </Badge>
                        )}
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

export default ZeroTrustDeviceAssessment;