import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Shield, AlertTriangle, CheckCircle, XCircle, RefreshCw } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';

interface ComplianceResult {
  mfa_adoption_rate: number;
  unprotected_admin_accounts: number;
  inactive_sessions_requiring_cleanup: number;
  compliance_score: 'EXCELLENT' | 'GOOD' | 'FAIR' | 'POOR';
  recommendations: string[];
  checked_at: string;
}

export const SecurityCompliancePanel = () => {
  const [complianceData, setComplianceData] = useState<ComplianceResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [lastChecked, setLastChecked] = useState<Date | null>(null);

  const runComplianceCheck = async () => {
    setLoading(true);
    try {
      const { data, error } = await supabase.rpc('check_security_policy_compliance');
      
      if (error) {
        toast.error('Failed to run compliance check: ' + error.message);
        return;
      }

      setComplianceData(data as unknown as ComplianceResult);
      setLastChecked(new Date());
      toast.success('Security compliance check completed');
      
    } catch (error) {
      console.error('Compliance check error:', error);
      toast.error('Failed to run compliance check');
    } finally {
      setLoading(false);
    }
  };

  const correlateSecurityAlerts = async () => {
    try {
      await supabase.rpc('correlate_security_alerts');
      toast.success('Security alert correlation completed');
    } catch (error) {
      console.error('Alert correlation error:', error);
      toast.error('Failed to correlate security alerts');
    }
  };

  const getScoreColor = (score: string) => {
    switch (score) {
      case 'EXCELLENT': return 'bg-green-500';
      case 'GOOD': return 'bg-blue-500';
      case 'FAIR': return 'bg-yellow-500';
      case 'POOR': return 'bg-red-500';
      default: return 'bg-gray-500';
    }
  };

  const getScoreIcon = (score: string) => {
    switch (score) {
      case 'EXCELLENT': return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'GOOD': return <CheckCircle className="w-5 h-5 text-blue-500" />;
      case 'FAIR': return <AlertTriangle className="w-5 h-5 text-yellow-500" />;
      case 'POOR': return <XCircle className="w-5 h-5 text-red-500" />;
      default: return <Shield className="w-5 h-5 text-gray-500" />;
    }
  };

  useEffect(() => {
    runComplianceCheck();
  }, []);

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-lg font-medium flex items-center gap-2">
          <Shield className="w-5 h-5" />
          Security Compliance Status
        </CardTitle>
        <div className="flex gap-2">
          <Button 
            variant="outline" 
            size="sm" 
            onClick={correlateSecurityAlerts}
            className="text-xs"
          >
            Correlate Alerts
          </Button>
          <Button 
            variant="outline" 
            size="sm" 
            onClick={runComplianceCheck}
            disabled={loading}
            className="text-xs"
          >
            {loading ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              'Refresh Check'
            )}
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {lastChecked && (
          <p className="text-xs text-muted-foreground">
            Last checked: {lastChecked.toLocaleString()}
          </p>
        )}

        {complianceData ? (
          <>
            {/* Overall Compliance Score */}
            <div className="flex items-center justify-between p-4 border rounded-lg">
              <div className="flex items-center gap-2">
                {getScoreIcon(complianceData.compliance_score)}
                <div>
                  <p className="font-medium">Overall Security Score</p>
                  <p className="text-sm text-muted-foreground">
                    Based on MFA adoption and account protection
                  </p>
                </div>
              </div>
              <Badge className={getScoreColor(complianceData.compliance_score)}>
                {complianceData.compliance_score}
              </Badge>
            </div>

            {/* MFA Adoption Rate */}
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <span className="text-sm font-medium">MFA Adoption Rate</span>
                <span className="text-sm">{complianceData.mfa_adoption_rate}%</span>
              </div>
              <Progress value={complianceData.mfa_adoption_rate} className="h-2" />
              {complianceData.mfa_adoption_rate < 70 && (
                <Alert>
                  <AlertTriangle className="w-4 h-4" />
                  <AlertDescription className="text-sm">
                    MFA adoption is below recommended 70% threshold
                  </AlertDescription>
                </Alert>
              )}
            </div>

            {/* Security Metrics */}
            <div className="grid grid-cols-2 gap-4">
              <div className="p-3 border rounded-lg">
                <p className="text-2xl font-bold text-red-500">
                  {complianceData.unprotected_admin_accounts}
                </p>
                <p className="text-sm text-muted-foreground">
                  Unprotected Admin Accounts
                </p>
              </div>
              <div className="p-3 border rounded-lg">
                <p className="text-2xl font-bold text-yellow-500">
                  {complianceData.inactive_sessions_requiring_cleanup}
                </p>
                <p className="text-sm text-muted-foreground">
                  Inactive Sessions
                </p>
              </div>
            </div>

            {/* Recommendations */}
            {complianceData.recommendations.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-sm font-medium">Security Recommendations</h4>
                <div className="space-y-1">
                  {complianceData.recommendations.map((rec, index) => (
                    <Alert key={index}>
                      <AlertTriangle className="w-4 h-4" />
                      <AlertDescription className="text-sm">{rec}</AlertDescription>
                    </Alert>
                  ))}
                </div>
              </div>
            )}

            {/* Critical Issues Alert */}
            {(complianceData.unprotected_admin_accounts > 0 || 
              complianceData.mfa_adoption_rate < 50) && (
              <Alert className="border-red-200 bg-red-50">
                <XCircle className="w-4 h-4 text-red-500" />
                <AlertDescription>
                  <strong>Critical Security Issues Detected:</strong> Immediate action 
                  required to secure admin accounts and improve MFA adoption.
                </AlertDescription>
              </Alert>
            )}
          </>
        ) : (
          <div className="flex items-center justify-center p-8 text-muted-foreground">
            {loading ? (
              <div className="flex items-center gap-2">
                <RefreshCw className="w-4 h-4 animate-spin" />
                Running security compliance check...
              </div>
            ) : (
              'Click "Refresh Check" to run security compliance analysis'
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
};