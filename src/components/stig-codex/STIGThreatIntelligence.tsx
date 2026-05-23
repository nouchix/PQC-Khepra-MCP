/**
 * STIG Threat Intelligence Component
 * Correlates threat intelligence with STIG requirements
 */

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { 
  Shield, 
  AlertTriangle, 
  TrendingUp, 
  Eye, 
  RefreshCw,
  Activity,
  Target,
  Zap
} from 'lucide-react';
import { useSTIGCodex } from '@/hooks/useSTIGCodex';
import { useOrganization } from '@/hooks/useOrganization';

export const STIGThreatIntelligence = () => {
  const { currentOrganization } = useOrganization();
  const {
    threatCorrelations,
    aiAnalyses,
    loading,
    correlateThreatIntel,
    analyzeOptimization,
    generatePredictiveRecommendations
  } = useSTIGCodex(currentOrganization?.id || '');

  const [selectedThreatSources, setSelectedThreatSources] = useState([
    'disa_vulnerability',
    'cve_nvd',
    'mitre_attack'
  ]);

  useEffect(() => {
    if (currentOrganization?.id) {
      handleThreatCorrelation();
    }
  }, [currentOrganization]);

  const handleThreatCorrelation = async () => {
    if (!currentOrganization?.id) return;
    await correlateThreatIntel(selectedThreatSources);
  };

  const handlePredictiveAnalysis = async () => {
    if (!currentOrganization?.id) return;
    await generatePredictiveRecommendations({
      analysis_depth: 'comprehensive',
      prediction_horizon_days: 30,
      include_emerging_threats: true
    });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-50 border-red-200';
      case 'high': return 'text-orange-600 bg-orange-50 border-orange-200';
      case 'medium': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'low': return 'text-blue-600 bg-blue-50 border-blue-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getThreatSourceIcon = (source: string) => {
    switch (source) {
      case 'disa_vulnerability': return <Shield className="w-4 h-4" />;
      case 'cve_nvd': return <AlertTriangle className="w-4 h-4" />;
      case 'mitre_attack': return <Target className="w-4 h-4" />;
      default: return <Activity className="w-4 h-4" />;
    }
  };

  const criticalThreats = threatCorrelations.filter(t => t.risk_elevation === 'critical').length;
  const highThreats = threatCorrelations.filter(t => t.risk_elevation === 'high').length;
  const averageConfidence = threatCorrelations.length > 0 ? 
    threatCorrelations.reduce((sum, t) => sum + t.correlation_confidence, 0) / threatCorrelations.length : 0;

  return (
    <div className="space-y-6">
      {/* Threat Intelligence Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Active Threats</p>
                <p className="text-2xl font-bold">{threatCorrelations.length}</p>
              </div>
              <Activity className="w-8 h-8 text-blue-600" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Critical Threats</p>
                <p className="text-2xl font-bold text-red-600">{criticalThreats}</p>
              </div>
              <AlertTriangle className="w-8 h-8 text-red-600" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">High Priority</p>
                <p className="text-2xl font-bold text-orange-600">{highThreats}</p>
              </div>
              <TrendingUp className="w-8 h-8 text-orange-600" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Avg Confidence</p>
                <p className="text-2xl font-bold">{Math.round(averageConfidence * 100)}%</p>
              </div>
              <Eye className="w-8 h-8 text-green-600" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Actions */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="w-5 h-5" />
            Threat Intelligence Operations
          </CardTitle>
          <CardDescription>
            Correlate threat intelligence with STIG requirements and generate predictive recommendations
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4">
            <Button onClick={handleThreatCorrelation} disabled={loading}>
              <RefreshCw className="w-4 h-4 mr-2" />
              Refresh Threat Intel
            </Button>
            <Button variant="outline" onClick={handlePredictiveAnalysis} disabled={loading}>
              <Zap className="w-4 h-4 mr-2" />
              Generate Predictions
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Threat Correlations */}
      <Card>
        <CardHeader>
          <CardTitle>Threat Correlations</CardTitle>
          <CardDescription>
            Real-time threat intelligence correlated with STIG requirements
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="active" className="w-full">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="active">Active Threats</TabsTrigger>
              <TabsTrigger value="predictions">AI Predictions</TabsTrigger>
              <TabsTrigger value="recommendations">Recommendations</TabsTrigger>
            </TabsList>

            <TabsContent value="active" className="space-y-4">
              {threatCorrelations.length > 0 ? (
                threatCorrelations.map((threat) => (
                  <div
                    key={threat.id}
                    className={`p-4 border rounded-lg ${getSeverityColor(threat.risk_elevation)}`}
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-center gap-2">
                        {getThreatSourceIcon(threat.threat_source)}
                        <div>
                          <div className="font-medium">{threat.threat_indicator}</div>
                          <div className="text-sm opacity-75">{threat.threat_type}</div>
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <Badge 
                          variant={threat.risk_elevation === 'critical' ? 'destructive' : 
                                 threat.risk_elevation === 'high' ? 'secondary' : 'outline'}
                        >
                          {threat.risk_elevation} risk
                        </Badge>
                        <Badge variant="outline">
                          {Math.round(threat.correlation_confidence * 100)}% confidence
                        </Badge>
                      </div>
                    </div>

                    <div className="mb-3">
                      <div className="text-sm font-medium mb-1">Correlated STIG Rules:</div>
                      <div className="flex flex-wrap gap-1">
                        {threat.correlated_stig_rules.map((rule, index) => (
                          <Badge key={index} variant="secondary">
                            {rule}
                          </Badge>
                        ))}
                      </div>
                    </div>

                    {threat.correlation_details && (
                      <p className="text-sm opacity-90 mb-3">{threat.correlation_details}</p>
                    )}

                    {threat.mitigation_recommendations && threat.mitigation_recommendations.length > 0 && (
                      <div>
                        <div className="text-sm font-medium mb-1">Recommended Actions:</div>
                        <ul className="text-sm list-disc list-inside space-y-1">
                          {threat.mitigation_recommendations.map((rec, index) => (
                            <li key={index}>{rec}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {threat.automated_response_triggered && (
                      <Alert className="mt-3">
                        <Zap className="h-4 w-4" />
                        <AlertDescription>
                          Automated response has been triggered for this threat
                        </AlertDescription>
                      </Alert>
                    )}
                  </div>
                ))
              ) : (
                <div className="text-center text-muted-foreground py-8">
                  No active threat correlations found
                </div>
              )}
            </TabsContent>

            <TabsContent value="predictions" className="space-y-4">
              {aiAnalyses.filter(a => a.analysis_type === 'predictive').length > 0 ? (
                aiAnalyses
                  .filter(a => a.analysis_type === 'predictive')
                  .map((analysis) => (
                    <div key={analysis.id} className="p-4 border rounded-lg">
                      <div className="flex items-center justify-between mb-3">
                        <div className="font-medium">Predictive Analysis</div>
                        <Badge variant="outline">
                          {Math.round(analysis.confidence_score * 100)}% confidence
                        </Badge>
                      </div>

                      <div className="space-y-2">
                        {analysis.recommendations.map((rec, index) => (
                          <div key={index} className="p-2 bg-muted rounded text-sm">
                            {rec}
                          </div>
                        ))}
                      </div>

                      {analysis.estimated_impact && (
                        <div className="mt-3 text-sm text-muted-foreground">
                          Estimated Impact: {analysis.estimated_impact}
                        </div>
                      )}
                    </div>
                  ))
              ) : (
                <div className="text-center text-muted-foreground py-8">
                  No predictive analyses available. Click "Generate Predictions" to create new analyses.
                </div>
              )}
            </TabsContent>

            <TabsContent value="recommendations" className="space-y-4">
              <div className="grid gap-4">
                {/* Static recommendations based on threat intelligence */}
                <div className="p-4 border rounded-lg">
                  <div className="font-medium mb-2">Enhanced Monitoring</div>
                  <p className="text-sm text-muted-foreground mb-2">
                    Implement enhanced monitoring for high-risk STIG controls based on current threat landscape
                  </p>
                  <div className="flex flex-wrap gap-1">
                    <Badge variant="secondary">V-220857</Badge>
                    <Badge variant="secondary">V-220858</Badge>
                    <Badge variant="secondary">V-220859</Badge>
                  </div>
                </div>

                <div className="p-4 border rounded-lg">
                  <div className="font-medium mb-2">Priority Hardening</div>
                  <p className="text-sm text-muted-foreground mb-2">
                    Focus on these STIG implementations to mitigate emerging threats
                  </p>
                  <div className="flex flex-wrap gap-1">
                    <Badge variant="secondary">V-220123</Badge>
                    <Badge variant="secondary">V-220124</Badge>
                  </div>
                </div>

                <div className="p-4 border rounded-lg">
                  <div className="font-medium mb-2">Automated Response</div>
                  <p className="text-sm text-muted-foreground">
                    Enable automated STIG remediation for critical threat indicators
                  </p>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};