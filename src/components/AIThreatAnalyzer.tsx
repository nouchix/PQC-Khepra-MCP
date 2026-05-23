import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Progress } from '@/components/ui/progress';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { 
  Brain, Zap, Target, TrendingUp, AlertTriangle, CheckCircle, 
  Clock, Globe, Shield, Activity, BarChart3, MapPin,
  Play, RefreshCw, Eye, Lightbulb
} from 'lucide-react';
import { useAIThreatAnalyzer, AnalysisRequest } from '@/hooks/useAIThreatAnalyzer';
import { formatDistanceToNow } from 'date-fns';

export const AIThreatAnalyzer = () => {
  const { 
    loading, 
    analyses, 
    currentAnalysis, 
    runAnalysis, 
    generateRealtimeInsights,
    clearAnalyses 
  } = useAIThreatAnalyzer();

  const [analysisConfig, setAnalysisConfig] = useState<AnalysisRequest>({
    data_source: 'combined',
    time_range: '24h'
  });

  const realtimeInsights = generateRealtimeInsights();

  const handleRunAnalysis = () => {
    runAnalysis(analysisConfig);
  };

  const getRiskScoreColor = (score: number) => {
    if (score >= 80) return 'text-destructive';
    if (score >= 60) return 'text-warning';
    if (score >= 40) return 'text-info';
    return 'text-success';
  };

  const getThreatLevelColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'high': return 'bg-destructive text-destructive-foreground';
      case 'medium': return 'bg-warning text-warning-foreground';
      case 'low': return 'bg-success text-success-foreground';
      default: return 'bg-secondary text-secondary-foreground';
    }
  };

  return (
    <div className="space-y-6">
      {/* Real-time Insights Header */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Current Threat Level</p>
                <Badge className={getThreatLevelColor(realtimeInsights.current_threat_level)}>
                  {realtimeInsights.current_threat_level}
                </Badge>
              </div>
              <Brain className="h-8 w-8 text-primary" />
            </div>
          </CardContent>
        </Card>

        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Active Campaigns</p>
                <p className="text-2xl font-bold text-warning">{realtimeInsights.active_campaigns}</p>
              </div>
              <Target className="h-8 w-8 text-warning" />
            </div>
          </CardContent>
        </Card>

        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Prediction Accuracy</p>
                <p className="text-2xl font-bold text-success">{realtimeInsights.prediction_accuracy}%</p>
              </div>
              <BarChart3 className="h-8 w-8 text-success" />
            </div>
          </CardContent>
        </Card>

        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">AI Status</p>
                <p className="text-sm font-bold text-primary">
                  {loading ? 'Processing...' : 'Ready'}
                </p>
              </div>
              <Zap className={`h-8 w-8 ${loading ? 'animate-pulse text-warning' : 'text-primary'}`} />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Analysis Interface */}
      <Card className="card-cyber">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center space-x-2">
                <Brain className="h-5 w-5 text-primary" />
                <span>AI Threat Analysis Engine</span>
              </CardTitle>
              <CardDescription>
                Advanced machine learning algorithms for threat pattern detection and risk assessment
              </CardDescription>
            </div>
            <div className="flex items-center space-x-2">
              <Button
                variant="outline"
                size="sm"
                onClick={clearAnalyses}
                disabled={loading || analyses.length === 0}
              >
                <RefreshCw className="h-4 w-4 mr-2" />
                Clear
              </Button>
              <Button
                onClick={handleRunAnalysis}
                disabled={loading}
                className="bg-primary hover:bg-primary/90"
              >
                {loading ? (
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <Play className="h-4 w-4 mr-2" />
                )}
                Run Analysis
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {/* Analysis Configuration */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            <div className="space-y-2">
              <label className="text-sm font-medium text-foreground">Data Source</label>
              <Select
                value={analysisConfig.data_source}
                onValueChange={(value) => setAnalysisConfig(prev => ({ ...prev, data_source: value as any }))}
              >
                <SelectTrigger className="bg-card border-border">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="threat_intelligence">Threat Intelligence Only</SelectItem>
                  <SelectItem value="security_events">Security Events Only</SelectItem>
                  <SelectItem value="combined">Combined Analysis</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium text-foreground">Time Range</label>
              <Select
                value={analysisConfig.time_range}
                onValueChange={(value) => setAnalysisConfig(prev => ({ ...prev, time_range: value as any }))}
              >
                <SelectTrigger className="bg-card border-border">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1h">Last Hour</SelectItem>
                  <SelectItem value="6h">Last 6 Hours</SelectItem>
                  <SelectItem value="24h">Last 24 Hours</SelectItem>
                  <SelectItem value="7d">Last 7 Days</SelectItem>
                  <SelectItem value="30d">Last 30 Days</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Analysis Results */}
          <Tabs defaultValue="current" className="space-y-4">
            <TabsList className="bg-card border border-border">
              <TabsTrigger value="current">Current Analysis</TabsTrigger>
              <TabsTrigger value="history">Analysis History</TabsTrigger>
              <TabsTrigger value="insights">Live Insights</TabsTrigger>
            </TabsList>

            <TabsContent value="current" className="space-y-4">
              {currentAnalysis ? (
                <div className="space-y-6">
                  {/* Analysis Overview */}
                  <Card className="card-cyber">
                    <CardHeader>
                      <CardTitle className="flex items-center justify-between">
                        <span>Analysis Results</span>
                        <div className="flex items-center space-x-4">
                          <div className="text-right">
                            <div className={`text-2xl font-bold ${getRiskScoreColor(currentAnalysis.risk_score)}`}>
                              {currentAnalysis.risk_score}/100
                            </div>
                            <div className="text-xs text-muted-foreground">Risk Score</div>
                          </div>
                          <div className="text-right">
                            <div className="text-lg font-bold text-info">
                              {currentAnalysis.confidence_level}%
                            </div>
                            <div className="text-xs text-muted-foreground">Confidence</div>
                          </div>
                        </div>
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-4">
                        <div>
                          <h4 className="font-medium text-foreground mb-2">Analysis Summary</h4>
                          <p className="text-sm text-muted-foreground leading-relaxed">
                            {currentAnalysis.analysis_summary}
                          </p>
                        </div>
                        
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div>
                            <h4 className="font-medium text-foreground mb-2">Timeline Prediction</h4>
                            <div className="flex items-center space-x-2 mb-1">
                              <TrendingUp className={`h-4 w-4 ${
                                currentAnalysis.timeline_analysis.trend === 'increasing' ? 'text-destructive' :
                                currentAnalysis.timeline_analysis.trend === 'decreasing' ? 'text-success' : 'text-info'
                              }`} />
                              <Badge variant="outline" className={
                                currentAnalysis.timeline_analysis.trend === 'increasing' ? 'border-destructive text-destructive' :
                                currentAnalysis.timeline_analysis.trend === 'decreasing' ? 'border-success text-success' : 'border-info text-info'
                              }>
                                {currentAnalysis.timeline_analysis.trend}
                              </Badge>
                            </div>
                            <p className="text-xs text-muted-foreground">
                              {currentAnalysis.timeline_analysis.prediction}
                            </p>
                          </div>
                          
                          <div>
                            <h4 className="font-medium text-foreground mb-2">Correlation Data</h4>
                            <div className="space-y-1 text-sm">
                              <div className="flex justify-between">
                                <span className="text-muted-foreground">Related Incidents:</span>
                                <span className="text-foreground">{currentAnalysis.correlation_data.related_incidents}</span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-muted-foreground">Affected Systems:</span>
                                <span className="text-foreground">{currentAnalysis.correlation_data.affected_systems.length}</span>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  {/* Recommendations */}
                  <Card className="card-cyber">
                    <CardHeader>
                      <CardTitle className="flex items-center space-x-2">
                        <Lightbulb className="h-5 w-5 text-warning" />
                        <span>AI Recommendations</span>
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-3">
                        {currentAnalysis.recommendations.map((rec, index) => (
                          <div key={index} className="flex items-start space-x-3 p-3 rounded-lg border border-border bg-accent/50">
                            <CheckCircle className="h-4 w-4 text-success mt-0.5 flex-shrink-0" />
                            <span className="text-sm text-foreground">{rec}</span>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>

                  {/* Attack Patterns */}
                  <Card className="card-cyber">
                    <CardHeader>
                      <CardTitle className="flex items-center space-x-2">
                        <Target className="h-5 w-5 text-destructive" />
                        <span>Detected Attack Patterns</span>
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-2">
                        {currentAnalysis.attack_patterns.map((pattern, index) => (
                          <div key={index} className="flex items-center space-x-3 p-2 rounded border border-border">
                            <AlertTriangle className="h-4 w-4 text-warning flex-shrink-0" />
                            <span className="text-sm text-foreground">{pattern}</span>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                </div>
              ) : (
                <div className="text-center text-muted-foreground py-12">
                  <Brain className="h-16 w-16 mx-auto mb-4 opacity-50" />
                  <p className="text-lg font-medium mb-2">No Analysis Available</p>
                  <p className="text-sm">Run an analysis to see AI-powered threat insights</p>
                </div>
              )}
            </TabsContent>

            <TabsContent value="history" className="space-y-4">
              <ScrollArea className="h-96">
                <div className="space-y-3">
                  {analyses.length === 0 ? (
                    <div className="text-center text-muted-foreground py-8">
                      <Clock className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No analysis history available</p>
                    </div>
                  ) : (
                    analyses.map((analysis, index) => (
                      <Card key={analysis.id} className="card-cyber cursor-pointer hover:bg-accent/50 transition-colors">
                        <CardContent className="p-4">
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center space-x-2">
                              <Brain className="h-4 w-4 text-primary" />
                              <span className="font-medium text-foreground">
                                Analysis #{analyses.length - index}
                              </span>
                            </div>
                            <div className="flex items-center space-x-2">
                              <div className={`text-lg font-bold ${getRiskScoreColor(analysis.risk_score)}`}>
                                {analysis.risk_score}
                              </div>
                              <div className="text-xs text-muted-foreground">
                                {formatDistanceToNow(new Date(analysis.created_at), { addSuffix: true })}
                              </div>
                            </div>
                          </div>
                          <p className="text-sm text-muted-foreground line-clamp-2">
                            {analysis.analysis_summary}
                          </p>
                          <div className="flex items-center space-x-4 mt-2 text-xs text-muted-foreground">
                            <span>{analysis.threat_indicators.length} indicators</span>
                            <span>{analysis.confidence_level}% confidence</span>
                            <span>{analysis.attack_patterns.length} patterns</span>
                          </div>
                        </CardContent>
                      </Card>
                    ))
                  )}
                </div>
              </ScrollArea>
            </TabsContent>

            <TabsContent value="insights" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Card className="card-cyber">
                  <CardHeader>
                    <CardTitle className="text-sm">Emerging Threats</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {realtimeInsights.emerging_threats.map((threat, index) => (
                        <div key={index} className="flex items-start space-x-2">
                          <AlertTriangle className="h-4 w-4 text-warning mt-0.5 flex-shrink-0" />
                          <span className="text-sm text-foreground">{threat}</span>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>

                <Card className="card-cyber">
                  <CardHeader>
                    <CardTitle className="text-sm">System Performance</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div>
                        <div className="flex justify-between text-sm mb-1">
                          <span className="text-muted-foreground">Processing Speed</span>
                          <span className="text-foreground">98%</span>
                        </div>
                        <Progress value={98} className="h-2" />
                      </div>
                      <div>
                        <div className="flex justify-between text-sm mb-1">
                          <span className="text-muted-foreground">Accuracy Rate</span>
                          <span className="text-foreground">{realtimeInsights.prediction_accuracy}%</span>
                        </div>
                        <Progress value={realtimeInsights.prediction_accuracy} className="h-2" />
                      </div>
                      <div>
                        <div className="flex justify-between text-sm mb-1">
                          <span className="text-muted-foreground">Model Confidence</span>
                          <span className="text-foreground">94%</span>
                        </div>
                        <Progress value={94} className="h-2" />
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};