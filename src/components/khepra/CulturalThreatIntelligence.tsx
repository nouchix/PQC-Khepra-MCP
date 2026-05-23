import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { 
  Globe, TrendingUp, AlertTriangle, Brain, Eye, Sparkles,
  Shield, Target, Zap, Activity, RefreshCw
} from 'lucide-react';
import { CulturalThreatTaxonomy, SymbolicThreatAnalysis } from '@/khepra/taxonomy/CulturalThreatTaxonomy';
import { AdinkraSymbolDisplay } from './AdinkraSymbolDisplay';
import { useThreatIntelligence } from '@/hooks/useThreatIntelligence';
import { useToast } from '@/hooks/use-toast';

interface CulturalIntelligenceMetrics {
  totalPatterns: number;
  criticalPatterns: number;
  riskAmplification: number;
  culturalCoverage: number;
}

export const CulturalThreatIntelligence = () => {
  const { threats, loading } = useThreatIntelligence();
  const [symbolicAnalysis, setSymbolicAnalysis] = useState<SymbolicThreatAnalysis[]>([]);
  const [selectedPattern, setSelectedPattern] = useState<string | null>(null);
  const [metrics, setMetrics] = useState<CulturalIntelligenceMetrics>({
    totalPatterns: 0,
    criticalPatterns: 0,
    riskAmplification: 0,
    culturalCoverage: 0
  });
  const [evolutionPredictions, setEvolutionPredictions] = useState<Record<string, number>>({});
  const { toast } = useToast();

  useEffect(() => {
    if (threats.length > 0) {
      performCulturalAnalysis();
    }
  }, [threats]);

  const performCulturalAnalysis = async () => {
    try {
      // Perform symbolic pattern analysis
      const analysis = CulturalThreatTaxonomy.analyzeSymbolicPatterns(threats);
      setSymbolicAnalysis(analysis);

      // Calculate metrics
      const totalPatterns = analysis.reduce((sum, a) => sum + a.detectedPatterns.length, 0);
      const criticalPatterns = analysis.reduce((sum, a) => 
        sum + a.detectedPatterns.filter(p => p.severity === 'critical').length, 0
      );
      const avgRiskAmplification = analysis.reduce((sum, a) => sum + a.riskAmplification, 0) / analysis.length;
      const coverage = Math.min(100, (totalPatterns / threats.length) * 100);

      setMetrics({
        totalPatterns,
        criticalPatterns,
        riskAmplification: avgRiskAmplification || 0,
        culturalCoverage: coverage
      });

      // Generate evolution predictions
      const predictions = CulturalThreatTaxonomy.predictThreatEvolution(threats);
      setEvolutionPredictions(predictions);

    } catch (error) {
      console.error('Cultural analysis error:', error);
      toast({
        title: "Analysis Error",
        description: "Failed to perform cultural threat analysis",
        variant: "destructive"
      });
    }
  };

  const generateHuntingQueries = (symbol: string) => {
    const queries = CulturalThreatTaxonomy.generateHuntingQueries(symbol);
    
    // In a real implementation, this would trigger threat hunting
    toast({
      title: "Hunting Queries Generated",
      description: `Generated ${queries.length} cultural threat hunting queries for ${symbol}`,
    });
    
    console.log(`Hunting queries for ${symbol}:`, queries);
  };

  const getPatternSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-400 bg-red-500/20 border-red-500/30';
      case 'high': return 'text-orange-400 bg-orange-500/20 border-orange-500/30';
      case 'medium': return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30';
      case 'low': return 'text-green-400 bg-green-500/20 border-green-500/30';
      default: return 'text-gray-400 bg-gray-500/20 border-gray-500/30';
    }
  };

  const getEvolutionProbabilityColor = (probability: number) => {
    if (probability >= 0.7) return 'text-red-400';
    if (probability >= 0.4) return 'text-yellow-400';
    return 'text-green-400';
  };

  if (loading) {
    return (
      <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Sparkles className="h-5 w-5 text-purple-400" />
            <span>Cultural Threat Intelligence</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center text-muted-foreground">
            Analyzing cultural patterns...
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Cultural Intelligence Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Brain className="h-5 w-5 text-purple-400" />
              <div>
                <p className="text-sm text-muted-foreground">Cultural Patterns</p>
                <p className="text-2xl font-bold text-purple-400">{metrics.totalPatterns}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="h-5 w-5 text-red-400" />
              <div>
                <p className="text-sm text-muted-foreground">Critical Patterns</p>
                <p className="text-2xl font-bold text-red-400">{metrics.criticalPatterns}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <TrendingUp className="h-5 w-5 text-yellow-400" />
              <div>
                <p className="text-sm text-muted-foreground">Risk Amplification</p>
                <p className="text-2xl font-bold text-yellow-400">
                  +{Math.round(metrics.riskAmplification * 100)}%
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Eye className="h-5 w-5 text-blue-400" />
              <div>
                <p className="text-sm text-muted-foreground">Cultural Coverage</p>
                <p className="text-2xl font-bold text-blue-400">
                  {Math.round(metrics.culturalCoverage)}%
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Content Tabs */}
      <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center space-x-2">
              <Sparkles className="h-5 w-5 text-purple-400" />
              <span>Cultural Threat Intelligence</span>
            </CardTitle>
            <Button
              size="sm"
              variant="outline"
              onClick={performCulturalAnalysis}
              disabled={loading}
            >
              <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
              Refresh Analysis
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="patterns" className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="patterns">Pattern Analysis</TabsTrigger>
              <TabsTrigger value="symbols">Adinkra Symbols</TabsTrigger>
              <TabsTrigger value="hunting">Threat Hunting</TabsTrigger>
              <TabsTrigger value="predictions">Evolution Predictions</TabsTrigger>
            </TabsList>

            <TabsContent value="patterns" className="space-y-4">
              <ScrollArea className="h-[500px]">
                <div className="space-y-4">
                  {symbolicAnalysis.map((analysis, index) => (
                    <Card key={analysis.threatId} className="border-border/50">
                      <CardContent className="p-4">
                        <div className="space-y-3">
                          <div className="flex items-center justify-between">
                            <h3 className="font-semibold">Threat: {analysis.threatId}</h3>
                            <div className="flex items-center space-x-2">
                              <Badge variant="outline" className="text-xs">
                                Amplification: +{Math.round(analysis.riskAmplification * 100)}%
                              </Badge>
                              {analysis.symbolicFingerprint && (
                                <Badge variant="outline" className="text-xs font-mono">
                                  {analysis.symbolicFingerprint.split(':')[2]?.substring(0, 8)}...
                                </Badge>
                              )}
                            </div>
                          </div>

                          {analysis.detectedPatterns.length > 0 && (
                            <div>
                              <h4 className="text-sm font-medium mb-2">Detected Cultural Patterns:</h4>
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                {analysis.detectedPatterns.map((pattern, idx) => (
                                  <div
                                    key={idx}
                                    className={`p-2 rounded border ${getPatternSeverityColor(pattern.severity)}`}
                                  >
                                    <div className="flex items-center justify-between">
                                      <span className="text-sm font-medium">{pattern.name}</span>
                                      <Badge 
                                        className={getPatternSeverityColor(pattern.severity)}
                                        variant="outline"
                                      >
                                        {pattern.severity}
                                      </Badge>
                                    </div>
                                    <p className="text-xs mt-1 opacity-90">{pattern.culturalMeaning}</p>
                                    <div className="flex items-center justify-between mt-1">
                                      <span className="text-xs">Symbol: {pattern.adinkraSymbol}</span>
                                      <Button
                                        size="sm"
                                        variant="ghost"
                                        className="h-6 text-xs"
                                        onClick={() => generateHuntingQueries(pattern.adinkraSymbol)}
                                      >
                                        <Target className="h-3 w-3 mr-1" />
                                        Hunt
                                      </Button>
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {analysis.culturalRecommendations.length > 0 && (
                            <div>
                              <h4 className="text-sm font-medium mb-2">Cultural Recommendations:</h4>
                              <div className="space-y-1">
                                {analysis.culturalRecommendations.slice(0, 3).map((rec, idx) => (
                                  <div key={idx} className="flex items-start space-x-2">
                                    <Zap className="h-3 w-3 text-yellow-400 mt-0.5 flex-shrink-0" />
                                    <span className="text-xs">{rec}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {analysis.culturalCorrelations.length > 0 && (
                            <div>
                              <h4 className="text-sm font-medium mb-2">Cultural Correlations:</h4>
                              <div className="flex flex-wrap gap-1">
                                {analysis.culturalCorrelations.map((corr, idx) => (
                                  <Badge key={idx} variant="secondary" className="text-xs">
                                    {corr}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      </CardContent>
                    </Card>
                  ))}

                  {symbolicAnalysis.length === 0 && (
                    <div className="text-center py-8 text-muted-foreground">
                      <Brain className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No cultural patterns detected in current threats.</p>
                      <p className="text-sm">Import threat data to begin cultural analysis.</p>
                    </div>
                  )}
                </div>
              </ScrollArea>
            </TabsContent>

            <TabsContent value="symbols" className="space-y-4">
              <AdinkraSymbolDisplay showMatrix={true} showMeaning={true} />
            </TabsContent>

            <TabsContent value="hunting" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {CulturalThreatTaxonomy.getAllPatterns().map((pattern) => (
                  <Card key={pattern.id} className="border-border/50">
                    <CardContent className="p-4">
                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <h3 className="font-semibold">{pattern.name}</h3>
                          <Badge className={getPatternSeverityColor(pattern.severity)}>
                            {pattern.severity}
                          </Badge>
                        </div>
                        
                        <p className="text-sm text-muted-foreground">
                          {pattern.culturalMeaning}
                        </p>
                        
                        <div className="space-y-2">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-medium">Adinkra Symbol:</span>
                            <Badge variant="outline" className="text-xs">
                              {pattern.adinkraSymbol}
                            </Badge>
                          </div>
                          
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-medium">Threat Categories:</span>
                            <span className="text-xs text-muted-foreground">
                              {pattern.threatCategories.length}
                            </span>
                          </div>
                        </div>
                        
                        <Button
                          size="sm"
                          className="w-full"
                          onClick={() => generateHuntingQueries(pattern.adinkraSymbol)}
                        >
                          <Target className="h-4 w-4 mr-2" />
                          Generate Hunting Queries
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </TabsContent>

            <TabsContent value="predictions" className="space-y-4">
              <div className="space-y-4">
                <div className="text-sm text-muted-foreground mb-4">
                  Evolution predictions based on current threat patterns and Adinkra transformations:
                </div>
                
                {Object.entries(evolutionPredictions).map(([patternId, probability]) => {
                  const pattern = CulturalThreatTaxonomy.getAllPatterns().find(p => p.id === patternId);
                  if (!pattern) return null;
                  
                  return (
                    <Card key={patternId} className="border-border/50">
                      <CardContent className="p-4">
                        <div className="space-y-3">
                          <div className="flex items-center justify-between">
                            <div>
                              <h3 className="font-semibold">{pattern.name}</h3>
                              <p className="text-sm text-muted-foreground">{pattern.culturalMeaning}</p>
                            </div>
                            <div className="text-right">
                              <div className={`text-lg font-bold ${getEvolutionProbabilityColor(probability)}`}>
                                {Math.round(probability * 100)}%
                              </div>
                              <div className="text-xs text-muted-foreground">Evolution Risk</div>
                            </div>
                          </div>
                          
                          <Progress 
                            value={probability * 100} 
                            className="h-2"
                          />
                          
                          <div className="flex items-center justify-between text-xs">
                            <span className="text-muted-foreground">
                              Transformation Path: {pattern.transformationPath.join(' → ')}
                            </span>
                            <Badge 
                              variant="outline" 
                              className={getPatternSeverityColor(pattern.severity)}
                            >
                              {pattern.severity}
                            </Badge>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  );
                })}
                
                {Object.keys(evolutionPredictions).length === 0 && (
                  <div className="text-center py-8 text-muted-foreground">
                    <Activity className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No evolution predictions available.</p>
                    <p className="text-sm">Threat data needed for predictive analysis.</p>
                  </div>
                )}
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};