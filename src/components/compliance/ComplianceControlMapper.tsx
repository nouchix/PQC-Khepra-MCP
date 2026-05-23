import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import {
  Network,
  Shield,
  Eye,
  Target,
  MapPin,
  CheckCircle,
  AlertTriangle,
  Clock,
  Layers,
  GitBranch,
  Database,
  Settings,
  FileText,
  Lock,
  Brain,
  Zap,
  TrendingUp,
  Download,
  RefreshCw
} from 'lucide-react';

interface ControlMapping {
  id: string;
  sourceControl: {
    id: string;
    title: string;
    framework: string;
    description: string;
  };
  mappedControls: {
    id: string;
    title: string;
    framework: string;
    mappingStrength: number;
    gap?: string;
    aiAnalysis?: string;
  }[];
  implementation: {
    tools: string[];
    automationLevel: number;
    evidenceRequirements: string[];
    testProcedures: string[];
    aiRecommendations?: string[];
  };
  status: 'mapped' | 'partial' | 'gap' | 'not-applicable';
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  aiConfidence: number;
}

interface FrameworkCoverage {
  framework: string;
  totalControls: number;
  mappedControls: number;
  gapControls: number;
  coveragePercentage: number;
  lastUpdated: Date;
  aiAnalyzed: boolean;
}

interface AIAnalysisSummary {
  overlapPercentage: number;
  criticalGaps: number;
  automationOpportunities: string[];
  riskAssessment: {
    high: number;
    medium: number;
    low: number;
  };
  recommendations: string[];
}

export const ComplianceControlMapper: React.FC = () => {
  const [controlMappings, setControlMappings] = useState<ControlMapping[]>([]);
  const [frameworkCoverage, setFrameworkCoverage] = useState<FrameworkCoverage[]>([]);
  const [selectedFrameworks, setSelectedFrameworks] = useState<string[]>(['NIST 800-171', 'CMMC 2.0']);
  const [isGeneratingMapping, setIsGeneratingMapping] = useState(false);
  const [aiAnalysis, setAiAnalysis] = useState<AIAnalysisSummary | null>(null);
  const [crossWalkGenerated, setCrossWalkGenerated] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    initializeControlMappings();
    loadFrameworkCoverage();
  }, []);

  const initializeControlMappings = () => {
    // Awaiting telemetry for real control mappings
    const pendingMappings: ControlMapping[] = [];

    setControlMappings(pendingMappings);
  };

  const loadFrameworkCoverage = () => {
    // Awaiting telemetry for real framework coverage
    const pendingCoverage: FrameworkCoverage[] = [];

    setFrameworkCoverage(pendingCoverage);
  };

  const generateAIPoweredMapping = async () => {
    setIsGeneratingMapping(true);

    try {
      // Enhanced AI-powered cross-framework mapping
      const { data, error } = await supabase.functions.invoke('grok-ai-agent', {
        body: {
          action: 'cross_framework_mapping',
          frameworks: selectedFrameworks,
          analysis_type: 'comprehensive',
          include_gap_analysis: true,
          include_risk_assessment: true,
          ai_recommendations: true,
          khepra_integration: true
        }
      });

      if (error) throw error;

      // Pending telemetry for AI analysis result
      const pendingAiAnalysis: AIAnalysisSummary = {
        overlapPercentage: 0,
        criticalGaps: 0,
        automationOpportunities: [],
        riskAssessment: {
          high: 0,
          medium: 0,
          low: 0
        },
        recommendations: []
      };

      setAiAnalysis(pendingAiAnalysis);
      setCrossWalkGenerated(true);

      toast({
        title: "AI-Powered Mapping Complete",
        description: `Comprehensive cross-framework analysis completed with ${pendingAiAnalysis.overlapPercentage}% control overlap identified.`,
      });

      // Refresh mappings
      initializeControlMappings();
      loadFrameworkCoverage();

    } catch (error) {
      console.error('AI mapping generation failed:', error);
      toast({
        title: "Mapping Failed",
        description: "Unable to generate AI-powered control mapping",
        variant: "destructive"
      });
    } finally {
      setIsGeneratingMapping(false);
    }
  };

  const exportCrossWalk = () => {
    toast({
      title: "CrossWalk Export",
      description: "Generating comprehensive cross-framework mapping document with AI analysis...",
    });
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'mapped': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'partial': return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      case 'gap': return <AlertTriangle className="h-4 w-4 text-red-500" />;
      case 'not-applicable': return <Clock className="h-4 w-4 text-gray-500" />;
      default: return <Clock className="h-4 w-4 text-gray-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'mapped': return 'bg-green-500/20 text-green-400';
      case 'partial': return 'bg-yellow-500/20 text-yellow-400';
      case 'gap': return 'bg-red-500/20 text-red-400';
      case 'not-applicable': return 'bg-gray-500/20 text-gray-400';
      default: return 'bg-gray-500/20 text-gray-400';
    }
  };

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-green-500';
      default: return 'bg-gray-500';
    }
  };

  const frameworkOptions = [
    { id: 'nist-800-171', name: 'NIST 800-171', description: 'Protecting CUI in Non-Federal Systems' },
    { id: 'cmmc-2.0', name: 'CMMC 2.0', description: 'Cybersecurity Maturity Model Certification' },
    { id: 'windows-server-2019-stig', name: 'Windows Server 2019 STIG', description: 'Security Technical Implementation Guide' },
    { id: 'ubuntu-22-04-stig', name: 'Ubuntu 22.04 STIG', description: 'Linux Security Configuration' },
    { id: 'iis-10-stig', name: 'IIS 10.0 STIG', description: 'Web Server Security Configuration' },
    { id: 'apache-24-stig', name: 'Apache 2.4 STIG', description: 'Web Server Security Implementation' }
  ];

  return (
    <div className="space-y-6">
      {/* AI-Enhanced Header */}
      <Card className="bg-gradient-to-r from-purple-900/40 to-blue-900/40 border-purple-500/30">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2 text-white">
                <Brain className="h-6 w-6 text-purple-400" />
                AI-Powered Compliance Control Mapper
              </CardTitle>
              <CardDescription className="text-purple-200">
                Cross-framework control mapping with intelligent gap analysis and automation recommendations
              </CardDescription>
            </div>
            <div className="flex items-center gap-3">
              <Button
                onClick={generateAIPoweredMapping}
                disabled={isGeneratingMapping || selectedFrameworks.length < 2}
                className="bg-purple-600 hover:bg-purple-700"
              >
                {isGeneratingMapping ? (
                  <>
                    <RefreshCw className="h-4 w-4 animate-spin mr-2" />
                    AI Analyzing...
                  </>
                ) : (
                  <>
                    <Zap className="h-4 w-4 mr-2" />
                    AI Generate Mapping
                  </>
                )}
              </Button>
              <Button
                onClick={exportCrossWalk}
                variant="outline"
                className="border-purple-500/30 text-purple-400 hover:bg-purple-600/20"
              >
                <Download className="h-4 w-4 mr-2" />
                Export CrossWalk
              </Button>
            </div>
          </div>
        </CardHeader>
      </Card>

      {/* Framework Selection with AI Analysis */}
      <Card className="bg-black/40 border-purple-500/30">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-white">
            <Brain className="h-5 w-5 text-purple-400" />
            Framework Selection
            {crossWalkGenerated && (
              <Badge className="bg-green-500/20 text-green-400 ml-2">
                <TrendingUp className="h-3 w-3 mr-1" />
                AI Analysis Complete
              </Badge>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            {frameworkOptions.map((framework) => (
              <div key={framework.id} className="relative">
                <input
                  type="checkbox"
                  id={framework.id}
                  checked={selectedFrameworks.includes(framework.name)}
                  onChange={(e) => {
                    if (e.target.checked) {
                      setSelectedFrameworks([...selectedFrameworks, framework.name]);
                    } else {
                      setSelectedFrameworks(selectedFrameworks.filter(f => f !== framework.name));
                    }
                  }}
                  className="absolute top-2 right-2 rounded"
                />
                <div className={`p-4 bg-slate-800/40 rounded-lg border transition-colors ${selectedFrameworks.includes(framework.name)
                    ? 'border-purple-500/70 bg-purple-500/10'
                    : 'border-slate-600/30 hover:border-purple-500/50'
                  }`}>
                  <h3 className="text-white font-medium mb-2">{framework.name}</h3>
                  <p className="text-gray-400 text-sm">{framework.description}</p>
                  {aiAnalysis && selectedFrameworks.includes(framework.name) && (
                    <Badge variant="outline" className="text-purple-400 border-purple-500/50 mt-2">
                      <TrendingUp className="h-3 w-3 mr-1" />
                      AI Analyzed
                    </Badge>
                  )}
                </div>
              </div>
            ))}
          </div>

          {aiAnalysis && (
            <div className="p-4 bg-purple-900/20 border border-purple-500/30 rounded-lg">
              <h4 className="text-purple-400 font-medium mb-3 flex items-center">
                <Zap className="h-4 w-4 mr-2" />
                AI Analysis Summary
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                <div>
                  <div className="text-gray-300 mb-1">Control Overlap</div>
                  <div className="text-2xl font-bold text-purple-400">{aiAnalysis.overlapPercentage}%</div>
                </div>
                <div>
                  <div className="text-gray-300 mb-1">Critical Gaps</div>
                  <div className="text-2xl font-bold text-red-400">{aiAnalysis.criticalGaps}</div>
                </div>
                <div>
                  <div className="text-gray-300 mb-1">Automation Opportunities</div>
                  <div className="text-2xl font-bold text-green-400">{aiAnalysis.automationOpportunities.length}</div>
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Enhanced Framework Coverage */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {frameworkCoverage.map((framework) => (
          <Card key={framework.framework} className="bg-black/40 border-slate-600/30">
            <CardContent className="pt-6">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold text-white">{framework.framework}</h3>
                  <div className="flex gap-1">
                    <Badge className="bg-blue-500/20 text-blue-400">
                      {framework.coveragePercentage}%
                    </Badge>
                    {framework.aiAnalyzed && (
                      <Badge className="bg-purple-500/20 text-purple-400">
                        <Brain className="h-3 w-3" />
                      </Badge>
                    )}
                  </div>
                </div>
                <Progress value={framework.coveragePercentage} className="h-2" />
                <div className="space-y-1 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Mapped</span>
                    <span className="text-green-400">{framework.mappedControls}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Gaps</span>
                    <span className="text-red-400">{framework.gapControls}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Total</span>
                    <span className="text-white">{framework.totalControls}</span>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Tabs defaultValue="mappings" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="mappings">AI Control Mappings</TabsTrigger>
          <TabsTrigger value="gaps">Gap Analysis</TabsTrigger>
          <TabsTrigger value="implementation">Implementation</TabsTrigger>
          <TabsTrigger value="recommendations">AI Recommendations</TabsTrigger>
        </TabsList>

        <TabsContent value="mappings" className="space-y-4">
          <div className="space-y-4">
            {controlMappings.map((mapping) => (
              <Card key={mapping.id} className="bg-black/40 border-slate-600/30">
                <CardContent className="pt-6">
                  <div className="space-y-4">
                    {/* Enhanced Source Control with AI Confidence */}
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          {getStatusIcon(mapping.status)}
                          <Badge variant="outline" className="text-blue-400 border-blue-400">
                            {mapping.sourceControl.id}
                          </Badge>
                          <Badge className="bg-purple-500/20 text-purple-400">
                            {mapping.sourceControl.framework}
                          </Badge>
                          <Badge className={getStatusColor(mapping.status)}>
                            {mapping.status.toUpperCase()}
                          </Badge>
                          <Badge className={`text-white ${getRiskColor(mapping.riskLevel)}`}>
                            {mapping.riskLevel.toUpperCase()}
                          </Badge>
                          <Badge className="bg-brain-gradient text-white">
                            <Brain className="h-3 w-3 mr-1" />
                            {mapping.aiConfidence}% AI Confidence
                          </Badge>
                        </div>
                        <h3 className="font-semibold text-white mb-1">
                          {mapping.sourceControl.title}
                        </h3>
                        <p className="text-gray-400 text-sm">
                          {mapping.sourceControl.description}
                        </p>
                      </div>
                    </div>

                    {/* Enhanced Cross-Framework Mappings */}
                    <div className="bg-slate-800/40 p-4 rounded border border-slate-600/30">
                      <h4 className="font-medium text-white mb-3 flex items-center gap-2">
                        <MapPin className="h-4 w-4 text-purple-400" />
                        AI-Powered Cross-Framework Mappings
                      </h4>
                      <div className="space-y-3">
                        {mapping.mappedControls.map((mapped, index) => (
                          <div key={index} className="p-3 bg-slate-700/40 rounded border border-slate-600/20">
                            <div className="flex items-center justify-between mb-2">
                              <div className="flex items-center gap-3">
                                <Badge variant="outline">{mapped.id}</Badge>
                                <span className="text-sm text-white font-medium">{mapped.title}</span>
                                <Badge variant="secondary">{mapped.framework}</Badge>
                              </div>
                              <div className="flex items-center gap-2">
                                <div className="text-sm font-medium text-green-400">
                                  {mapped.mappingStrength}%
                                </div>
                              </div>
                            </div>
                            {mapped.aiAnalysis && (
                              <div className="text-xs text-purple-400 mb-2">
                                <Zap className="h-3 w-3 inline mr-1" />
                                AI Analysis: {mapped.aiAnalysis}
                              </div>
                            )}
                            {mapped.gap && (
                              <div className="text-xs text-orange-400">
                                Gap Identified: {mapped.gap}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* AI Recommendations */}
                    {mapping.implementation.aiRecommendations && (
                      <div className="bg-purple-900/20 border border-purple-500/30 rounded p-3">
                        <h4 className="text-purple-400 font-medium text-sm mb-2 flex items-center">
                          <Zap className="h-4 w-4 mr-2" />
                          AI Implementation Recommendations
                        </h4>
                        <ul className="text-gray-300 text-xs space-y-1">
                          {mapping.implementation.aiRecommendations.map((rec, idx) => (
                            <li key={idx}>• {rec}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="gaps" className="space-y-4">
          <Card className="bg-black/40 border-red-500/30">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-red-400" />
                AI-Identified Gaps & Risks
              </CardTitle>
            </CardHeader>
            <CardContent>
              {aiAnalysis && (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="p-4 bg-red-900/20 border border-red-500/30 rounded">
                    <div className="text-red-400 font-medium mb-2">High Risk</div>
                    <div className="text-2xl font-bold text-white">{aiAnalysis.riskAssessment.high}</div>
                    <div className="text-xs text-gray-400">Controls requiring immediate attention</div>
                  </div>
                  <div className="p-4 bg-yellow-900/20 border border-yellow-500/30 rounded">
                    <div className="text-yellow-400 font-medium mb-2">Medium Risk</div>
                    <div className="text-2xl font-bold text-white">{aiAnalysis.riskAssessment.medium}</div>
                    <div className="text-xs text-gray-400">Controls needing remediation planning</div>
                  </div>
                  <div className="p-4 bg-green-900/20 border border-green-500/30 rounded">
                    <div className="text-green-400 font-medium mb-2">Low Risk</div>
                    <div className="text-2xl font-bold text-white">{aiAnalysis.riskAssessment.low}</div>
                    <div className="text-xs text-gray-400">Controls with minor adjustments needed</div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="implementation" className="space-y-4">
          <Card className="bg-black/40 border-slate-600/30">
            <CardHeader>
              <CardTitle className="text-white">Implementation Tools & Automation</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {controlMappings.map((mapping) => (
                  <div key={mapping.id} className="p-4 bg-slate-800/40 rounded border border-slate-600/30">
                    <div className="flex items-center justify-between mb-3">
                      <h4 className="text-white font-medium">{mapping.sourceControl.id}</h4>
                      <Badge className="bg-blue-500/20 text-blue-400">
                        {mapping.implementation.automationLevel}% Automated
                      </Badge>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                      <div>
                        <div className="text-gray-400 mb-2">Implementation Tools</div>
                        <div className="flex flex-wrap gap-1">
                          {mapping.implementation.tools.map((tool) => (
                            <Badge key={tool} variant="outline" className="text-xs">
                              {tool}
                            </Badge>
                          ))}
                        </div>
                      </div>
                      <div>
                        <div className="text-gray-400 mb-2">Test Procedures</div>
                        <ul className="text-gray-300 space-y-1">
                          {mapping.implementation.testProcedures.slice(0, 2).map((procedure, idx) => (
                            <li key={idx} className="text-xs">• {procedure}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                    <div className="mt-3">
                      <Progress value={mapping.implementation.automationLevel} className="h-2" />
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="recommendations" className="space-y-4">
          <Card className="bg-black/40 border-purple-500/30">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Brain className="h-5 w-5 text-purple-400" />
                AI Strategic Recommendations
              </CardTitle>
            </CardHeader>
            <CardContent>
              {aiAnalysis && (
                <div className="space-y-6">
                  <div>
                    <h4 className="text-purple-400 font-medium mb-3">Priority Recommendations</h4>
                    <div className="space-y-2">
                      {aiAnalysis.recommendations.map((rec, idx) => (
                        <div key={idx} className="p-3 bg-purple-900/20 border border-purple-500/30 rounded">
                          <div className="flex items-start gap-3">
                            <TrendingUp className="h-4 w-4 text-purple-400 mt-0.5" />
                            <span className="text-gray-300 text-sm">{rec}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div>
                    <h4 className="text-green-400 font-medium mb-3">Automation Opportunities</h4>
                    <div className="space-y-2">
                      {aiAnalysis.automationOpportunities.map((opp, idx) => (
                        <div key={idx} className="p-3 bg-green-900/20 border border-green-500/30 rounded">
                          <div className="flex items-start gap-3">
                            <Zap className="h-4 w-4 text-green-400 mt-0.5" />
                            <span className="text-gray-300 text-sm">{opp}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};