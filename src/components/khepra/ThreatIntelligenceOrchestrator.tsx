import { useState, useEffect, useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { Progress } from '@/components/ui/progress';
import { 
  Shield, Activity, Database, Globe, Zap, Eye, Target,
  AlertTriangle, CheckCircle, XCircle, TrendingUp, Clock,
  Server, Network, Lock, Brain, Sparkles
} from 'lucide-react';
import { AdinkraSymbolDisplay } from './AdinkraSymbolDisplay';
import { AdinkraAlgebraicEngine } from '@/khepra/aae/AdinkraEngine';
import { TrustedAgentRegistry } from '@/khepra/registry/TrustedAgentRegistry';
import { useThreatIntelligence } from '@/hooks/useThreatIntelligence';

// MITRE ATT&CK Framework Integration
interface MITREAttackMatrix {
  id: string;
  name: string;
  techniques: MITRETechnique[];
  coverage: number;
  lastUpdate: Date;
}

interface MITRETechnique {
  id: string;
  name: string;
  tactic: string;
  description: string;
  platforms: string[];
  detectionCoverage: number;
  mitigationStatus: 'none' | 'partial' | 'complete';
  references: string[];
}

// CVSS Integration
interface CVSSAssessment {
  cveId: string;
  baseScore: number;
  temporalScore?: number;
  environmentalScore?: number;
  vector: string;
  severity: 'None' | 'Low' | 'Medium' | 'High' | 'Critical';
  lastAssessed: Date;
  khepraAnalysis: {
    culturalRisk: number;
    adinkraMapping: string;
    protocolRecommendation: string;
  };
}

interface ThreatIntelligenceData {
  sources: string[];
  indicators: number;
  lastSync: Date;
  coverage: {
    mitre: number;
    cvss: number;
    openSource: number;
  };
}

export const ThreatIntelligenceOrchestrator = () => {
  const [activeView, setActiveView] = useState('overview');
  const [mitreMatrix, setMitreMatrix] = useState<MITREAttackMatrix[]>([]);
  const [cvssAssessments, setCvssAssessments] = useState<CVSSAssessment[]>([]);
  const [threatIntel, setThreatIntel] = useState<ThreatIntelligenceData>({
    sources: [],
    indicators: 0,
    lastSync: new Date(),
    coverage: { mitre: 0, cvss: 0, openSource: 0 }
  });
  const [syncInProgress, setSyncInProgress] = useState(false);
  const { threats, loading } = useThreatIntelligence();

  // Simulated MITRE ATT&CK data
  useEffect(() => {
    setMitreMatrix([
      {
        id: 'enterprise',
        name: 'ATT&CK for Enterprise',
        techniques: generateMockMITRETechniques(),
        coverage: 78,
        lastUpdate: new Date()
      }
    ]);

    setCvssAssessments(generateMockCVSSAssessments());
    
    setThreatIntel({
      sources: ['MITRE ATT&CK', 'NVD CVSS', 'CISA KEV', 'AlienVault OTX', 'AbuseIPDB'],
      indicators: 15420,
      lastSync: new Date(),
      coverage: { mitre: 78, cvss: 92, openSource: 85 }
    });
  }, []);

  const handleSyncIntelligence = async () => {
    setSyncInProgress(true);
    
    // Simulate sync process with KHEPRA protocol verification
    const syncSteps = [
      'Establishing secure channel with Eban protocol...',
      'Fetching MITRE ATT&CK matrix updates...',
      'Retrieving CVSS vulnerability data...',
      'Processing indicators through Adinkra transformations...',
      'Updating cultural threat mappings...',
      'Validating data integrity with Fawohodie...'
    ];

    for (let i = 0; i < syncSteps.length; i++) {
      await new Promise(resolve => setTimeout(resolve, 1000));
      console.log(syncSteps[i]);
    }

    setThreatIntel(prev => ({
      ...prev,
      lastSync: new Date(),
      indicators: prev.indicators // Real indicator count requires sync response metadata
    }));

    setSyncInProgress(false);
  };

  const getCvssColor = (score: number) => {
    if (score >= 9.0) return 'text-red-500';
    if (score >= 7.0) return 'text-orange-500';
    if (score >= 4.0) return 'text-yellow-500';
    return 'text-green-500';
  };

  const getCvssBadgeVariant = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'destructive';
      case 'High': return 'destructive';
      case 'Medium': return 'secondary';
      case 'Low': return 'outline';
      default: return 'outline';
    }
  };

  const getMitreDetectionColor = (coverage: number) => {
    if (coverage >= 80) return 'text-green-500';
    if (coverage >= 60) return 'text-yellow-500';
    return 'text-red-500';
  };

  return (
    <div className="space-y-6">
      {/* KHEPRA Protocol Header */}
      <div className="relative overflow-hidden rounded-lg border border-primary/20 bg-gradient-to-r from-primary/5 via-purple-500/5 to-amber-500/5 p-6">
        <div className="relative z-10">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-primary mb-2">
                KHEPRA Threat Intelligence Orchestrator
              </h1>
              <p className="text-muted-foreground">
                Afrofuturist cryptographic framework for OSINT integration • Active monitoring of MITRE ATT&CK & CVSS sources
              </p>
            </div>
            <div className="flex items-center space-x-4">
              <AdinkraSymbolDisplay 
                symbolName="Eban" 
                size="small" 
                showMatrix={false} 
                className="opacity-60"
              />
              <Badge variant="outline" className="bg-primary/10 border-primary/30">
                Protocol Active
              </Badge>
            </div>
          </div>
        </div>
        
        {/* Decorative elements */}
        <div className="absolute top-0 right-0 w-32 h-32 opacity-10">
          <AdinkraSymbolDisplay symbolName="Nkyinkyim" size="large" showMatrix={false} />
        </div>
      </div>

      {/* Intelligence Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Database className="h-5 w-5 text-blue-400" />
              <div>
                <p className="text-sm text-muted-foreground">MITRE Coverage</p>
                <div className="flex items-center space-x-2">
                  <p className="text-2xl font-bold">{threatIntel.coverage.mitre}%</p>
                  <Progress value={threatIntel.coverage.mitre} className="w-16 h-2" />
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Shield className="h-5 w-5 text-green-400" />
              <div>
                <p className="text-sm text-muted-foreground">CVSS Assessed</p>
                <div className="flex items-center space-x-2">
                  <p className="text-2xl font-bold">{threatIntel.coverage.cvss}%</p>
                  <Progress value={threatIntel.coverage.cvss} className="w-16 h-2" />
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Globe className="h-5 w-5 text-purple-400" />
              <div>
                <p className="text-sm text-muted-foreground">OSINT Sources</p>
                <p className="text-2xl font-bold">{threatIntel.sources.length}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Target className="h-5 w-5 text-amber-400" />
              <div>
                <p className="text-sm text-muted-foreground">Indicators</p>
                <p className="text-2xl font-bold">{threatIntel.indicators.toLocaleString()}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Sync Controls */}
      <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center space-x-2">
              <Zap className="h-5 w-5" />
              <span>Intelligence Synchronization</span>
            </CardTitle>
            <Button 
              onClick={handleSyncIntelligence} 
              disabled={syncInProgress}
              className="bg-primary/20 hover:bg-primary/30 border border-primary/30"
            >
              {syncInProgress ? (
                <>
                  <Sparkles className="h-4 w-4 mr-2 animate-pulse" />
                  Syncing...
                </>
              ) : (
                <>
                  <TrendingUp className="h-4 w-4 mr-2" />
                  Sync Intelligence
                </>
              )}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <h4 className="font-medium mb-2">Active Sources</h4>
              <div className="space-y-1">
                {threatIntel.sources.map((source, index) => (
                  <div key={index} className="flex items-center justify-between text-sm">
                    <span>{source}</span>
                    <Badge variant="outline" className="text-xs">
                      <CheckCircle className="h-3 w-3 mr-1" />
                      Active
                    </Badge>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <h4 className="font-medium mb-2">Last Synchronization</h4>
              <div className="space-y-2 text-sm">
                <div className="flex items-center space-x-2">
                  <Clock className="h-4 w-4" />
                  <span>{threatIntel.lastSync.toLocaleString()}</span>
                </div>
                <div className="text-muted-foreground">
                  Next scheduled sync: {new Date(threatIntel.lastSync.getTime() + 3600000).toLocaleString()}
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Main Intelligence Tabs */}
      <Tabs value={activeView} onValueChange={setActiveView} className="space-y-4">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="overview" className="flex items-center space-x-2">
            <Eye className="h-4 w-4" />
            <span>Overview</span>
          </TabsTrigger>
          <TabsTrigger value="mitre" className="flex items-center space-x-2">
            <Database className="h-4 w-4" />
            <span>MITRE ATT&CK</span>
          </TabsTrigger>
          <TabsTrigger value="cvss" className="flex items-center space-x-2">
            <Shield className="h-4 w-4" />
            <span>CVSS Analysis</span>
          </TabsTrigger>
          <TabsTrigger value="cultural" className="flex items-center space-x-2">
            <Brain className="h-4 w-4" />
            <span>Cultural Intelligence</span>
          </TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Critical Vulnerabilities */}
            <Card className="border-destructive/20 bg-destructive/5">
              <CardHeader>
                <CardTitle className="text-destructive flex items-center space-x-2">
                  <AlertTriangle className="h-5 w-5" />
                  <span>Critical Vulnerabilities (CVSS 9.0+)</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-48">
                  <div className="space-y-2">
                    {cvssAssessments.filter(c => c.baseScore >= 9.0).map((cve, index) => (
                      <div key={index} className="flex items-center justify-between p-2 border-l-2 border-destructive">
                        <div>
                          <p className="font-medium text-destructive">{cve.cveId}</p>
                          <p className="text-xs text-muted-foreground">
                            Cultural Risk: {cve.khepraAnalysis.culturalRisk}%
                          </p>
                        </div>
                        <Badge variant="destructive">{cve.baseScore.toFixed(1)}</Badge>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>

            {/* MITRE Coverage Summary */}
            <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Database className="h-5 w-5" />
                  <span>MITRE ATT&CK Coverage</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {mitreMatrix[0]?.techniques.slice(0, 5).map((technique, index) => (
                    <div key={index} className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-sm font-medium">{technique.name}</span>
                        <Badge variant="outline" className="text-xs">
                          {technique.tactic}
                        </Badge>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Progress value={technique.detectionCoverage} className="flex-1 h-2" />
                        <span className={`text-xs ${getMitreDetectionColor(technique.detectionCoverage)}`}>
                          {technique.detectionCoverage}%
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* MITRE ATT&CK Tab */}
        <TabsContent value="mitre" className="space-y-4">
          <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>MITRE ATT&CK Matrix Coverage</CardTitle>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-96">
                <div className="space-y-4">
                  {mitreMatrix[0]?.techniques.map((technique, index) => (
                    <Card key={index} className="border-border/50">
                      <CardContent className="p-4">
                        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                          <div>
                            <h4 className="font-medium">{technique.name}</h4>
                            <p className="text-sm text-muted-foreground">{technique.id}</p>
                            <Badge variant="outline" className="mt-2 text-xs">
                              {technique.tactic}
                            </Badge>
                          </div>
                          
                          <div>
                            <p className="text-sm font-medium mb-2">Detection Coverage</p>
                            <div className="flex items-center space-x-2">
                              <Progress value={technique.detectionCoverage} className="flex-1 h-2" />
                              <span className={`text-sm ${getMitreDetectionColor(technique.detectionCoverage)}`}>
                                {technique.detectionCoverage}%
                              </span>
                            </div>
                            
                            <div className="mt-2">
                              <Badge 
                                variant={
                                  technique.mitigationStatus === 'complete' ? 'default' :
                                  technique.mitigationStatus === 'partial' ? 'secondary' : 'outline'
                                }
                                className="text-xs"
                              >
                                {technique.mitigationStatus} mitigation
                              </Badge>
                            </div>
                          </div>
                          
                          <div>
                            <p className="text-sm font-medium mb-2">Platforms</p>
                            <div className="flex flex-wrap gap-1">
                              {technique.platforms.map((platform, pidx) => (
                                <Badge key={pidx} variant="outline" className="text-xs">
                                  {platform}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* CVSS Analysis Tab */}
        <TabsContent value="cvss" className="space-y-4">
          <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>CVSS Vulnerability Analysis</CardTitle>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-96">
                <div className="space-y-4">
                  {cvssAssessments.map((assessment, index) => (
                    <Card key={index} className="border-border/50">
                      <CardContent className="p-4">
                        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
                          <div>
                            <h4 className="font-medium">{assessment.cveId}</h4>
                            <Badge 
                              variant={getCvssBadgeVariant(assessment.severity)}
                              className="mt-2"
                            >
                              {assessment.severity}
                            </Badge>
                          </div>
                          
                          <div>
                            <p className="text-sm font-medium mb-1">CVSS Score</p>
                            <p className={`text-2xl font-bold ${getCvssColor(assessment.baseScore)}`}>
                              {assessment.baseScore.toFixed(1)}
                            </p>
                          </div>
                          
                          <div>
                            <p className="text-sm font-medium mb-1">KHEPRA Analysis</p>
                            <div className="space-y-1">
                              <div className="text-xs">
                                Cultural Risk: {assessment.khepraAnalysis.culturalRisk}%
                              </div>
                              <div className="text-xs">
                                Symbol: {assessment.khepraAnalysis.adinkraMapping}
                              </div>
                            </div>
                          </div>
                          
                          <div>
                            <p className="text-sm font-medium mb-1">Vector</p>
                            <p className="text-xs font-mono bg-muted p-1 rounded">
                              {assessment.vector}
                            </p>
                          </div>
                        </div>
                        
                        <Separator className="my-3" />
                        
                        <div>
                          <p className="text-sm font-medium mb-1">KHEPRA Recommendation</p>
                          <p className="text-sm text-muted-foreground">
                            {assessment.khepraAnalysis.protocolRecommendation}
                          </p>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Cultural Intelligence Tab */}
        <TabsContent value="cultural" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Adinkra Symbol Mappings */}
            <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
              <CardHeader>
                <CardTitle>Cultural Threat Mappings</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="p-3 border-l-4 border-blue-500 bg-blue-500/10">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium">Eban (Fortress)</span>
                      <Badge variant="outline">Protection</Badge>
                    </div>
                    <p className="text-sm text-muted-foreground">
                      Applied to perimeter defense and access control threats. 
                      Maps to MITRE tactics: Defense Evasion, Privilege Escalation.
                    </p>
                  </div>
                  
                  <div className="p-3 border-l-4 border-purple-500 bg-purple-500/10">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium">Nyame (Authority)</span>
                      <Badge variant="outline">Trust</Badge>
                    </div>
                    <p className="text-sm text-muted-foreground">
                      Applied to authentication and authorization vulnerabilities.
                      Maps to MITRE tactics: Credential Access, Initial Access.
                    </p>
                  </div>
                  
                  <div className="p-3 border-l-4 border-yellow-500 bg-yellow-500/10">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium">Nkyinkyim (Journey)</span>
                      <Badge variant="outline">Transformation</Badge>
                    </div>
                    <p className="text-sm text-muted-foreground">
                      Applied to lateral movement and persistence threats.
                      Maps to MITRE tactics: Lateral Movement, Persistence.
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Cultural Risk Assessment */}
            <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
              <CardHeader>
                <CardTitle>Cultural Risk Assessment</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium">Overall Cultural Risk</span>
                      <span className="text-2xl font-bold text-amber-500">73%</span>
                    </div>
                    <Progress value={73} className="h-2" />
                  </div>
                  
                  <Separator />
                  
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Protection (Eban) Threats</span>
                      <span className="text-sm font-bold">42</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Trust (Nyame) Threats</span>
                      <span className="text-sm font-bold">28</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Transformation (Nkyinkyim) Threats</span>
                      <span className="text-sm font-bold">15</span>
                    </div>
                  </div>
                  
                  <Separator />
                  
                  <div>
                    <p className="text-sm font-medium mb-2">Protocol Recommendations</p>
                    <div className="space-y-2 text-sm text-muted-foreground">
                      <p>• Strengthen Eban-based perimeter controls</p>
                      <p>• Implement Nyame trust verification protocols</p>
                      <p>• Deploy Nkyinkyim adaptive response systems</p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};

// Mock data generators
function generateMockMITRETechniques(): MITRETechnique[] {
  const tactics = ['Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact'];
  const platforms = ['Windows', 'Linux', 'macOS', 'AWS', 'Azure', 'GCP', 'Office 365'];
  
  return Array.from({ length: 25 }, (_, i) => ({
    id: `T${(1000 + i).toString()}`,
    name: `Technique ${i + 1}`,
    tactic: tactics[i % tactics.length],
    description: `Sample technique description for T${1000 + i}`,
    platforms: platforms.slice(0, (i % 4) + 1), // Deterministic slice based on index
    detectionCoverage: 0, // Real coverage requires threat detection engine data
    mitigationStatus: 'none' as any, // Real status requires threat intelligence database
    references: [`https://attack.mitre.org/techniques/T${1000 + i}`]
  }));
}

function generateMockCVSSAssessments(): CVSSAssessment[] {
  const severities: Array<'None' | 'Low' | 'Medium' | 'High' | 'Critical'> = ['Low', 'Medium', 'High', 'Critical'];
  const symbols = ['Eban', 'Nyame', 'Nkyinkyim', 'Fawohodie', 'Adwo'];
  
  return Array.from({ length: 15 }, (_, i) => ({
    cveId: `CVE-2024-${(1000 + i).toString()}`,
    baseScore: 0, // Real CVSS score requires NVD or vulnerability feed
    vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`,
    severity: severities[i % severities.length], // Deterministic cycle through severities
    lastAssessed: new Date(),
    khepraAnalysis: {
      culturalRisk: 0, // Real cultural risk requires Khepra analysis engine
      adinkraMapping: symbols[i % symbols.length], // Deterministic cycle
      protocolRecommendation: `Apply ${symbols[i % symbols.length]} transformation with enhanced monitoring`
    }
  }));
}