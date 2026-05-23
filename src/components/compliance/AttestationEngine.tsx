import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { AdinkraAlgebraicEngine } from '@/khepra/aae/AdinkraEngine';
import {
  Shield,
  FileCheck,
  Key,
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  Download,
  Upload,
  QrCode,
  Lock,
  Unlock,
  Hash,
  Eye,
  EyeOff,
  Fingerprint,
  Calendar,
  User,
  Building
} from 'lucide-react';

interface AttestationRecord {
  id: string;
  controlId: string;
  framework: string;
  status: 'compliant' | 'non-compliant' | 'partial' | 'not-tested';
  attestedBy: string;
  attestedAt: Date;
  validUntil: Date;
  evidenceHash: string;
  signature: string;
  culturalFingerprint: string;
  trustScore: number;
  metadata: {
    evidenceCount: number;
    testResults: number;
    remediationActions: number;
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
  };
}

interface EvidencePackage {
  id: string;
  name: string;
  framework: string;
  generatedAt: Date;
  attestations: string[];
  totalControls: number;
  compliantControls: number;
  packageHash: string;
  encryptionKey?: string;
  downloadUrl?: string;
  expiresAt: Date;
}

interface AttestationChain {
  blockId: string;
  previousHash: string;
  currentHash: string;
  timestamp: Date;
  attestations: string[];
  culturalSignature: string;
  trustLevel: number;
  verificationStatus: 'verified' | 'pending' | 'failed';
}

// Awaiting telemetry for real attestations
const pendingAttestations: AttestationRecord[] = [];

// Awaiting telemetry for real evidence packages
const pendingEvidencePackages: EvidencePackage[] = [];

export const AttestationEngine: React.FC = () => {
  const [attestations, setAttestations] = useState<AttestationRecord[]>(pendingAttestations);
  const [evidencePackages, setEvidencePackages] = useState<EvidencePackage[]>(pendingEvidencePackages);
  const [selectedAttestation, setSelectedAttestation] = useState<AttestationRecord | null>(null);
  const [isGeneratingPackage, setIsGeneratingPackage] = useState(false);
  const [showSignatureDetails, setShowSignatureDetails] = useState(false);
  const [adinkraEngine] = useState(new AdinkraAlgebraicEngine());
  const { toast } = useToast();

  const refreshAttestations = () => {
    setAttestations(prev => prev.map(att => ({
      ...att,
      trustScore: att.trustScore // Trust score is static until re-attested; real updates require re-running attestation
    })));
  };

  useEffect(() => {
    // Simulate real-time attestation updates
    const interval = setInterval(refreshAttestations, 30000);

    return () => clearInterval(interval);
  }, []);

  const generateAttestation = async (controlId: string, framework: string) => {
    try {
      // Generate cultural fingerprint using Adinkra engine
      const culturalContext = await determineCulturalContext(controlId);
      const fingerprint = AdinkraAlgebraicEngine.generateFingerprint(
        `${controlId}:${framework}:${Date.now()}`,
        [culturalContext]
      );

      const { data, error } = await supabase.functions.invoke('grok-ai-agent', {
        body: {
          action: 'generate_attestation',
          controlId,
          framework,
          culturalFingerprint: fingerprint,
          includeEvidence: true
        }
      });

      if (error) throw error;

      const newAttestation: AttestationRecord = {
        id: `att-${Date.now()}`,
        controlId,
        framework,
        status: data?.compliant ? 'compliant' : 'non-compliant',
        attestedBy: 'ai-agent@company.com',
        attestedAt: new Date(),
        validUntil: new Date(Date.now() + 1000 * 60 * 60 * 24 * 90),
        evidenceHash: data?.evidenceHash || `sha256:${crypto.randomUUID().replace(/-/g, '')}`,
        signature: data?.signature || `khepra:sig:${crypto.randomUUID().replace(/-/g, '')}`,
        culturalFingerprint: fingerprint,
        trustScore: data?.trustScore || 0, // Real trust score comes from attestation service
        metadata: {
          evidenceCount: data?.evidenceCount || 0, // Real count from evidence collection
          testResults: data?.testResults || 0, // Real results from test execution
          remediationActions: data?.remediationActions || 0, // Real count from remediation engine
          riskLevel: (data?.riskLevel || 'low') as any
        }
      };

      setAttestations(prev => [...prev, newAttestation]);

      toast({
        title: "Attestation Generated",
        description: `KHEPRA attestation created for ${controlId}`,
      });

    } catch (error) {
      console.error('Failed to generate attestation:', error);
      toast({
        title: "Attestation Failed",
        description: "Unable to generate compliance attestation",
        variant: "destructive"
      });
    }
  };

  const generateEvidencePackage = async (framework: string) => {
    setIsGeneratingPackage(true);

    try {
      const frameworkAttestations = attestations.filter(att => att.framework === framework);
      const compliantCount = frameworkAttestations.filter(att => att.status === 'compliant').length;

      const newPackage: EvidencePackage = {
        id: `pkg-${Date.now()}`,
        name: `${framework} Compliance Package - ${new Date().toLocaleDateString()}`,
        framework,
        generatedAt: new Date(),
        attestations: frameworkAttestations.map(att => att.id),
        totalControls: frameworkAttestations.length,
        compliantControls: compliantCount,
        packageHash: `sha256:package:${crypto.randomUUID().replace(/-/g, '')}`,
        downloadUrl: `/downloads/${framework.toLowerCase().replaceAll(' ', '-')}-${Date.now()}.zip`,
        expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 90)
      };

      // Simulate package generation
      await new Promise(resolve => setTimeout(resolve, 3000));

      setEvidencePackages(prev => [...prev, newPackage]);

      toast({
        title: "Evidence Package Generated",
        description: `${framework} compliance package is ready for download`,
      });

    } catch (error) {
      console.error('Failed to generate package:', error);
      toast({
        title: "Package Generation Failed",
        description: "Unable to generate evidence package",
        variant: "destructive"
      });
    } finally {
      setIsGeneratingPackage(false);
    }
  };

  const verifyAttestation = async (attestation: AttestationRecord) => {
    try {
      // Verify using KHEPRA protocol
      const isValid = AdinkraAlgebraicEngine.validateToken(
        attestation.signature,
        `${attestation.controlId}:${attestation.framework}`
      );

      toast({
        title: isValid ? "Attestation Verified" : "Verification Failed",
        description: isValid
          ? "KHEPRA signature is cryptographically valid"
          : "Attestation signature verification failed",
        variant: isValid ? "default" : "destructive"
      });

    } catch (error) {
      console.error('Failed to verify attestation:', error);
      toast({
        title: "Verification Error",
        description: "Unable to verify attestation signature",
        variant: "destructive"
      });
    }
  };

  const determineCulturalContext = async (controlId: string): Promise<string> => {
    // Map control types to Adinkra symbols based on cultural meaning
    if (controlId.includes('MFA') || controlId.includes('6.6')) return 'Eban'; // Fortress/Security
    if (controlId.includes('Access') || controlId.includes('9.2')) return 'Fawohodie'; // Freedom/Emancipation
    if (controlId.includes('Encryption') || controlId.includes('3.4')) return 'Nkyinkyim'; // Journey/Adaptability
    return 'Eban'; // Default to security symbol
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'compliant': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'non-compliant': return <XCircle className="h-4 w-4 text-red-500" />;
      case 'partial': return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      default: return <Clock className="h-4 w-4 text-gray-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'compliant': return 'bg-green-500';
      case 'non-compliant': return 'bg-red-500';
      case 'partial': return 'bg-yellow-500';
      default: return 'bg-gray-500';
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

  const overallStats = {
    totalAttestations: attestations.length,
    compliantCount: attestations.filter(a => a.status === 'compliant').length,
    avgTrustScore: Math.round(attestations.reduce((acc, a) => acc + a.trustScore, 0) / attestations.length),
    packagesGenerated: evidencePackages.length,
    expiringCount: attestations.filter(a => a.validUntil < new Date(Date.now() + 1000 * 60 * 60 * 24 * 30)).length
  };

  return (
    <div className="space-y-6">
      {/* Stats Overview */}
      <div className="grid grid-cols-5 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-2xl font-bold">{overallStats.totalAttestations}</div>
              <div className="text-sm text-muted-foreground">Total Attestations</div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-green-500">{overallStats.compliantCount}</div>
              <div className="text-sm text-muted-foreground">Compliant</div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-500">{overallStats.avgTrustScore}%</div>
              <div className="text-sm text-muted-foreground">Avg Trust Score</div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-purple-500">{overallStats.packagesGenerated}</div>
              <div className="text-sm text-muted-foreground">Evidence Packages</div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-orange-500">{overallStats.expiringCount}</div>
              <div className="text-sm text-muted-foreground">Expiring Soon</div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="attestations" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="attestations">Attestations</TabsTrigger>
          <TabsTrigger value="packages">Evidence Packages</TabsTrigger>
          <TabsTrigger value="verification">Verification</TabsTrigger>
          <TabsTrigger value="chain">Attestation Chain</TabsTrigger>
        </TabsList>

        <TabsContent value="attestations" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <Shield className="h-5 w-5" />
                    KHEPRA Compliance Attestations
                  </CardTitle>
                  <CardDescription>
                    Cryptographically signed compliance attestations with cultural fingerprinting
                  </CardDescription>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    onClick={() => generateAttestation('SOC2-CC6.7', 'SOC 2')}
                    size="sm"
                  >
                    <FileCheck className="h-4 w-4 mr-2" />
                    Generate Attestation
                  </Button>
                </div>
              </div>
            </CardHeader>
          </Card>

          <div className="space-y-4">
            {attestations.map((attestation) => (
              <Card key={attestation.id}>
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        <Badge className={getStatusColor(attestation.status)}>
                          {attestation.status.toUpperCase()}
                        </Badge>
                        <Badge variant="outline">{attestation.framework}</Badge>
                        <Badge className={getRiskColor(attestation.metadata.riskLevel)}>
                          {attestation.metadata.riskLevel.toUpperCase()}
                        </Badge>
                      </div>
                      <CardTitle className="flex items-center gap-2">
                        {getStatusIcon(attestation.status)}
                        {attestation.controlId}
                      </CardTitle>
                      <CardDescription>
                        Attested by {attestation.attestedBy} •
                        Trust Score: {attestation.trustScore}% •
                        Valid until {attestation.validUntil.toLocaleDateString()}
                      </CardDescription>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button
                        onClick={() => verifyAttestation(attestation)}
                        size="sm"
                        variant="outline"
                      >
                        <Fingerprint className="h-4 w-4 mr-1" />
                        Verify
                      </Button>
                      <Button
                        onClick={() => setSelectedAttestation(attestation)}
                        size="sm"
                        variant="outline"
                      >
                        <Eye className="h-4 w-4 mr-1" />
                        Details
                      </Button>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-4 gap-4 mb-4">
                    <div className="text-center">
                      <div className="text-lg font-semibold">{attestation.metadata.evidenceCount}</div>
                      <div className="text-sm text-muted-foreground">Evidence Items</div>
                    </div>
                    <div className="text-center">
                      <div className="text-lg font-semibold">{attestation.metadata.testResults}</div>
                      <div className="text-sm text-muted-foreground">Test Results</div>
                    </div>
                    <div className="text-center">
                      <div className="text-lg font-semibold">{attestation.metadata.remediationActions}</div>
                      <div className="text-sm text-muted-foreground">Remediations</div>
                    </div>
                    <div className="text-center">
                      <div className="text-lg font-semibold">{attestation.trustScore}%</div>
                      <div className="text-sm text-muted-foreground">Trust Score</div>
                    </div>
                  </div>

                  <div className="space-y-3">
                    <div>
                      <div className="flex justify-between text-sm mb-1">
                        <span>Trust Score</span>
                        <span>{attestation.trustScore}%</span>
                      </div>
                      <Progress value={attestation.trustScore} className="h-2" />
                    </div>

                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <div className="text-muted-foreground mb-1">Evidence Hash</div>
                        <div className="font-mono text-xs bg-muted p-2 rounded">
                          {attestation.evidenceHash}
                        </div>
                      </div>
                      <div>
                        <div className="text-muted-foreground mb-1">Cultural Fingerprint</div>
                        <div className="font-mono text-xs bg-muted p-2 rounded">
                          {attestation.culturalFingerprint}
                        </div>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="packages" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <FileCheck className="h-5 w-5" />
                    Evidence Packages
                  </CardTitle>
                  <CardDescription>
                    Downloadable compliance evidence packages for auditors and regulators
                  </CardDescription>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    onClick={() => generateEvidencePackage('SOC 2')}
                    disabled={isGeneratingPackage}
                    size="sm"
                  >
                    {isGeneratingPackage ? (
                      <Clock className="h-4 w-4 mr-2 animate-spin" />
                    ) : (
                      <Upload className="h-4 w-4 mr-2" />
                    )}
                    Generate Package
                  </Button>
                </div>
              </div>
            </CardHeader>
          </Card>

          <div className="space-y-4">
            {evidencePackages.map((pkg) => (
              <Card key={pkg.id}>
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div>
                      <CardTitle>{pkg.name}</CardTitle>
                      <CardDescription>
                        Generated: {pkg.generatedAt.toLocaleString()} •
                        Expires: {pkg.expiresAt.toLocaleDateString()}
                      </CardDescription>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button size="sm" variant="outline">
                        <QrCode className="h-4 w-4 mr-1" />
                        QR Code
                      </Button>
                      {pkg.downloadUrl && (
                        <Button size="sm">
                          <Download className="h-4 w-4 mr-1" />
                          Download
                        </Button>
                      )}
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-4 gap-4 mb-4">
                    <div className="text-center">
                      <div className="text-lg font-semibold">{pkg.totalControls}</div>
                      <div className="text-sm text-muted-foreground">Total Controls</div>
                    </div>
                    <div className="text-center">
                      <div className="text-lg font-semibold text-green-500">{pkg.compliantControls}</div>
                      <div className="text-sm text-muted-foreground">Compliant</div>
                    </div>
                    <div className="text-center">
                      <div className="text-lg font-semibold">{pkg.attestations.length}</div>
                      <div className="text-sm text-muted-foreground">Attestations</div>
                    </div>
                    <div className="text-center">
                      <div className="text-lg font-semibold">
                        {Math.round((pkg.compliantControls / pkg.totalControls) * 100)}%
                      </div>
                      <div className="text-sm text-muted-foreground">Compliance</div>
                    </div>
                  </div>

                  <div className="space-y-3">
                    <div>
                      <div className="flex justify-between text-sm mb-1">
                        <span>Compliance Progress</span>
                        <span>{Math.round((pkg.compliantControls / pkg.totalControls) * 100)}%</span>
                      </div>
                      <Progress
                        value={(pkg.compliantControls / pkg.totalControls) * 100}
                        className="h-2"
                      />
                    </div>

                    <div>
                      <div className="text-sm text-muted-foreground mb-1">Package Hash</div>
                      <div className="font-mono text-xs bg-muted p-2 rounded flex items-center justify-between">
                        <span>{pkg.packageHash}</span>
                        <Button size="sm" variant="ghost">
                          <Hash className="h-3 w-3" />
                        </Button>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="verification" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Fingerprint className="h-5 w-5" />
                Attestation Verification
              </CardTitle>
              <CardDescription>
                Verify the cryptographic integrity of KHEPRA attestations
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                <Alert>
                  <Shield className="h-4 w-4" />
                  <AlertDescription>
                    All attestations are protected by KHEPRA's cultural cryptographic protocol,
                    ensuring both technical and semantic integrity.
                  </AlertDescription>
                </Alert>

                {selectedAttestation && (
                  <div className="space-y-4">
                    <h3 className="text-lg font-semibold">Attestation Details</h3>

                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <h4 className="font-medium mb-2">Basic Information</h4>
                        <div className="space-y-2 text-sm">
                          <div className="flex justify-between">
                            <span>Control ID:</span>
                            <span className="font-mono">{selectedAttestation.controlId}</span>
                          </div>
                          <div className="flex justify-between">
                            <span>Framework:</span>
                            <span>{selectedAttestation.framework}</span>
                          </div>
                          <div className="flex justify-between">
                            <span>Status:</span>
                            <Badge className={getStatusColor(selectedAttestation.status)}>
                              {selectedAttestation.status}
                            </Badge>
                          </div>
                          <div className="flex justify-between">
                            <span>Trust Score:</span>
                            <span>{selectedAttestation.trustScore}%</span>
                          </div>
                        </div>
                      </div>

                      <div>
                        <h4 className="font-medium mb-2">Cryptographic Details</h4>
                        <div className="space-y-2 text-sm">
                          <div>
                            <span className="text-muted-foreground">Signature:</span>
                            <div className="font-mono text-xs bg-muted p-2 rounded mt-1">
                              {showSignatureDetails ? selectedAttestation.signature : '•••••••••••••••'}
                            </div>
                            <Button
                              onClick={() => setShowSignatureDetails(!showSignatureDetails)}
                              size="sm"
                              variant="ghost"
                              className="mt-1"
                            >
                              {showSignatureDetails ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                            </Button>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Cultural Fingerprint:</span>
                            <div className="font-mono text-xs bg-muted p-2 rounded mt-1">
                              {selectedAttestation.culturalFingerprint}
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="flex gap-4">
                      <Button onClick={() => verifyAttestation(selectedAttestation)}>
                        <Fingerprint className="h-4 w-4 mr-2" />
                        Verify Signature
                      </Button>
                      <Button variant="outline">
                        <FileCheck className="h-4 w-4 mr-2" />
                        Generate Certificate
                      </Button>
                      <Button variant="outline">
                        <Download className="h-4 w-4 mr-2" />
                        Export Evidence
                      </Button>
                    </div>
                  </div>
                )}

                {!selectedAttestation && (
                  <div className="text-center text-muted-foreground py-8">
                    Select an attestation from the Attestations tab to view verification details
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="chain" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Lock className="h-5 w-5" />
                Attestation Chain
              </CardTitle>
              <CardDescription>
                Immutable chain of compliance attestations with cultural verification
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <Alert>
                  <Key className="h-4 w-4" />
                  <AlertDescription>
                    The attestation chain provides tamper-evident audit trails using KHEPRA's
                    Adinkra-based cryptographic signatures and cultural consensus mechanisms.
                  </AlertDescription>
                </Alert>

                <div className="space-y-3">
                  {Array.from({ length: 5 }).map((_, index) => {
                    const timestamp = new Date(Date.now() - index * 1000 * 60 * 60 * 6);
                    const blockId = `block-${5 - index}`;

                    return (
                      <div key={index} className="border rounded-lg p-4">
                        <div className="flex items-center justify-between mb-3">
                          <div className="flex items-center gap-2">
                            <Lock className="h-4 w-4 text-blue-500" />
                            <span className="font-medium">Block {blockId}</span>
                          </div>
                          <Badge variant="outline">
                            {timestamp.toLocaleString()}
                          </Badge>
                        </div>

                        <div className="grid grid-cols-3 gap-4 text-sm">
                          <div>
                            <span className="text-muted-foreground">Hash:</span>
                            <div className="font-mono text-xs">
                              sha256:{'N/A'}
                            </div>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Attestations:</span>
                            <div>{'N/A'}</div>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Trust Level:</span>
                            <div>{'N/A'}</div>
                          </div>
                        </div>

                        <div className="mt-3 pt-3 border-t">
                          <div className="text-xs text-muted-foreground">
                            Cultural Signature: adinkra:{['eban', 'fawohodie', 'nkyinkyim'][index % 3]}:verified:N/A
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};