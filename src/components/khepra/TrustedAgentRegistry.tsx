import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { 
  Shield, Users, Key, Award, AlertTriangle, CheckCircle, 
  Plus, RefreshCw, Eye, Settings, Zap, Clock
} from 'lucide-react';
import { TrustedAgentRegistry, AgentRegistration, PostQuantumKeyPair } from '@/khepra/registry/TrustedAgentRegistry';
import { AdinkraAlgebraicEngine } from '@/khepra/aae/AdinkraEngine';
import { useToast } from '@/hooks/use-toast';

export const TrustedAgentRegistryComponent = () => {
  const [registrations, setRegistrations] = useState<AgentRegistration[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState<AgentRegistration | null>(null);
  const [showRegisterForm, setShowRegisterForm] = useState(false);
  const [keyGenerationStatus, setKeyGenerationStatus] = useState<Record<string, string>>({});
  const { toast } = useToast();

  const [newAgent, setNewAgent] = useState({
    agentId: '',
    capabilities: '',
    culturalContext: 'security' as const
  });

  useEffect(() => {
    loadRegistrations();
  }, []);

  const loadRegistrations = () => {
    setLoading(true);
    try {
      const agents = TrustedAgentRegistry.getAllRegistrations();
      setRegistrations(agents);
    } catch (error) {
      console.error('Failed to load agent registrations:', error);
      toast({
        title: "Load Error",
        description: "Failed to load agent registrations",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const handleRegisterAgent = async () => {
    if (!newAgent.agentId.trim()) {
      toast({
        title: "Validation Error",
        description: "Agent ID is required",
        variant: "destructive"
      });
      return;
    }

    setLoading(true);
    try {
      // Generate post-quantum key pair
      const keyPair = await TrustedAgentRegistry.generatePostQuantumKeys('kyber1024', newAgent.culturalContext);
      const publicKeyHex = Array.from(keyPair.publicKey).map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 64);
      
      // Parse capabilities
      const capabilities = newAgent.capabilities.split(',').map(c => c.trim()).filter(c => c);
      
      // Register agent
      const registration = await TrustedAgentRegistry.registerAgent(
        newAgent.agentId,
        publicKeyHex,
        capabilities,
        newAgent.culturalContext
      );

      setRegistrations(prev => [...prev, registration]);
      setNewAgent({ agentId: '', capabilities: '', culturalContext: 'security' });
      setShowRegisterForm(false);

      toast({
        title: "Agent Registered",
        description: `Agent ${newAgent.agentId} registered successfully with DID`,
      });
    } catch (error) {
      console.error('Failed to register agent:', error);
      toast({
        title: "Registration Error",
        description: "Failed to register agent",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyAgent = async (agentId: string) => {
    const challenge = crypto.randomUUID();
    
    try {
      const verified = await TrustedAgentRegistry.verifyAgent(agentId, challenge);
      
      if (verified) {
        TrustedAgentRegistry.updateTrustScore(agentId, 5, 'Successful verification');
        toast({
          title: "Verification Successful",
          description: `Agent ${agentId} verified successfully`,
        });
      } else {
        TrustedAgentRegistry.updateTrustScore(agentId, -10, 'Failed verification');
        toast({
          title: "Verification Failed",
          description: `Agent ${agentId} failed verification`,
          variant: "destructive"
        });
      }
      
      loadRegistrations();
    } catch (error) {
      console.error('Verification error:', error);
      toast({
        title: "Verification Error",
        description: "Failed to verify agent",
        variant: "destructive"
      });
    }
  };

  const handleRevokeAgent = (agentId: string) => {
    const success = TrustedAgentRegistry.revokeAgent(agentId, 'Manual revocation');
    
    if (success) {
      loadRegistrations();
      toast({
        title: "Agent Revoked",
        description: `Agent ${agentId} has been revoked`,
      });
    } else {
      toast({
        title: "Revocation Error",
        description: "Failed to revoke agent",
        variant: "destructive"
      });
    }
  };

  const generateNewKeyPair = async (agentId: string) => {
    setKeyGenerationStatus(prev => ({ ...prev, [agentId]: 'generating' }));
    
    try {
      const registration = registrations.find(r => r.agentId === agentId);
      if (!registration) return;

      const keyPair = await TrustedAgentRegistry.generatePostQuantumKeys('dilithium5', registration.culturalContext);
      
      // In a real implementation, this would update the registration with new keys
      toast({
        title: "Key Pair Generated",
        description: `New post-quantum keys generated for ${agentId}`,
      });
      
      setKeyGenerationStatus(prev => ({ ...prev, [agentId]: 'completed' }));
      
      // Clear status after 3 seconds
      setTimeout(() => {
        setKeyGenerationStatus(prev => {
          const updated = { ...prev };
          delete updated[agentId];
          return updated;
        });
      }, 3000);
    } catch (error) {
      console.error('Key generation error:', error);
      setKeyGenerationStatus(prev => ({ ...prev, [agentId]: 'error' }));
      toast({
        title: "Key Generation Error",
        description: "Failed to generate new key pair",
        variant: "destructive"
      });
    }
  };

  const getTrustScoreColor = (score: number) => {
    if (score >= 80) return 'text-green-400';
    if (score >= 60) return 'text-yellow-400';
    return 'text-red-400';
  };

  const getTrustScoreBadgeVariant = (score: number) => {
    if (score >= 80) return 'default';
    if (score >= 60) return 'secondary';
    return 'destructive';
  };

  const getRiskScoreColor = (score: number) => {
    if (score <= 30) return 'text-green-400';
    if (score <= 60) return 'text-yellow-400';
    return 'text-red-400';
  };

  const getCulturalContextColor = (context: string) => {
    const colors = {
      'security': 'bg-blue-500/20 text-blue-300 border-blue-500/30',
      'trust': 'bg-purple-500/20 text-purple-300 border-purple-500/30',
      'transformation': 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
      'unity': 'bg-green-500/20 text-green-300 border-green-500/30'
    };
    return colors[context] || 'bg-gray-500/20 text-gray-300 border-gray-500/30';
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-primary">Trusted Agent Registry</h2>
          <p className="text-muted-foreground">Manage AI agents with cultural verification and post-quantum security</p>
        </div>
        <div className="flex items-center space-x-2">
          <Button
            onClick={loadRegistrations}
            disabled={loading}
            variant="outline"
            size="sm"
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Dialog open={showRegisterForm} onOpenChange={setShowRegisterForm}>
            <DialogTrigger asChild>
              <Button size="sm">
                <Plus className="h-4 w-4 mr-2" />
                Register Agent
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Register New Agent</DialogTitle>
              </DialogHeader>
              <div className="space-y-4">
                <div>
                  <Label htmlFor="agentId">Agent ID</Label>
                  <Input
                    id="agentId"
                    value={newAgent.agentId}
                    onChange={(e) => setNewAgent(prev => ({ ...prev, agentId: e.target.value }))}
                    placeholder="e.g., argus-ai-security"
                  />
                </div>
                <div>
                  <Label htmlFor="capabilities">Capabilities (comma-separated)</Label>
                  <Input
                    id="capabilities"
                    value={newAgent.capabilities}
                    onChange={(e) => setNewAgent(prev => ({ ...prev, capabilities: e.target.value }))}
                    placeholder="e.g., threat_analysis, incident_response"
                  />
                </div>
                <div>
                  <Label htmlFor="culturalContext">Cultural Context</Label>
                  <select
                    id="culturalContext"
                    value={newAgent.culturalContext}
                    onChange={(e) => setNewAgent(prev => ({ ...prev, culturalContext: e.target.value as any }))}
                    className="w-full rounded-md border border-input bg-background px-3 py-2"
                  >
                    <option value="security">Security (Eban)</option>
                    <option value="trust">Trust (Nyame)</option>
                    <option value="transformation">Transformation (Nkyinkyim)</option>
                    <option value="unity">Unity (Adwo)</option>
                  </select>
                </div>
                <div className="flex justify-end space-x-2">
                  <Button variant="outline" onClick={() => setShowRegisterForm(false)}>
                    Cancel
                  </Button>
                  <Button onClick={handleRegisterAgent} disabled={loading}>
                    {loading ? <RefreshCw className="h-4 w-4 animate-spin mr-2" /> : null}
                    Register
                  </Button>
                </div>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Registry Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Users className="h-5 w-5 text-primary" />
              <div>
                <p className="text-sm text-muted-foreground">Total Agents</p>
                <p className="text-2xl font-bold">{registrations.length}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Shield className="h-5 w-5 text-green-400" />
              <div>
                <p className="text-sm text-muted-foreground">Verified</p>
                <p className="text-2xl font-bold text-green-400">
                  {registrations.filter(r => !r.did.revoked && r.did.trustScore >= 70).length}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="h-5 w-5 text-yellow-400" />
              <div>
                <p className="text-sm text-muted-foreground">Low Trust</p>
                <p className="text-2xl font-bold text-yellow-400">
                  {registrations.filter(r => !r.did.revoked && r.did.trustScore < 70).length}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Key className="h-5 w-5 text-purple-400" />
              <div>
                <p className="text-sm text-muted-foreground">PQ Keys</p>
                <p className="text-2xl font-bold text-purple-400">
                  {registrations.length}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Agent Registry Table */}
      <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Users className="h-5 w-5" />
            <span>Registered Agents</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[600px]">
            <div className="space-y-4">
              {registrations.map((registration) => (
                <Card key={registration.agentId} className="border-border/50">
                  <CardContent className="p-4">
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                      {/* Agent Info */}
                      <div className="space-y-2">
                        <div className="flex items-center space-x-2">
                          <h3 className="font-semibold">{registration.agentId}</h3>
                          {registration.did.revoked ? (
                            <Badge variant="destructive">Revoked</Badge>
                          ) : (
                            <Badge variant="default">Active</Badge>
                          )}
                        </div>
                        
                        <div className="space-y-1">
                          <div className="flex items-center space-x-2">
                            <span className="text-xs text-muted-foreground">Trust Score:</span>
                            <Badge 
                              variant={getTrustScoreBadgeVariant(registration.did.trustScore)}
                              className="text-xs"
                            >
                              {registration.did.trustScore}
                            </Badge>
                          </div>
                          
                          <div className="flex items-center space-x-2">
                            <span className="text-xs text-muted-foreground">Risk Score:</span>
                            <span className={`text-xs ${getRiskScoreColor(registration.riskScore)}`}>
                              {registration.riskScore}
                            </span>
                          </div>
                          
                          <div className="flex items-center space-x-2">
                            <span className="text-xs text-muted-foreground">Cultural Context:</span>
                            <Badge className={getCulturalContextColor(registration.culturalContext)}>
                              {registration.culturalContext}
                            </Badge>
                          </div>
                        </div>
                      </div>

                      {/* DID & Credentials */}
                      <div className="space-y-2">
                        <h4 className="text-sm font-medium">Digital Identity</h4>
                        
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <div className="text-xs font-mono bg-muted p-2 rounded truncate cursor-help">
                              {registration.did.did}
                            </div>
                          </TooltipTrigger>
                          <TooltipContent>
                            <p>Full DID: {registration.did.did}</p>
                          </TooltipContent>
                        </Tooltip>
                        
                        <div className="space-y-1">
                          <div className="text-xs text-muted-foreground">
                            Credentials: {registration.credentials.length}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            Expires: {registration.did.expires.toLocaleDateString()}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            Last Verified: {registration.lastVerified.toLocaleString()}
                          </div>
                        </div>

                        <div className="flex flex-wrap gap-1">
                          {registration.capabilities.slice(0, 3).map((cap, idx) => (
                            <Badge key={idx} variant="outline" className="text-xs">
                              {cap}
                            </Badge>
                          ))}
                          {registration.capabilities.length > 3 && (
                            <Badge variant="outline" className="text-xs">
                              +{registration.capabilities.length - 3} more
                            </Badge>
                          )}
                        </div>
                      </div>

                      {/* Actions */}
                      <div className="space-y-2">
                        <h4 className="text-sm font-medium">Actions</h4>
                        
                        <div className="flex flex-wrap gap-2">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleVerifyAgent(registration.agentId)}
                            disabled={registration.did.revoked}
                          >
                            <CheckCircle className="h-3 w-3 mr-1" />
                            Verify
                          </Button>
                          
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => generateNewKeyPair(registration.agentId)}
                            disabled={registration.did.revoked || keyGenerationStatus[registration.agentId] === 'generating'}
                          >
                            {keyGenerationStatus[registration.agentId] === 'generating' ? (
                              <RefreshCw className="h-3 w-3 mr-1 animate-spin" />
                            ) : keyGenerationStatus[registration.agentId] === 'completed' ? (
                              <CheckCircle className="h-3 w-3 mr-1 text-green-400" />
                            ) : (
                              <Key className="h-3 w-3 mr-1" />
                            )}
                            PQ Keys
                          </Button>
                          
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => setSelectedAgent(registration)}
                          >
                            <Eye className="h-3 w-3 mr-1" />
                            Details
                          </Button>
                          
                          {!registration.did.revoked && (
                            <Button
                              size="sm"
                              variant="destructive"
                              onClick={() => handleRevokeAgent(registration.agentId)}
                            >
                              <AlertTriangle className="h-3 w-3 mr-1" />
                              Revoke
                            </Button>
                          )}
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
              
              {registrations.length === 0 && !loading && (
                <div className="text-center py-8 text-muted-foreground">
                  <Users className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No agents registered yet.</p>
                  <p className="text-sm">Register your first agent to get started.</p>
                </div>
              )}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>

      {/* Agent Details Dialog */}
      {selectedAgent && (
        <Dialog open={!!selectedAgent} onOpenChange={() => setSelectedAgent(null)}>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Agent Details: {selectedAgent.agentId}</DialogTitle>
            </DialogHeader>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h4 className="font-medium mb-2">Digital Identity</h4>
                  <div className="space-y-1 text-sm">
                    <p><span className="text-muted-foreground">DID:</span> {selectedAgent.did.did}</p>
                    <p><span className="text-muted-foreground">Trust Score:</span> 
                      <span className={getTrustScoreColor(selectedAgent.did.trustScore)}>
                        {selectedAgent.did.trustScore}
                      </span>
                    </p>
                    <p><span className="text-muted-foreground">Cultural Context:</span> {selectedAgent.culturalContext}</p>
                    <p><span className="text-muted-foreground">Risk Score:</span> 
                      <span className={getRiskScoreColor(selectedAgent.riskScore)}>
                        {selectedAgent.riskScore}
                      </span>
                    </p>
                  </div>
                </div>
                
                <div>
                  <h4 className="font-medium mb-2">Registration Info</h4>
                  <div className="space-y-1 text-sm">
                    <p><span className="text-muted-foreground">Created:</span> {selectedAgent.did.created.toLocaleString()}</p>
                    <p><span className="text-muted-foreground">Expires:</span> {selectedAgent.did.expires.toLocaleString()}</p>
                    <p><span className="text-muted-foreground">Last Verified:</span> {selectedAgent.lastVerified.toLocaleString()}</p>
                    <p><span className="text-muted-foreground">Status:</span> 
                      {selectedAgent.did.revoked ? 
                        <Badge variant="destructive" className="ml-1">Revoked</Badge> : 
                        <Badge variant="default" className="ml-1">Active</Badge>
                      }
                    </p>
                  </div>
                </div>
              </div>
              
              <Separator />
              
              <div>
                <h4 className="font-medium mb-2">Capabilities</h4>
                <div className="flex flex-wrap gap-2">
                  {selectedAgent.capabilities.map((cap, idx) => (
                    <Badge key={idx} variant="outline">{cap}</Badge>
                  ))}
                </div>
              </div>
              
              <Separator />
              
              <div>
                <h4 className="font-medium mb-2">Credentials ({selectedAgent.credentials.length})</h4>
                <div className="space-y-2">
                  {selectedAgent.credentials.map((cred, idx) => (
                    <div key={idx} className="p-2 bg-muted rounded text-sm">
                      <div className="flex items-center justify-between">
                        <span className="font-medium">{cred.credentialType.replaceAll('_', ' ')}</span>
                        <Badge variant="outline" className="text-xs">
                          Valid until {cred.validUntil.toLocaleDateString()}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground mt-1">
                        Adinkra Fingerprint: {cred.adinkraFingerprint}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      )}
    </div>
  );
};