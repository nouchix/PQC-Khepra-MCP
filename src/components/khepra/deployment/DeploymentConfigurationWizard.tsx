import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { Slider } from '@/components/ui/slider';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Settings, 
  Shield, 
  Zap, 
  Network, 
  Globe, 
  Lock,
  Eye,
  Bell,
  Database,
  Code,
  Cpu,
  HardDrive,
  Wifi,
  ChevronRight,
  Info,
  AlertTriangle,
  CheckCircle
} from 'lucide-react';
import { AdinkraSymbolDisplay } from '../AdinkraSymbolDisplay';

interface SecurityProfile {
  id: string;
  name: string;
  description: string;
  level: 'basic' | 'standard' | 'advanced' | 'maximum';
  features: string[];
  cultural_symbol: string;
  quantum_safe: boolean;
  ai_powered: boolean;
}

interface CulturalContext {
  id: string;
  name: string;
  description: string;
  symbols: string[];
  threat_patterns: string[];
  wisdom_principles: string[];
}

interface DeploymentConfiguration {
  // Security Settings
  security_profile: string;
  cultural_context: string;
  encryption_level: number;
  quantum_safe_enabled: boolean;
  cultural_fingerprinting: boolean;
  
  // Network Settings
  network_isolation: boolean;
  mesh_networking: boolean;
  p2p_encryption: boolean;
  bandwidth_allocation: number;
  
  // Monitoring Settings
  real_time_monitoring: boolean;
  threat_intelligence: boolean;
  anomaly_detection: boolean;
  cultural_analysis: boolean;
  alert_sensitivity: number;
  
  // Advanced Settings
  custom_adinkra_set: string[];
  agent_density: number;
  consensus_threshold: number;
  auto_remediation: boolean;
  backup_strategy: string;
  compliance_frameworks: string[];
  
  // Environment Specific
  environment_type: 'production' | 'staging' | 'development' | 'testing';
  scaling_mode: 'manual' | 'auto' | 'predictive';
  resource_limits: {
    cpu_cores: number;
    memory_gb: number;
    storage_gb: number;
    network_mbps: number;
  };
}

interface DeploymentConfigurationWizardProps {
  deploymentVector: any;
  selectedAssets: any[];
  onConfigurationChange: (config: DeploymentConfiguration) => void;
  onComplete: (config: DeploymentConfiguration) => void;
}

const securityProfiles: SecurityProfile[] = [
  {
    id: 'basic',
    name: 'Sankofa Guardian',
    description: 'Essential protection with cultural wisdom',
    level: 'basic',
    features: ['Basic encryption', 'Cultural symbols', 'Simple monitoring'],
    cultural_symbol: 'Sankofa',
    quantum_safe: false,
    ai_powered: false
  },
  {
    id: 'standard',
    name: 'Gye Nyame Shield',
    description: 'Comprehensive security with AI enhancement',
    level: 'standard',
    features: ['AES-256 encryption', 'AI threat detection', 'Cultural fingerprinting', 'Real-time monitoring'],
    cultural_symbol: 'Gye_Nyame',
    quantum_safe: true,
    ai_powered: true
  },
  {
    id: 'advanced',
    name: 'Eban Fortress',
    description: 'Advanced protection with quantum safety',
    level: 'advanced',
    features: ['Quantum-safe encryption', 'Adaptive AI agents', 'Cultural threat taxonomy', 'Predictive analytics'],
    cultural_symbol: 'Eban',
    quantum_safe: true,
    ai_powered: true
  },
  {
    id: 'maximum',
    name: 'Adwo Collective',
    description: 'Maximum security with community intelligence',
    level: 'maximum',
    features: ['Post-quantum cryptography', 'Autonomous agents', 'Cultural mesh network', 'Collective intelligence'],
    cultural_symbol: 'Adwo',
    quantum_safe: true,
    ai_powered: true
  }
];

const culturalContexts: CulturalContext[] = [
  {
    id: 'west_african',
    name: 'West African Wisdom',
    description: 'Traditional Akan and Yoruba security principles',
    symbols: ['Sankofa', 'Gye_Nyame', 'Eban', 'Nkyinkyim'],
    threat_patterns: ['Colonial exploitation patterns', 'Resource extraction threats', 'Cultural appropriation'],
    wisdom_principles: ['Community protection', 'Ancestral guidance', 'Collective security']
  },
  {
    id: 'pan_african',
    name: 'Pan-African Unity',
    description: 'Continental security framework',
    symbols: ['Adwo', 'Fawohodie', 'Dwennimmen', 'Aya'],
    threat_patterns: ['Neo-colonial digital threats', 'Economic manipulation', 'Cultural dilution'],
    wisdom_principles: ['Unity in diversity', 'Self-determination', 'Collective prosperity']
  },
  {
    id: 'diaspora',
    name: 'Diaspora Resilience',
    description: 'Global African diaspora security patterns',
    symbols: ['Sankofa', 'Fawohodie', 'Nkyinkyim', 'Mpatapo'],
    threat_patterns: ['Systemic discrimination', 'Identity erasure', 'Economic exclusion'],
    wisdom_principles: ['Cultural preservation', 'Adaptive resistance', 'Community building']
  }
];

export const DeploymentConfigurationWizard: React.FC<DeploymentConfigurationWizardProps> = ({
  deploymentVector,
  selectedAssets,
  onConfigurationChange,
  onComplete
}) => {
  const [configuration, setConfiguration] = useState<DeploymentConfiguration>({
    // Security Settings
    security_profile: 'standard',
    cultural_context: 'west_african',
    encryption_level: 256,
    quantum_safe_enabled: true,
    cultural_fingerprinting: true,
    
    // Network Settings
    network_isolation: true,
    mesh_networking: false,
    p2p_encryption: true,
    bandwidth_allocation: 50,
    
    // Monitoring Settings
    real_time_monitoring: true,
    threat_intelligence: true,
    anomaly_detection: true,
    cultural_analysis: true,
    alert_sensitivity: 70,
    
    // Advanced Settings
    custom_adinkra_set: [],
    agent_density: 3,
    consensus_threshold: 67,
    auto_remediation: false,
    backup_strategy: 'distributed',
    compliance_frameworks: ['NIST', 'CMMC'],
    
    // Environment Specific
    environment_type: 'production',
    scaling_mode: 'auto',
    resource_limits: {
      cpu_cores: 4,
      memory_gb: 8,
      storage_gb: 100,
      network_mbps: 1000
    }
  });

  const [currentTab, setCurrentTab] = useState('security');
  const [configurationValid, setConfigurationValid] = useState(false);

  useEffect(() => {
    onConfigurationChange(configuration);
    validateConfiguration();
  }, [configuration, onConfigurationChange]);

  const validateConfiguration = () => {
    const isValid = 
      configuration.security_profile &&
      configuration.cultural_context &&
      configuration.encryption_level >= 128 &&
      configuration.agent_density > 0 &&
      configuration.consensus_threshold > 50 &&
      configuration.resource_limits.cpu_cores > 0 &&
      configuration.resource_limits.memory_gb > 0;
    
    setConfigurationValid(isValid);
  };

  const updateConfiguration = (updates: Partial<DeploymentConfiguration>) => {
    setConfiguration(prev => ({ ...prev, ...updates }));
  };

  const getProfileIcon = (level: string) => {
    switch (level) {
      case 'basic': return <Shield className="h-4 w-4 text-green-500" />;
      case 'standard': return <Shield className="h-4 w-4 text-blue-500" />;
      case 'advanced': return <Shield className="h-4 w-4 text-purple-500" />;
      case 'maximum': return <Shield className="h-4 w-4 text-red-500" />;
      default: return <Shield className="h-4 w-4" />;
    }
  };

  const getSecurityLevel = () => {
    const profile = securityProfiles.find(p => p.id === configuration.security_profile);
    return profile?.level || 'standard';
  };

  const getEstimatedResources = () => {
    const baseMultiplier = securityProfiles.find(p => p.id === configuration.security_profile)?.level === 'maximum' ? 2 : 1;
    const assetMultiplier = selectedAssets.length * 0.1;
    
    return {
      cpu: Math.max(2, Math.round(configuration.resource_limits.cpu_cores * baseMultiplier * (1 + assetMultiplier))),
      memory: Math.max(4, Math.round(configuration.resource_limits.memory_gb * baseMultiplier * (1 + assetMultiplier))),
      storage: Math.max(50, Math.round(configuration.resource_limits.storage_gb * baseMultiplier * (1 + assetMultiplier))),
      network: Math.round(configuration.resource_limits.network_mbps * baseMultiplier)
    };
  };

  return (
    <div className="space-y-6">
      {/* Configuration Header */}
      <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Settings className="h-5 w-5 text-primary" />
            <span>KHEPRA Protocol Configuration</span>
          </CardTitle>
          <p className="text-sm text-muted-foreground">
            Configure your deployment for {deploymentVector?.name} across {selectedAssets.length} assets
          </p>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="text-center">
              <div className="text-lg font-bold text-primary capitalize">{getSecurityLevel()}</div>
              <div className="text-sm text-muted-foreground">Security Level</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-bold text-green-500">{selectedAssets.length}</div>
              <div className="text-sm text-muted-foreground">Protected Assets</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-bold text-blue-500">
                {configuration.quantum_safe_enabled ? 'Quantum-Safe' : 'Standard'}
              </div>
              <div className="text-sm text-muted-foreground">Encryption</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-bold text-purple-500">
                {culturalContexts.find(c => c.id === configuration.cultural_context)?.symbols.length || 0}
              </div>
              <div className="text-sm text-muted-foreground">Cultural Symbols</div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Configuration Tabs */}
      <Card className="border-border">
        <CardContent className="p-0">
          <Tabs value={currentTab} onValueChange={setCurrentTab}>
            <div className="border-b border-border p-4">
              <TabsList className="grid grid-cols-5 w-full">
                <TabsTrigger value="security" className="flex items-center space-x-2">
                  <Shield className="h-4 w-4" />
                  <span>Security</span>
                </TabsTrigger>
                <TabsTrigger value="network" className="flex items-center space-x-2">
                  <Network className="h-4 w-4" />
                  <span>Network</span>
                </TabsTrigger>
                <TabsTrigger value="monitoring" className="flex items-center space-x-2">
                  <Eye className="h-4 w-4" />
                  <span>Monitoring</span>
                </TabsTrigger>
                <TabsTrigger value="advanced" className="flex items-center space-x-2">
                  <Code className="h-4 w-4" />
                  <span>Advanced</span>
                </TabsTrigger>
                <TabsTrigger value="resources" className="flex items-center space-x-2">
                  <Cpu className="h-4 w-4" />
                  <span>Resources</span>
                </TabsTrigger>
              </TabsList>
            </div>

            <div className="p-6">
              <TabsContent value="security" className="space-y-6 mt-0">
                {/* Security Profile */}
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">Security Profile</h3>
                  <RadioGroup 
                    value={configuration.security_profile} 
                    onValueChange={(value) => updateConfiguration({ security_profile: value })}
                  >
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      {securityProfiles.map((profile) => (
                        <div key={profile.id} className="relative">
                          <RadioGroupItem 
                            value={profile.id} 
                            id={profile.id} 
                            className="sr-only" 
                          />
                          <Label 
                            htmlFor={profile.id}
                            className={`block p-4 border rounded-lg cursor-pointer transition-all ${
                              configuration.security_profile === profile.id 
                                ? 'border-primary bg-primary/5' 
                                : 'border-border hover:border-primary/30'
                            }`}
                          >
                            <div className="flex items-start space-x-3">
                              <div className="w-8 h-8 mt-1">
                                <AdinkraSymbolDisplay 
                                  symbolName={profile.cultural_symbol} 
                                  size="small" 
                                  showMatrix={false}
                                />
                              </div>
                              <div className="flex-1">
                                <div className="flex items-center space-x-2">
                                  <h4 className="font-medium">{profile.name}</h4>
                                  {getProfileIcon(profile.level)}
                                  {profile.quantum_safe && (
                                    <Badge variant="outline">
                                      <Lock className="h-3 w-3 mr-1" />
                                      Quantum-Safe
                                    </Badge>
                                  )}
                                  {profile.ai_powered && (
                                    <Badge variant="outline">
                                      <Zap className="h-3 w-3 mr-1" />
                                      AI-Powered
                                    </Badge>
                                  )}
                                </div>
                                <p className="text-sm text-muted-foreground mt-1">
                                  {profile.description}
                                </p>
                                <div className="mt-2">
                                  <div className="text-xs text-muted-foreground">Features:</div>
                                  <div className="flex flex-wrap gap-1 mt-1">
                                    {profile.features.map(feature => (
                                      <Badge key={feature} variant="secondary">
                                        {feature}
                                      </Badge>
                                    ))}
                                  </div>
                                </div>
                              </div>
                            </div>
                          </Label>
                        </div>
                      ))}
                    </div>
                  </RadioGroup>
                </div>

                {/* Cultural Context */}
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">Cultural Context</h3>
                  <RadioGroup 
                    value={configuration.cultural_context} 
                    onValueChange={(value) => updateConfiguration({ cultural_context: value })}
                  >
                    {culturalContexts.map((context) => (
                      <div key={context.id} className="relative">
                        <RadioGroupItem 
                          value={context.id} 
                          id={context.id} 
                          className="sr-only" 
                        />
                        <Label 
                          htmlFor={context.id}
                          className={`block p-4 border rounded-lg cursor-pointer transition-all ${
                            configuration.cultural_context === context.id 
                              ? 'border-primary bg-primary/5' 
                              : 'border-border hover:border-primary/30'
                          }`}
                        >
                          <div>
                            <h4 className="font-medium">{context.name}</h4>
                            <p className="text-sm text-muted-foreground mt-1">
                              {context.description}
                            </p>
                            <div className="mt-2 space-y-1">
                              <div className="text-xs text-muted-foreground">Symbols:</div>
                              <div className="flex flex-wrap gap-1">
                                {context.symbols.map(symbol => (
                                  <Badge key={symbol} variant="outline">
                                    {symbol}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          </div>
                        </Label>
                      </div>
                    ))}
                  </RadioGroup>
                </div>

                {/* Security Options */}
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">Security Options</h3>
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <Label htmlFor="quantum-safe">Quantum-Safe Encryption</Label>
                        <Switch
                          id="quantum-safe"
                          checked={configuration.quantum_safe_enabled}
                          onCheckedChange={(checked) => updateConfiguration({ quantum_safe_enabled: checked })}
                        />
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <Label htmlFor="cultural-fingerprinting">Cultural Fingerprinting</Label>
                        <Switch
                          id="cultural-fingerprinting"
                          checked={configuration.cultural_fingerprinting}
                          onCheckedChange={(checked) => updateConfiguration({ cultural_fingerprinting: checked })}
                        />
                      </div>

                      <div className="space-y-2">
                        <Label htmlFor="encryption-level">Encryption Level</Label>
                        <div className="space-y-2">
                          <Slider
                            id="encryption-level"
                            min={128}
                            max={512}
                            step={64}
                            value={[configuration.encryption_level]}
                            onValueChange={([value]) => updateConfiguration({ encryption_level: value })}
                          />
                          <div className="flex justify-between text-xs text-muted-foreground">
                            <span>128-bit</span>
                            <span>{configuration.encryption_level}-bit</span>
                            <span>512-bit</span>
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="space-y-4">
                      <div className="space-y-2">
                        <Label htmlFor="agent-density">Agent Density</Label>
                        <div className="space-y-2">
                          <Slider
                            id="agent-density"
                            min={1}
                            max={10}
                            step={1}
                            value={[configuration.agent_density]}
                            onValueChange={([value]) => updateConfiguration({ agent_density: value })}
                          />
                          <div className="flex justify-between text-xs text-muted-foreground">
                            <span>Low (1)</span>
                            <span>{configuration.agent_density}</span>
                            <span>High (10)</span>
                          </div>
                        </div>
                      </div>

                      <div className="space-y-2">
                        <Label htmlFor="consensus-threshold">Consensus Threshold</Label>
                        <div className="space-y-2">
                          <Slider
                            id="consensus-threshold"
                            min={51}
                            max={99}
                            step={1}
                            value={[configuration.consensus_threshold]}
                            onValueChange={([value]) => updateConfiguration({ consensus_threshold: value })}
                          />
                          <div className="flex justify-between text-xs text-muted-foreground">
                            <span>51%</span>
                            <span>{configuration.consensus_threshold}%</span>
                            <span>99%</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="network" className="space-y-6 mt-0">
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">Network Configuration</h3>
                  
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <Label htmlFor="network-isolation">Network Isolation</Label>
                        <Switch
                          id="network-isolation"
                          checked={configuration.network_isolation}
                          onCheckedChange={(checked) => updateConfiguration({ network_isolation: checked })}
                        />
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <Label htmlFor="mesh-networking">Mesh Networking</Label>
                        <Switch
                          id="mesh-networking"
                          checked={configuration.mesh_networking}
                          onCheckedChange={(checked) => updateConfiguration({ mesh_networking: checked })}
                        />
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <Label htmlFor="p2p-encryption">P2P Encryption</Label>
                        <Switch
                          id="p2p-encryption"
                          checked={configuration.p2p_encryption}
                          onCheckedChange={(checked) => updateConfiguration({ p2p_encryption: checked })}
                        />
                      </div>
                    </div>

                    <div className="space-y-4">
                      <div className="space-y-2">
                        <Label htmlFor="bandwidth-allocation">Bandwidth Allocation (%)</Label>
                        <div className="space-y-2">
                          <Slider
                            id="bandwidth-allocation"
                            min={10}
                            max={100}
                            step={5}
                            value={[configuration.bandwidth_allocation]}
                            onValueChange={([value]) => updateConfiguration({ bandwidth_allocation: value })}
                          />
                          <div className="flex justify-between text-xs text-muted-foreground">
                            <span>10%</span>
                            <span>{configuration.bandwidth_allocation}%</span>
                            <span>100%</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="monitoring" className="space-y-6 mt-0">
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">Monitoring & Detection</h3>
                  
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <Label htmlFor="real-time-monitoring">Real-time Monitoring</Label>
                        <Switch
                          id="real-time-monitoring"
                          checked={configuration.real_time_monitoring}
                          onCheckedChange={(checked) => updateConfiguration({ real_time_monitoring: checked })}
                        />
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <Label htmlFor="threat-intelligence">Threat Intelligence</Label>
                        <Switch
                          id="threat-intelligence"
                          checked={configuration.threat_intelligence}
                          onCheckedChange={(checked) => updateConfiguration({ threat_intelligence: checked })}
                        />
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <Label htmlFor="anomaly-detection">Anomaly Detection</Label>
                        <Switch
                          id="anomaly-detection"
                          checked={configuration.anomaly_detection}
                          onCheckedChange={(checked) => updateConfiguration({ anomaly_detection: checked })}
                        />
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <Label htmlFor="cultural-analysis">Cultural Analysis</Label>
                        <Switch
                          id="cultural-analysis"
                          checked={configuration.cultural_analysis}
                          onCheckedChange={(checked) => updateConfiguration({ cultural_analysis: checked })}
                        />
                      </div>
                    </div>

                    <div className="space-y-4">
                      <div className="space-y-2">
                        <Label htmlFor="alert-sensitivity">Alert Sensitivity</Label>
                        <div className="space-y-2">
                          <Slider
                            id="alert-sensitivity"
                            min={10}
                            max={100}
                            step={5}
                            value={[configuration.alert_sensitivity]}
                            onValueChange={([value]) => updateConfiguration({ alert_sensitivity: value })}
                          />
                          <div className="flex justify-between text-xs text-muted-foreground">
                            <span>Low (10)</span>
                            <span>{configuration.alert_sensitivity}</span>
                            <span>High (100)</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="advanced" className="space-y-6 mt-0">
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">Advanced Settings</h3>
                  
                  <div className="space-y-4">
                    <div>
                      <Label htmlFor="environment-type">Environment Type</Label>
                      <RadioGroup 
                        value={configuration.environment_type} 
                        onValueChange={(value: any) => updateConfiguration({ environment_type: value })}
                        className="mt-2"
                      >
                        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                          {['production', 'staging', 'development', 'testing'].map((env) => (
                            <div key={env} className="flex items-center space-x-2">
                              <RadioGroupItem value={env} id={env} />
                              <Label htmlFor={env} className="capitalize">{env}</Label>
                            </div>
                          ))}
                        </div>
                      </RadioGroup>
                    </div>

                    <div>
                      <Label htmlFor="scaling-mode">Scaling Mode</Label>
                      <RadioGroup 
                        value={configuration.scaling_mode} 
                        onValueChange={(value: any) => updateConfiguration({ scaling_mode: value })}
                        className="mt-2"
                      >
                        <div className="grid grid-cols-3 gap-4">
                          {['manual', 'auto', 'predictive'].map((mode) => (
                            <div key={mode} className="flex items-center space-x-2">
                              <RadioGroupItem value={mode} id={mode} />
                              <Label htmlFor={mode} className="capitalize">{mode}</Label>
                            </div>
                          ))}
                        </div>
                      </RadioGroup>
                    </div>

                    <div>
                      <Label htmlFor="backup-strategy">Backup Strategy</Label>
                      <RadioGroup 
                        value={configuration.backup_strategy} 
                        onValueChange={(value) => updateConfiguration({ backup_strategy: value })}
                        className="mt-2"
                      >
                        <div className="grid grid-cols-3 gap-4">
                          {['centralized', 'distributed', 'hybrid'].map((strategy) => (
                            <div key={strategy} className="flex items-center space-x-2">
                              <RadioGroupItem value={strategy} id={strategy} />
                              <Label htmlFor={strategy} className="capitalize">{strategy}</Label>
                            </div>
                          ))}
                        </div>
                      </RadioGroup>
                    </div>

                    <div className="flex items-center justify-between">
                      <Label htmlFor="auto-remediation">Auto-remediation</Label>
                      <Switch
                        id="auto-remediation"
                        checked={configuration.auto_remediation}
                        onCheckedChange={(checked) => updateConfiguration({ auto_remediation: checked })}
                      />
                    </div>
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="resources" className="space-y-6 mt-0">
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">Resource Allocation</h3>
                  
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div className="space-y-4">
                      <div className="space-y-2">
                        <Label htmlFor="cpu-cores">CPU Cores</Label>
                        <Input
                          id="cpu-cores"
                          type="number"
                          min="1"
                          max="64"
                          value={configuration.resource_limits.cpu_cores}
                          onChange={(e) => updateConfiguration({
                            resource_limits: {
                              ...configuration.resource_limits,
                              cpu_cores: Number.parseInt(e.target.value) || 1
                            }
                          })}
                        />
                      </div>

                      <div className="space-y-2">
                        <Label htmlFor="memory-gb">Memory (GB)</Label>
                        <Input
                          id="memory-gb"
                          type="number"
                          min="1"
                          max="512"
                          value={configuration.resource_limits.memory_gb}
                          onChange={(e) => updateConfiguration({
                            resource_limits: {
                              ...configuration.resource_limits,
                              memory_gb: Number.parseInt(e.target.value) || 1
                            }
                          })}
                        />
                      </div>
                    </div>

                    <div className="space-y-4">
                      <div className="space-y-2">
                        <Label htmlFor="storage-gb">Storage (GB)</Label>
                        <Input
                          id="storage-gb"
                          type="number"
                          min="10"
                          max="10000"
                          value={configuration.resource_limits.storage_gb}
                          onChange={(e) => updateConfiguration({
                            resource_limits: {
                              ...configuration.resource_limits,
                              storage_gb: Number.parseInt(e.target.value) || 10
                            }
                          })}
                        />
                      </div>

                      <div className="space-y-2">
                        <Label htmlFor="network-mbps">Network (Mbps)</Label>
                        <Input
                          id="network-mbps"
                          type="number"
                          min="10"
                          max="10000"
                          value={configuration.resource_limits.network_mbps}
                          onChange={(e) => updateConfiguration({
                            resource_limits: {
                              ...configuration.resource_limits,
                              network_mbps: Number.parseInt(e.target.value) || 10
                            }
                          })}
                        />
                      </div>
                    </div>
                  </div>

                  {/* Resource Estimation */}
                  <Card className="border-info/20 bg-info/5">
                    <CardHeader>
                      <CardTitle className="text-sm flex items-center space-x-2">
                        <Info className="h-4 w-4" />
                        <span>Estimated Resource Usage</span>
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                        {Object.entries(getEstimatedResources()).map(([key, value]) => (
                          <div key={key} className="text-center">
                            <div className="text-lg font-bold text-primary">{value}</div>
                            <div className="text-xs text-muted-foreground capitalize">
                              {key === 'network' ? 'Mbps' : key === 'cpu' ? 'Cores' : key === 'memory' ? 'GB RAM' : 'GB Storage'}
                            </div>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>
            </div>
          </Tabs>
        </CardContent>
      </Card>

      {/* Configuration Summary & Action */}
      <Card className="border-border">
        <CardContent className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <div className="flex items-center space-x-2">
                <CheckCircle className={`h-5 w-5 ${configurationValid ? 'text-green-500' : 'text-muted-foreground'}`} />
                <span className="font-medium">
                  Configuration {configurationValid ? 'Complete' : 'Incomplete'}
                </span>
              </div>
              <div className="text-sm text-muted-foreground mt-1">
                {configurationValid 
                  ? 'Your KHEPRA deployment is ready to begin'
                  : 'Please complete all required configuration fields'
                }
              </div>
            </div>
            <Button 
              onClick={() => onComplete(configuration)}
              disabled={!configurationValid}
              className="btn-cyber"
            >
              <ChevronRight className="h-4 w-4 mr-2" />
              Proceed to Deployment
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};