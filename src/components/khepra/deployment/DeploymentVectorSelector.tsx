import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import { ScrollArea } from '@/components/ui/scroll-area';
import { 
  Globe, 
  Cloud, 
  Zap, 
  HardDrive, 
  Network,
  CheckCircle,
  AlertTriangle,
  Info,
  Shield,
  Download,
  Upload,
  Settings
} from 'lucide-react';

interface DeploymentVector {
  id: string;
  name: string;
  description: string;
  icon: React.ReactNode;
  difficulty: 'easy' | 'medium' | 'advanced';
  timeEstimate: string;
  requirements: string[];
  advantages: string[];
  suitable_for: string[];
  cultural_alignment: string;
  khepra_features: string[];
}

const deploymentVectors: DeploymentVector[] = [
  {
    id: 'web_agent',
    name: 'Web-Based Agent Deployment',
    description: 'Browser-based installer with KHEPRA symbolic handshakes',
    icon: <Globe className="h-5 w-5" />,
    difficulty: 'easy',
    timeEstimate: '5-10 minutes',
    requirements: ['Modern web browser', 'Administrative access', 'Internet connection'],
    advantages: ['No infrastructure changes', 'Immediate deployment', 'Easy rollback'],
    suitable_for: ['Development environments', 'Small teams', 'Quick prototyping'],
    cultural_alignment: 'Sankofa - Learning and adaptation',
    khepra_features: ['Adinkra-encoded authentication', 'Cultural threat detection', 'Basic DAG consensus']
  },
  {
    id: 'cloud_native',
    name: 'Cloud-Native Orchestration',
    description: 'Kubernetes operators with auto-discovery and KHEPRA DAG management',
    icon: <Cloud className="h-5 w-5" />,
    difficulty: 'medium',
    timeEstimate: '15-30 minutes',
    requirements: ['Kubernetes cluster', 'Helm charts', 'Cloud provider access'],
    advantages: ['Scalable deployment', 'Auto-discovery', 'Container-native security'],
    suitable_for: ['Production environments', 'Microservices', 'Cloud-first architectures'],
    cultural_alignment: 'Nkyinkyim - Dynamic adaptation and flow',
    khepra_features: ['Full DAG orchestration', 'Container-level protection', 'Quantum-safe key exchange']
  },
  {
    id: 'api_first',
    name: 'API-First Integration',
    description: 'Single API call deployment with webhook-based configuration',
    icon: <Zap className="h-5 w-5" />,
    difficulty: 'easy',
    timeEstimate: '1-5 minutes',
    requirements: ['API access', 'Webhook endpoints', 'SaaS platform integration'],
    advantages: ['Instant deployment', 'Real-time updates', 'Platform agnostic'],
    suitable_for: ['SaaS platforms', 'CI/CD pipelines', 'Automated workflows'],
    cultural_alignment: 'Gye Nyame - Supreme coordination and unity',
    khepra_features: ['Trusted agent validation', 'OSINT integration', 'Real-time monitoring']
  },
  {
    id: 'airgapped',
    name: 'Airgapped Package Distribution',
    description: 'Self-contained bundles with offline KHEPRA protocol capabilities',
    icon: <HardDrive className="h-5 w-5" />,
    difficulty: 'advanced',
    timeEstimate: '30-60 minutes',
    requirements: ['Physical media access', 'Offline environment', 'Security clearance'],
    advantages: ['Maximum security', 'No internet required', 'Full control'],
    suitable_for: ['Classified environments', 'Critical infrastructure', 'High-security deployments'],
    cultural_alignment: 'Eban - Fortress-like protection and isolation',
    khepra_features: ['Offline verification', 'Adinkra integrity checking', 'Standalone operation']
  },
  {
    id: 'agent_propagation',
    name: 'Agent-to-Agent Propagation',
    description: 'AI agents deploy and configure other agents autonomously',
    icon: <Network className="h-5 w-5" />,
    difficulty: 'advanced',
    timeEstimate: '20-45 minutes',
    requirements: ['Existing KHEPRA agent', 'Network connectivity', 'Cultural taxonomy'],
    advantages: ['Autonomous deployment', 'Intelligent placement', 'Mesh networking'],
    suitable_for: ['Large deployments', 'Distributed systems', 'Smart infrastructure'],
    cultural_alignment: 'Adwo - Community wisdom and collective action',
    khepra_features: ['Cultural placement logic', 'Mesh consensus', 'Autonomous configuration']
  }
];

interface DeploymentVectorSelectorProps {
  data?: any;
  onDataChange?: (data: any) => void;
  isActive?: boolean;
}

export const DeploymentVectorSelector: React.FC<DeploymentVectorSelectorProps> = ({
  data,
  onDataChange,
  isActive
}) => {
  const [selectedVectors, setSelectedVectors] = useState<string[]>(data?.selected_vectors || []);
  const [selectedVector, setSelectedVector] = useState<string>(data?.primary_vector || deploymentVectors[0].id);

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'easy': return 'bg-green-500/10 text-green-400 border-green-500/20';
      case 'medium': return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
      case 'advanced': return 'bg-red-500/10 text-red-400 border-red-500/20';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const handleVectorSelection = (vectorId: string) => {
    setSelectedVector(vectorId);
    if (!selectedVectors.includes(vectorId)) {
      setSelectedVectors(prev => [...prev, vectorId]);
    }
  };

  const handleMultiSelect = (vectorId: string, checked: boolean) => {
    if (checked) {
      setSelectedVectors(prev => [...prev, vectorId]);
    } else {
      setSelectedVectors(prev => prev.filter(id => id !== vectorId));
      if (selectedVector === vectorId && selectedVectors.length > 1) {
        setSelectedVector(selectedVectors.find(id => id !== vectorId) || deploymentVectors[0].id);
      }
    }
  };

  useEffect(() => {
    onDataChange?.({
      primary_vector: selectedVector,
      selected_vectors: selectedVectors,
      deployment_plan: deploymentVectors.filter(v => selectedVectors.includes(v.id))
    });
  }, [selectedVector, selectedVectors, onDataChange]);

  const primaryVector = deploymentVectors.find(v => v.id === selectedVector);

  return (
    <div className="space-y-6">
      {/* Vector Selection Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {deploymentVectors.map((vector) => {
          const isSelected = selectedVector === vector.id;
          const isMultiSelected = selectedVectors.includes(vector.id);
          
          return (
            <Card
              key={vector.id}
              className={`cursor-pointer transition-all duration-200 ${
                isSelected 
                  ? 'border-primary bg-primary/5 shadow-[var(--shadow-primary)]' 
                  : 'border-border hover:border-primary/30'
              }`}
              onClick={() => handleVectorSelection(vector.id)}
            >
              <CardHeader className="pb-3">
                <div className="flex items-start justify-between">
                  <div className="flex items-center space-x-3">
                    <div className={`p-2 rounded-lg ${isSelected ? 'bg-primary/20' : 'bg-muted/20'}`}>
                      {vector.icon}
                    </div>
                    <div>
                      <CardTitle className="text-base">{vector.name}</CardTitle>
                      <p className="text-sm text-muted-foreground mt-1">
                        {vector.description}
                      </p>
                    </div>
                  </div>
                  <Checkbox
                    checked={isMultiSelected}
                    onCheckedChange={(checked) => handleMultiSelect(vector.id, !!checked)}
                    onClick={(e) => e.stopPropagation()}
                  />
                </div>
              </CardHeader>
              
              <CardContent className="pt-0 space-y-3">
                <div className="flex items-center justify-between">
                  <Badge variant="outline" className={getDifficultyColor(vector.difficulty)}>
                    {vector.difficulty}
                  </Badge>
                  <span className="text-sm text-muted-foreground">
                    ⏱ {vector.timeEstimate}
                  </span>
                </div>

                <div className="space-y-2">
                  <div className="text-xs text-purple-400">
                    🔮 {vector.cultural_alignment}
                  </div>
                  
                  <div className="text-xs">
                    <span className="text-muted-foreground">Best for: </span>
                    {vector.suitable_for.join(', ')}
                  </div>
                </div>

                {isSelected && (
                  <div className="mt-3 p-3 bg-muted/20 rounded-lg">
                    <div className="text-xs space-y-1">
                      <div className="font-medium text-primary">KHEPRA Features:</div>
                      {vector.khepra_features.map((feature, index) => (
                        <div key={index} className="flex items-center space-x-1">
                          <CheckCircle className="h-3 w-3 text-green-400" />
                          <span>{feature}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Detailed View of Primary Selection */}
      {primaryVector && (
        <Card className="border-primary/20 bg-primary/5">
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Shield className="h-5 w-5" />
              <span>Primary Deployment Vector: {primaryVector.name}</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Requirements */}
              <div>
                <h4 className="font-medium mb-2 flex items-center space-x-2">
                  <AlertTriangle className="h-4 w-4 text-yellow-400" />
                  <span>Requirements</span>
                </h4>
                <ul className="space-y-1 text-sm">
                  {primaryVector.requirements.map((req, index) => (
                    <li key={index} className="flex items-center space-x-2">
                      <CheckCircle className="h-3 w-3 text-green-400" />
                      <span>{req}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Advantages */}
              <div>
                <h4 className="font-medium mb-2 flex items-center space-x-2">
                  <Info className="h-4 w-4 text-blue-400" />
                  <span>Advantages</span>
                </h4>
                <ul className="space-y-1 text-sm">
                  {primaryVector.advantages.map((advantage, index) => (
                    <li key={index} className="flex items-center space-x-2">
                      <CheckCircle className="h-3 w-3 text-green-400" />
                      <span>{advantage}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            {/* Multi-Vector Deployment Summary */}
            {selectedVectors.length > 1 && (
              <div className="mt-4 p-4 bg-card rounded-lg border border-border">
                <h4 className="font-medium mb-2">Multi-Vector Deployment Plan</h4>
                <p className="text-sm text-muted-foreground mb-3">
                  You have selected {selectedVectors.length} deployment vectors. 
                  This will create a robust, multi-layered KHEPRA deployment.
                </p>
                <div className="flex flex-wrap gap-2">
                  {selectedVectors.map(vectorId => {
                    const vector = deploymentVectors.find(v => v.id === vectorId);
                    return vector ? (
                      <Badge key={vectorId} variant="outline" className="text-xs">
                        {vector.name.split(' ')[0]}
                      </Badge>
                    ) : null;
                  })}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Action Summary */}
      <Card className="border-border">
        <CardContent className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="font-medium">Ready to Deploy</div>
              <div className="text-sm text-muted-foreground">
                {selectedVectors.length} vector{selectedVectors.length !== 1 ? 's' : ''} selected
                {primaryVector && ` • Primary: ${primaryVector.name}`}
              </div>
            </div>
            <div className="flex space-x-2">
              <Button variant="outline" size="sm">
                <Download className="h-4 w-4 mr-2" />
                Export Config
              </Button>
              <Button variant="outline" size="sm">
                <Settings className="h-4 w-4 mr-2" />
                Advanced Settings
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};