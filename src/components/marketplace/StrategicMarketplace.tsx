import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Search, 
  Star, 
  Download, 
  Shield, 
  Database, 
  Cloud, 
  Zap,
  CheckCircle,
  ExternalLink,
  Filter,
  Grid,
  Monitor,
  UserCheck,
  FileCheck
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface StrategicIntegration {
  id: string;
  name: string;
  vendor: string;
  description: string;
  category: 'DOD_TACTICAL' | 'INDUSTRIAL_OT' | 'AI_SECURITY' | 'AIR_GAPPED' | 'COMPLIANCE' | 'CLOUD';
  rating: number;
  deployments: number;
  clearanceLevel: 'UNCLASSIFIED' | 'CONFIDENTIAL' | 'SECRET' | 'TOP_SECRET';
  status: 'approved' | 'deployed' | 'testing';
  tags: string[];
  icon: React.ReactNode;
  capabilities: string[];
  supportLevel: 'dod_contractor' | 'prime_contractor' | 'government';
  compliance: string[];
  targetEnvironment: string[];
}

const strategicIntegrations: StrategicIntegration[] = [
  {
    id: 'disa-email',
    name: 'DoD Enterprise Email (DISA)',
    vendor: 'Defense Information Systems Agency',
    description: 'Enterprise email security integration for DoD contractors and defense operations.',
    category: 'DOD_TACTICAL',
    rating: 4.9,
    deployments: 145,
    clearanceLevel: 'SECRET',
    status: 'approved',
    tags: ['DISA', 'Email Security', 'DoD Enterprise'],
    icon: <Shield className="h-6 w-6" />,
    capabilities: ['Email threat detection', 'Phishing intelligence', 'Malware detection', 'DoD compliance'],
    supportLevel: 'government',
    compliance: ['FISMA', 'FedRAMP', 'DISA STIG', 'NIST 800-53'],
    targetEnvironment: ['DoD Networks', 'Contractor Systems', 'Defense Enclaves']
  },
  {
    id: 'dcgs-a',
    name: 'DCGS-A (Distributed Common Ground System)',
    vendor: 'US Army',
    description: 'Army distributed intelligence processing and dissemination system integration.',
    category: 'DOD_TACTICAL',
    rating: 4.8,
    deployments: 89,
    clearanceLevel: 'TOP_SECRET',
    status: 'approved',
    tags: ['Army', 'Intelligence', 'Battlefield'],
    icon: <Database className="h-6 w-6" />,
    capabilities: ['Intelligence reports', 'Geospatial data', 'Threat assessments', 'Battlefield intelligence'],
    supportLevel: 'government',
    compliance: ['TOP SECRET', 'NOFORN', 'DCGS STD'],
    targetEnvironment: ['Tactical Operations Centers', 'Forward Operating Bases', 'Intelligence Centers']
  },
  {
    id: 'schneider-ecostruxure',
    name: 'Schneider Electric EcoStruxure',
    vendor: 'Schneider Electric',
    description: 'Industrial automation and energy management platform security for critical infrastructure.',
    category: 'INDUSTRIAL_OT',
    rating: 4.7,
    deployments: 312,
    clearanceLevel: 'UNCLASSIFIED',
    status: 'approved',
    tags: ['SCADA', 'Energy Management', 'Industrial'],
    icon: <Zap className="h-6 w-6" />,
    capabilities: ['SCADA alarms', 'HMI events', 'PLC diagnostics', 'Energy data', 'Industrial protocols'],
    supportLevel: 'prime_contractor',
    compliance: ['IEC 62443', 'NERC CIP', 'NIST CSF'],
    targetEnvironment: ['Power Plants', 'Manufacturing', 'Critical Infrastructure']
  },
  {
    id: 'nvidia-morpheus',
    name: 'NVIDIA Morpheus AI Security',
    vendor: 'NVIDIA',
    description: 'AI-powered cybersecurity framework for enterprise AI workloads and inference engines.',
    category: 'AI_SECURITY',
    rating: 4.6,
    deployments: 167,
    clearanceLevel: 'CONFIDENTIAL',
    status: 'testing',
    tags: ['AI/ML', 'GPU Computing', 'Enterprise'],
    icon: <Monitor className="h-6 w-6" />,
    capabilities: ['AI model threats', 'Inference anomalies', 'Data poisoning detection', 'Adversarial attacks'],
    supportLevel: 'prime_contractor',
    compliance: ['MLOps Security', 'NIST AI RMF', 'ISO 23053'],
    targetEnvironment: ['Data Centers', 'AI/ML Pipelines', 'Edge Computing']
  },
  {
    id: 'raytheon-disconnected',
    name: 'Disconnected Operations Security Monitor',
    vendor: 'Raytheon',
    description: 'Security monitoring for air-gapped and tactical edge systems in isolated environments.',
    category: 'AIR_GAPPED',
    rating: 4.9,
    deployments: 56,
    clearanceLevel: 'TOP_SECRET',
    status: 'approved',
    tags: ['Air-gapped', 'Tactical Edge', 'Isolated'],
    icon: <UserCheck className="h-6 w-6" />,
    capabilities: ['Offline threats', 'USB events', 'Local anomalies', 'Device integrity'],
    supportLevel: 'dod_contractor',
    compliance: ['TEMPEST', 'Cross Domain', 'COMSEC', 'TRANSEC'],
    targetEnvironment: ['Air-gapped Systems', 'Tactical Edge', 'Isolated Networks']
  }
];

const StrategicMarketplace: React.FC = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('All');
  const [selectedClearance, setSelectedClearance] = useState<string>('All');
  const { toast } = useToast();

  // Strategic categories aligned with our target niches
  const categories = [
    { name: 'All', icon: Grid, description: 'View all strategic integrations' },
    { name: 'DOD_TACTICAL', icon: Shield, description: 'DoD Tactical & Strategic Systems' },
    { name: 'INDUSTRIAL_OT', icon: Zap, description: 'Critical Infrastructure OT/ICS/SCADA' },
    { name: 'AI_SECURITY', icon: Monitor, description: 'AI Agents & Container Security' },
    { name: 'AIR_GAPPED', icon: UserCheck, description: 'Air-gapped & SCIF Systems' },
    { name: 'COMPLIANCE', icon: FileCheck, description: 'Compliance and Audit Tools' },
    { name: 'CLOUD', icon: Cloud, description: 'Cloud Security Platforms' }
  ];

  const clearanceLevels = ['All', 'UNCLASSIFIED', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'];

  const filteredIntegrations = strategicIntegrations.filter(integration => {
    const matchesSearch = integration.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         integration.vendor.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         integration.tags.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase()));
    const matchesCategory = selectedCategory === 'All' || integration.category === selectedCategory;
    const matchesClearance = selectedClearance === 'All' || integration.clearanceLevel === selectedClearance;
    
    return matchesSearch && matchesCategory && matchesClearance;
  });

  const handleDeploy = (integrationId: string) => {
    console.log('🚀 Deploying strategic integration:', integrationId);
    toast({
      title: "Deploying Integration",
      description: "Initiating secure deployment process... This may require approval workflow.",
    });
  };

  const getClearanceColor = (clearance: string) => {
    switch (clearance) {
      case 'UNCLASSIFIED': return 'default';
      case 'CONFIDENTIAL': return 'secondary';
      case 'SECRET': return 'destructive';
      case 'TOP_SECRET': return 'destructive';
      default: return 'outline';
    }
  };

  const getCategoryIcon = (category: string) => {
    const categoryData = categories.find(cat => cat.name === category);
    return categoryData ? <categoryData.icon className="h-4 w-4" /> : <Grid className="h-4 w-4" />;
  };

  return (
    <div className="space-y-6">
      {/* Strategic Header */}
      <div className="mb-8">
        <h2 className="text-2xl font-bold text-foreground mb-4">Strategic Integration Marketplace</h2>
        <p className="text-muted-foreground mb-4">
          Connect IMOHTEP with systems designed for DoD contractors, critical infrastructure operators, and enterprise AI deployments.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 p-4 bg-card/50 rounded-lg border border-primary/20">
          <div className="text-center">
            <Shield className="h-8 w-8 text-primary mx-auto mb-2" />
            <h3 className="font-semibold text-foreground">DoD Contractors</h3>
            <p className="text-sm text-muted-foreground">Tactical systems, classified networks, defense operations</p>
          </div>
          <div className="text-center">
            <Zap className="h-8 w-8 text-accent mx-auto mb-2" />
            <h3 className="font-semibold text-foreground">Critical Infrastructure</h3>
            <p className="text-sm text-muted-foreground">SCADA/ICS/IoT, power grids, industrial controls</p>
          </div>
          <div className="text-center">
            <Monitor className="h-8 w-8 text-success mx-auto mb-2" />
            <h3 className="font-semibold text-foreground">Enterprise AI</h3>
            <p className="text-sm text-muted-foreground">AI agents, containers, data lakes, robotics</p>
          </div>
        </div>
      </div>

      {/* Search and Filters */}
      <div className="flex flex-col lg:flex-row gap-4">
        <div className="flex-1">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground h-4 w-4" />
            <Input
              placeholder="Search strategic integrations..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10"
            />
          </div>
        </div>
        <div className="flex gap-2">
          <select
            value={selectedClearance}
            onChange={(e) => setSelectedClearance(e.target.value)}
            className="px-3 py-2 border border-border rounded-md bg-background text-foreground"
          >
            {clearanceLevels.map(level => (
              <option key={level} value={level}>
                {level === 'All' ? 'All Clearance Levels' : level}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Category Tabs */}
      <Tabs value={selectedCategory} onValueChange={setSelectedCategory}>
        <TabsList className="grid w-full grid-cols-3 lg:grid-cols-7">
          {categories.map((category) => (
            <TabsTrigger key={category.name} value={category.name} className="flex items-center gap-1">
              <category.icon className="h-3 w-3" />
              <span className="hidden sm:inline">{category.name.replaceAll('_', ' ')}</span>
            </TabsTrigger>
          ))}
        </TabsList>

        {categories.map((category) => (
          <TabsContent key={category.name} value={category.name} className="space-y-4">
            <div className="text-sm text-muted-foreground">
              {category.description}
            </div>
          </TabsContent>
        ))}
      </Tabs>

      {/* Integration Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredIntegrations.map((integration) => (
          <Card key={integration.id} className="card-cyber">
            <CardHeader>
              <div className="flex items-start justify-between">
                <div className="flex items-center space-x-3">
                  {integration.icon}
                  <div>
                    <CardTitle className="text-lg text-foreground">{integration.name}</CardTitle>
                    <p className="text-sm text-muted-foreground">{integration.vendor}</p>
                  </div>
                </div>
                <div className="flex items-center space-x-1 text-sm text-warning">
                  <Star className="h-4 w-4 fill-current" />
                  <span>{integration.rating}</span>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-muted-foreground">{integration.description}</p>
              
              <div className="flex flex-wrap gap-2">
                <Badge variant="outline">{getCategoryIcon(integration.category)} {integration.category.replaceAll('_', ' ')}</Badge>
                <Badge className={getClearanceColor(integration.clearanceLevel)}>
                  {integration.clearanceLevel}
                </Badge>
              </div>

              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Deployments:</span>
                  <span className="text-foreground">{integration.deployments}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Support Level:</span>
                  <span className="text-foreground">{integration.supportLevel.replaceAll('_', ' ')}</span>
                </div>
              </div>

              <div className="space-y-2">
                <p className="text-sm font-medium text-foreground">Key Capabilities:</p>
                <div className="flex flex-wrap gap-1">
                  {integration.capabilities.slice(0, 3).map((capability, index) => (
                    <Badge key={index} variant="secondary" className="text-xs">
                      {capability}
                    </Badge>
                  ))}
                  {integration.capabilities.length > 3 && (
                    <Badge variant="secondary" className="text-xs">
                      +{integration.capabilities.length - 3} more
                    </Badge>
                  )}
                </div>
              </div>

              <div className="flex space-x-2">
                <Button 
                  onClick={() => handleDeploy(integration.id)}
                  className="flex-1"
                  variant={integration.status === 'approved' ? 'default' : 'outline'}
                >
                  {integration.status === 'deployed' ? 'Configured' : 
                   integration.status === 'testing' ? 'Deploy (Testing)' : 'Deploy'}
                </Button>
                <Button variant="outline" size="sm">
                  <ExternalLink className="h-4 w-4" />
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {filteredIntegrations.length === 0 && (
        <div className="text-center py-12">
          <Filter className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-foreground mb-2">No integrations found</h3>
          <p className="text-muted-foreground">Try adjusting your search criteria or clearance level filters.</p>
        </div>
      )}
    </div>
  );
};

export default StrategicMarketplace;