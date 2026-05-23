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
  Filter
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface Integration {
  id: string;
  name: string;
  vendor: string;
  description: string;
  category: 'security' | 'compliance' | 'infrastructure' | 'monitoring' | 'reporting';
  rating: number;
  downloads: number;
  price: 'free' | 'paid' | 'enterprise';
  status: 'available' | 'installed' | 'pending';
  tags: string[];
  icon: React.ReactNode;
  features: string[];
  supportLevel: 'community' | 'vendor' | 'premium';
  compatibility: string[];
}

const integrations: Integration[] = [
  {
    id: 'splunk-siem',
    name: 'Splunk SIEM Integration',
    vendor: 'Splunk Inc.',
    description: 'Connect with Splunk Enterprise Security for advanced threat detection and security analytics.',
    category: 'security',
    rating: 4.8,
    downloads: 1250,
    price: 'enterprise',
    status: 'available',
    tags: ['SIEM', 'Analytics', 'Enterprise'],
    icon: <Shield className="h-6 w-6" />,
    features: ['Real-time threat detection', 'Custom dashboards', 'Advanced analytics', 'Incident response'],
    supportLevel: 'vendor',
    compatibility: ['NIST SP 800-171', 'CMMC', 'SOC 2']
  },
  {
    id: 'aws-config',
    name: 'AWS Config Compliance',
    vendor: 'Amazon Web Services',
    description: 'Automated compliance monitoring and configuration management for AWS resources.',
    category: 'compliance',
    rating: 4.6,
    downloads: 2100,
    price: 'free',
    status: 'installed',
    tags: ['AWS', 'Cloud', 'Configuration'],
    icon: <Cloud className="h-6 w-6" />,
    features: ['Config drift detection', 'Compliance reporting', 'Automated remediation', 'Cost optimization'],
    supportLevel: 'vendor',
    compatibility: ['NIST SP 800-171', 'CMMC', 'FedRAMP']
  },
  {
    id: 'tenable-vuln',
    name: 'Tenable Vulnerability Management',
    vendor: 'Tenable Inc.',
    description: 'Comprehensive vulnerability assessment and management platform integration.',
    category: 'security',
    rating: 4.7,
    downloads: 890,
    price: 'paid',
    status: 'available',
    tags: ['Vulnerability', 'Scanning', 'Risk Assessment'],
    icon: <Shield className="h-6 w-6" />,
    features: ['Continuous scanning', 'Risk prioritization', 'Patch management', 'Compliance mapping'],
    supportLevel: 'vendor',
    compatibility: ['NIST SP 800-171', 'CMMC', 'PCI DSS']
  },
  {
    id: 'elastic-siem',
    name: 'Elastic Security',
    vendor: 'Elastic N.V.',
    description: 'Open-source SIEM and security analytics platform with machine learning capabilities.',
    category: 'security',
    rating: 4.5,
    downloads: 1680,
    price: 'free',
    status: 'available',
    tags: ['Open Source', 'ML', 'Analytics'],
    icon: <Database className="h-6 w-6" />,
    features: ['Machine learning detection', 'Timeline analysis', 'Case management', 'Threat hunting'],
    supportLevel: 'community',
    compatibility: ['NIST SP 800-171', 'MITRE ATT&CK']
  },
  {
    id: 'okta-identity',
    name: 'Okta Identity Management',
    vendor: 'Okta Inc.',
    description: 'Identity and access management integration for enhanced authentication and authorization.',
    category: 'security',
    rating: 4.9,
    downloads: 3200,
    price: 'paid',
    status: 'available',
    tags: ['Identity', 'SSO', 'MFA'],
    icon: <Shield className="h-6 w-6" />,
    features: ['Single sign-on', 'Multi-factor auth', 'User provisioning', 'Access policies'],
    supportLevel: 'vendor',
    compatibility: ['NIST SP 800-171', 'CMMC', 'SOC 2', 'FedRAMP']
  },
  {
    id: 'servicenow-itsm',
    name: 'ServiceNow ITSM',
    vendor: 'ServiceNow Inc.',
    description: 'IT service management and workflow automation for compliance and incident response.',
    category: 'infrastructure',
    rating: 4.4,
    downloads: 750,
    price: 'enterprise',
    status: 'pending',
    tags: ['ITSM', 'Workflow', 'Automation'],
    icon: <Zap className="h-6 w-6" />,
    features: ['Incident management', 'Change control', 'Asset tracking', 'Compliance workflows'],
    supportLevel: 'vendor',
    compatibility: ['NIST SP 800-171', 'CMMC', 'ITIL']
  }
];

export const IntegrationMarketplace = () => {
  const { toast } = useToast();
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [selectedPrice, setSelectedPrice] = useState<string>('all');

  const filteredIntegrations = integrations.filter(integration => {
    const matchesSearch = integration.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         integration.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         integration.tags.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase()));
    
    const matchesCategory = selectedCategory === 'all' || integration.category === selectedCategory;
    const matchesPrice = selectedPrice === 'all' || integration.price === selectedPrice;
    
    console.log('🔍 Filtering integrations:', { 
      searchTerm, 
      selectedCategory, 
      selectedPrice, 
      totalFiltered: integrations.filter(i => matchesSearch && matchesCategory && matchesPrice).length 
    });
    
    return matchesSearch && matchesCategory && matchesPrice;
  });

  const handleInstall = (integrationId: string) => {
    console.log('📦 Installing integration:', integrationId);
    toast({
      title: "Installing Integration",
      description: "Setting up the integration... This may take a few minutes.",
    });

    // Simulate installation
    setTimeout(() => {
      console.log('✅ Integration installed successfully:', integrationId);
      toast({
        title: "Integration Installed",
        description: "Successfully installed and configured the integration.",
      });
    }, 2000);
  };

  const handleConfigure = (integrationId: string) => {
    console.log('⚙️ Configuring integration:', integrationId);
    toast({
      title: "Opening Configuration",
      description: "Redirecting to integration configuration panel...",
    });
  };

  const getPriceColor = (price: string) => {
    switch (price) {
      case 'free': return 'default';
      case 'paid': return 'secondary';
      case 'enterprise': return 'destructive';
      default: return 'outline';
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'security': return <Shield className="h-4 w-4" />;
      case 'compliance': return <CheckCircle className="h-4 w-4" />;
      case 'infrastructure': return <Database className="h-4 w-4" />;
      case 'monitoring': return <Zap className="h-4 w-4" />;
      case 'reporting': return <ExternalLink className="h-4 w-4" />;
      default: return <Database className="h-4 w-4" />;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold">Integration Marketplace</h2>
        <Badge variant="outline" className="px-3 py-1">
          {integrations.filter(i => i.status === 'installed').length} Installed
        </Badge>
      </div>

      {/* Search and Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search integrations..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-10"
          />
        </div>
        <div className="flex gap-2">
          <select 
            value={selectedCategory} 
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="px-3 py-2 border rounded-md bg-background"
          >
            <option value="all">All Categories</option>
            <option value="security">Security</option>
            <option value="compliance">Compliance</option>
            <option value="infrastructure">Infrastructure</option>
            <option value="monitoring">Monitoring</option>
            <option value="reporting">Reporting</option>
          </select>
          <select 
            value={selectedPrice} 
            onChange={(e) => setSelectedPrice(e.target.value)}
            className="px-3 py-2 border rounded-md bg-background"
          >
            <option value="all">All Pricing</option>
            <option value="free">Free</option>
            <option value="paid">Paid</option>
            <option value="enterprise">Enterprise</option>
          </select>
        </div>
      </div>

      {/* Tabs for different views */}
      <Tabs defaultValue="browse" className="w-full">
        <TabsList>
          <TabsTrigger value="browse">Browse All</TabsTrigger>
          <TabsTrigger value="installed">Installed</TabsTrigger>
          <TabsTrigger value="popular">Popular</TabsTrigger>
          <TabsTrigger value="recommended">Recommended</TabsTrigger>
        </TabsList>

        <TabsContent value="browse" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {filteredIntegrations.map((integration) => (
              <Card key={integration.id} className="relative">
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      {integration.icon}
                      <div>
                        <CardTitle className="text-lg">{integration.name}</CardTitle>
                        <p className="text-sm text-muted-foreground">{integration.vendor}</p>
                      </div>
                    </div>
                    <Badge variant={getPriceColor(integration.price)} className="capitalize">
                      {integration.price}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p className="text-sm text-muted-foreground">
                    {integration.description}
                  </p>

                  <div className="flex items-center gap-4 text-sm">
                    <div className="flex items-center gap-1">
                      <Star className="h-4 w-4 fill-yellow-400 text-yellow-400" />
                      <span>{integration.rating}</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <Download className="h-4 w-4 text-muted-foreground" />
                      <span>{integration.downloads.toLocaleString()}</span>
                    </div>
                    <div className="flex items-center gap-1">
                      {getCategoryIcon(integration.category)}
                      <span className="capitalize">{integration.category}</span>
                    </div>
                  </div>

                  <div className="flex flex-wrap gap-1">
                    {integration.tags.slice(0, 3).map((tag) => (
                      <Badge key={tag} variant="outline" className="text-xs">
                        {tag}
                      </Badge>
                    ))}
                  </div>

                  <div className="space-y-2">
                    <p className="text-sm font-medium">Key Features:</p>
                    <ul className="text-xs text-muted-foreground space-y-1">
                      {integration.features.slice(0, 3).map((feature) => (
                        <li key={feature} className="flex items-center gap-2">
                          <CheckCircle className="h-3 w-3 text-green-500" />
                          {feature}
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="flex gap-2 pt-2">
                    {integration.status === 'installed' ? (
                      <Button 
                        onClick={() => handleConfigure(integration.id)}
                        variant="outline" 
                        className="flex-1"
                      >
                        Configure
                      </Button>
                    ) : integration.status === 'pending' ? (
                      <Button disabled className="flex-1">
                        Installing...
                      </Button>
                    ) : (
                      <Button 
                        onClick={() => handleInstall(integration.id)}
                        className="flex-1"
                      >
                        Install
                      </Button>
                    )}
                    <Button variant="outline" size="sm">
                      <ExternalLink className="h-4 w-4" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="installed">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {integrations
              .filter(i => i.status === 'installed')
              .map((integration) => (
                <Card key={integration.id}>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        {integration.icon}
                        <div>
                          <CardTitle className="text-lg">{integration.name}</CardTitle>
                          <p className="text-sm text-muted-foreground">Active</p>
                        </div>
                      </div>
                      <CheckCircle className="h-5 w-5 text-green-500" />
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="flex gap-2">
                      <Button onClick={() => handleConfigure(integration.id)} className="flex-1">
                        Configure
                      </Button>
                      <Button variant="outline" className="flex-1">
                        Logs
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ))}
          </div>
        </TabsContent>

        <TabsContent value="popular">
          <div className="space-y-4">
            <p className="text-muted-foreground">Most downloaded integrations this month</p>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {integrations
                .sort((a, b) => b.downloads - a.downloads)
                .slice(0, 6)
                .map((integration) => (
                  <Card key={integration.id}>
                    <CardHeader>
                      <div className="flex items-center gap-3">
                        {integration.icon}
                        <div>
                          <CardTitle className="text-lg">{integration.name}</CardTitle>
                          <p className="text-sm text-muted-foreground">
                            {integration.downloads.toLocaleString()} downloads
                          </p>
                        </div>
                      </div>
                    </CardHeader>
                  </Card>
                ))}
            </div>
          </div>
        </TabsContent>

        <TabsContent value="recommended">
          <div className="space-y-4">
            <p className="text-muted-foreground">Recommended for DoD contractors and CMMC compliance</p>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {integrations
                .filter(i => i.compatibility.includes('CMMC'))
                .map((integration) => (
                  <Card key={integration.id}>
                    <CardHeader>
                      <div className="flex items-center gap-3">
                        {integration.icon}
                        <div>
                          <CardTitle className="text-lg">{integration.name}</CardTitle>
                          <Badge variant="default" className="mt-1">
                            CMMC Ready
                          </Badge>
                        </div>
                      </div>
                    </CardHeader>
                  </Card>
                ))}
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};