
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { Badge } from '@/components/ui/badge';
import { 
  Cloud, 
  Server, 
  Container, 
  Cpu, 
  Network, 
  Zap,
  Wind,
  Battery,
  Shield,
  Globe,
  Database,
  Router,
  Smartphone,
  MonitorSpeaker,
  Gauge
} from 'lucide-react';

export interface WizardData {
  environments: string[];
  useCases: string[];
  connectionMethods: Record<string, string>;
  connectionDetails: Record<string, any>;
  scanningConfig: {
    schedule: string;
    stigRuleSets: string[];
    frameworks: string[];
    notifications: boolean;
  };
}

interface EnvironmentOption {
  id: string;
  title: string;
  description: string;
  icon: React.ElementType;
  category: string;
  stigComplexity: 'Low' | 'Medium' | 'High';
  examples: string[];
}

interface UseCase {
  id: string;
  title: string;
  description: string;
  icon: React.ElementType;
}

const USE_CASES: UseCase[] = [
  {
    id: 'stig-compliance',
    title: 'STIG Compliance Monitoring',
    description: 'Continuous monitoring for STIG compliance across all connected systems',
    icon: Shield
  },
  {
    id: 'vulnerability-scanning', 
    title: 'Vulnerability Scanning',
    description: 'Regular vulnerability assessments and security scans',
    icon: Gauge
  },
  {
    id: 'asset-discovery',
    title: 'Asset Discovery & Inventory',
    description: 'Automated discovery and inventory of infrastructure assets',
    icon: Network
  }
];

const ENVIRONMENT_OPTIONS: EnvironmentOption[] = [
  // Cloud Platforms
  {
    id: 'cloud-aws',
    title: 'AWS Cloud Infrastructure',
    description: 'Amazon Web Services EC2, RDS, Lambda, and other services',
    icon: Cloud,
    category: 'Cloud Platforms',
    stigComplexity: 'High',
    examples: ['EC2 Instances', 'RDS Databases', 'Lambda Functions', 'S3 Buckets']
  },
  {
    id: 'cloud-azure',
    title: 'Microsoft Azure',
    description: 'Azure Virtual Machines, SQL Database, and Azure services',
    icon: Cloud,
    category: 'Cloud Platforms',
    stigComplexity: 'High',
    examples: ['Virtual Machines', 'SQL Database', 'App Services', 'Storage Accounts']
  },
  {
    id: 'cloud-gcp',
    title: 'Google Cloud Platform',
    description: 'GCP Compute Engine, Cloud SQL, and other GCP services',
    icon: Cloud,
    category: 'Cloud Platforms',
    stigComplexity: 'High',
    examples: ['Compute Engine', 'Cloud SQL', 'Kubernetes Engine', 'Cloud Storage']
  },

  // On-Premises Servers
  {
    id: 'servers-windows',
    title: 'Windows Servers',
    description: 'Windows Server 2019/2022, Active Directory, IIS',
    icon: Server,
    category: 'On-Premises Servers',
    stigComplexity: 'Medium',
    examples: ['Windows Server 2022', 'Active Directory', 'IIS Web Server', 'SQL Server']
  },
  {
    id: 'servers-linux',
    title: 'Linux Servers',
    description: 'RHEL, Ubuntu, CentOS, and other Linux distributions',
    icon: Server,
    category: 'On-Premises Servers',
    stigComplexity: 'Medium',
    examples: ['RHEL 8/9', 'Ubuntu 20.04/22.04', 'CentOS', 'Apache/Nginx']
  },
  {
    id: 'servers-database',
    title: 'Database Servers',
    description: 'Oracle, MySQL, PostgreSQL, and other database systems',
    icon: Database,
    category: 'On-Premises Servers',
    stigComplexity: 'High',
    examples: ['Oracle Database', 'MySQL', 'PostgreSQL', 'MongoDB']
  },

  // Web Services & APIs
  {
    id: 'web-api-rest',
    title: 'REST Web APIs',
    description: 'RESTful web services and API endpoints',
    icon: Globe,
    category: 'Web Services & APIs',
    stigComplexity: 'Medium',
    examples: ['REST APIs', 'GraphQL Endpoints', 'Microservices', 'API Gateways']
  },
  {
    id: 'web-applications',
    title: 'Web Applications',
    description: 'Web-based applications and services',
    icon: Globe,
    category: 'Web Services & APIs',
    stigComplexity: 'Medium',
    examples: ['Web Apps', 'SPA Applications', 'Web Services', 'Portal Systems']
  },

  // Containerized Workloads
  {
    id: 'containers-docker',
    title: 'Docker Containers',
    description: 'Docker containers and Docker Swarm clusters',
    icon: Container,
    category: 'Containerized Workloads',
    stigComplexity: 'Medium',
    examples: ['Docker Engine', 'Container Images', 'Docker Compose', 'Swarm Mode']
  },
  {
    id: 'containers-k8s',
    title: 'Kubernetes Clusters',
    description: 'Kubernetes clusters, pods, and container orchestration',
    icon: Container,
    category: 'Containerized Workloads',
    stigComplexity: 'High',
    examples: ['K8s Clusters', 'Pods & Services', 'Ingress Controllers', 'Helm Charts']
  },

  // Industrial Control Systems
  {
    id: 'industrial-plc',
    title: 'PLCs and RTUs',
    description: 'Programmable Logic Controllers and Remote Terminal Units',
    icon: Cpu,
    category: 'Industrial Control Systems',
    stigComplexity: 'High',
    examples: ['Siemens PLCs', 'Allen-Bradley', 'Schneider RTUs', 'Modbus Devices']
  },
  {
    id: 'industrial-scada',
    title: 'SCADA Systems',
    description: 'Supervisory Control and Data Acquisition systems',
    icon: MonitorSpeaker,
    category: 'Industrial Control Systems',
    stigComplexity: 'High',
    examples: ['HMI Workstations', 'SCADA Servers', 'Historian Databases', 'OPC Servers']
  },
  {
    id: 'industrial-hmi',
    title: 'HMI Systems',
    description: 'Human Machine Interface systems and operator workstations',
    icon: MonitorSpeaker,
    category: 'Industrial Control Systems',
    stigComplexity: 'High',
    examples: ['Operator Workstations', 'Touch Panels', 'Control Displays', 'SCADA HMIs']
  },

  // Energy Generation & Storage
  {
    id: 'energy-solar',
    title: 'Solar Power Systems',
    description: 'Solar panels, inverters, and monitoring systems',
    icon: Zap,
    category: 'Energy Generation & Storage',
    stigComplexity: 'Medium',
    examples: ['Solar Inverters', 'Power Optimizers', 'Monitoring Systems', 'Grid Tie Systems']
  },
  {
    id: 'energy-wind',
    title: 'Wind Power Systems',
    description: 'Wind turbines and control systems',
    icon: Wind,
    category: 'Energy Generation & Storage',
    stigComplexity: 'Medium',
    examples: ['Wind Turbines', 'Turbine Controllers', 'SCADA Integration', 'Power Converters']
  },
  {
    id: 'energy-battery',
    title: 'Battery Storage Systems',
    description: 'Energy storage systems and battery management',
    icon: Battery,
    category: 'Energy Generation & Storage',
    stigComplexity: 'Medium',
    examples: ['Battery Management Systems', 'Energy Storage Controllers', 'Grid Integration', 'Safety Systems']
  },
  {
    id: 'energy-grid',
    title: 'Grid Infrastructure',
    description: 'Electrical grid systems and power distribution',
    icon: Gauge,
    category: 'Energy Generation & Storage',
    stigComplexity: 'High',
    examples: ['Grid Controllers', 'Distribution Systems', 'Smart Meters', 'Power Management']
  },

  // Network Infrastructure
  {
    id: 'network-routers',
    title: 'Routers & Switches',
    description: 'Network routers, switches, and routing equipment',
    icon: Router,
    category: 'Network Infrastructure',
    stigComplexity: 'Low',
    examples: ['Cisco Routers', 'Network Switches', 'Layer 3 Switches', 'Core Routers']
  },
  {
    id: 'network-security',
    title: 'Network Security Devices',
    description: 'Firewalls, IDS/IPS, and security appliances',
    icon: Shield,
    category: 'Network Infrastructure',
    stigComplexity: 'Medium',
    examples: ['Firewalls', 'IDS/IPS Systems', 'Security Appliances', 'VPN Gateways']
  },
  {
    id: 'network-wireless',
    title: 'Wireless Infrastructure',
    description: 'Wireless access points, controllers, and mobile networks',
    icon: Network,
    category: 'Network Infrastructure',
    stigComplexity: 'Low',
    examples: ['Wireless Access Points', 'WiFi Controllers', 'Mobile Networks', '5G Infrastructure']
  },

  // Mobile & IoT Devices
  {
    id: 'mobile-devices',
    title: 'Mobile Devices',
    description: 'Smartphones, tablets, and mobile endpoint devices',
    icon: Smartphone,
    category: 'Mobile & IoT Devices',
    stigComplexity: 'Medium',
    examples: ['Corporate Smartphones', 'Tablets', 'Mobile Workstations', 'Rugged Devices']
  },
  {
    id: 'iot-sensors',
    title: 'IoT Sensors & Devices',
    description: 'Internet of Things sensors and connected devices',
    icon: Cpu,
    category: 'Mobile & IoT Devices',
    stigComplexity: 'Medium',
    examples: ['Environmental Sensors', 'Smart Meters', 'Connected Devices', 'Edge Sensors']
  }
];

interface EnvironmentSelectionStepProps {
  data: WizardData;
  onUpdate: (updates: Partial<WizardData>) => void;
}

export const EnvironmentSelectionStep: React.FC<EnvironmentSelectionStepProps> = ({
  data,
  onUpdate
}) => {
  const handleEnvironmentToggle = (environmentId: string, checked: boolean) => {
    const updatedEnvironments = checked
      ? [...data.environments, environmentId]
      : data.environments.filter(id => id !== environmentId);
    
    onUpdate({ environments: updatedEnvironments });
  };

  const handleUseCaseToggle = (useCaseId: string, checked: boolean) => {
    const updatedUseCases = checked
      ? [...(data.useCases || []), useCaseId]
      : (data.useCases || []).filter(id => id !== useCaseId);
    
    onUpdate({ useCases: updatedUseCases });
  };

  const groupedOptions = ENVIRONMENT_OPTIONS.reduce((groups, option) => {
    if (!groups[option.category]) {
      groups[option.category] = [];
    }
    groups[option.category].push(option);
    return groups;
  }, {} as Record<string, EnvironmentOption[]>);

  const getComplexityColor = (complexity: string) => {
    switch (complexity) {
      case 'Low': return 'bg-green-500/10 text-green-600 border-green-500/20';
      case 'Medium': return 'bg-yellow-500/10 text-yellow-600 border-yellow-500/20';
      case 'High': return 'bg-red-500/10 text-red-600 border-red-500/20';
      default: return 'bg-gray-500/10 text-gray-600 border-gray-500/20';
    }
  };

  return (
    <div className="space-y-6">
      <div className="text-center space-y-2">
        <h3 className="text-lg font-semibold">Select Your Infrastructure Environment Types</h3>
        <p className="text-muted-foreground">
          Choose the types of systems you want to include in your STIG compliance monitoring.
          You can select multiple environment types.
        </p>
      </div>

      {/* Use Cases Selection */}
      <div className="space-y-4">
        <h4 className="font-medium text-sm uppercase tracking-wide text-muted-foreground">
          Use Cases
        </h4>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {USE_CASES.map((useCase) => {
            const isSelected = (data.useCases || []).includes(useCase.id);
            return (
              <Card 
                key={useCase.id}
                className={`cursor-pointer transition-all hover:shadow-md ${
                  isSelected ? 'ring-2 ring-primary border-primary bg-primary/5' : ''
                }`}
                onClick={() => handleUseCaseToggle(useCase.id, !isSelected)}
              >
                <CardHeader className="pb-2">
                  <div className="flex items-center space-x-3">
                    <useCase.icon className="h-5 w-5 text-primary" />
                    <Checkbox 
                      checked={isSelected}
                      onChange={() => {}}
                    />
                  </div>
                  <CardTitle className="text-sm">{useCase.title}</CardTitle>
                </CardHeader>
                <CardContent>
                  <CardDescription className="text-xs">
                    {useCase.description}
                  </CardDescription>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </div>

      {/* Environment Selection */}
      <div className="space-y-6">
        {Object.entries(groupedOptions).map(([category, options]) => (
          <div key={category} className="space-y-3">
            <h4 className="font-medium text-sm uppercase tracking-wide text-muted-foreground">
              {category}
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {options.map((option) => {
                const isSelected = data.environments.includes(option.id);
                return (
                  <Card 
                    key={option.id}
                    className={`cursor-pointer transition-all hover:shadow-md ${
                      isSelected ? 'ring-2 ring-primary border-primary' : ''
                    }`}
                    onClick={() => handleEnvironmentToggle(option.id, !isSelected)}
                  >
                    <CardHeader className="pb-2">
                      <div className="flex items-start justify-between">
                        <div className="flex items-center space-x-3">
                          <option.icon className="h-5 w-5 text-primary" />
                          <Checkbox 
                            checked={isSelected}
                            onChange={() => {}}
                          />
                        </div>
                        <Badge 
                          variant="outline"
                          className={`text-xs ${getComplexityColor(option.stigComplexity)}`}
                        >
                          {option.stigComplexity} STIG
                        </Badge>
                      </div>
                      <CardTitle className="text-sm">{option.title}</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <CardDescription className="text-xs mb-3">
                        {option.description}
                      </CardDescription>
                      <div className="space-y-1">
                        <p className="text-xs font-medium text-muted-foreground">Examples:</p>
                        <div className="flex flex-wrap gap-1">
                          {option.examples.slice(0, 3).map((example, index) => (
                            <Badge key={index} variant="secondary" className="text-xs">
                              {example}
                            </Badge>
                          ))}
                          {option.examples.length > 3 && (
                            <Badge variant="secondary" className="text-xs">
                              +{option.examples.length - 3} more
                            </Badge>
                          )}
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Summary */}
      {(data.environments.length > 0 || (data.useCases || []).length > 0) && (
        <Card className="bg-primary/5 border-primary/20">
          <CardContent className="pt-6">
            <div className="flex items-center space-x-3">
              <Shield className="h-5 w-5 text-primary" />
              <div>
                <h4 className="font-medium">
                  Selected: {data.environments.length} environment types, {(data.useCases || []).length} use cases
                </h4>
                <p className="text-sm text-muted-foreground">
                  The STIG-Connector will be configured to discover and monitor these infrastructure types for your selected use cases.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};