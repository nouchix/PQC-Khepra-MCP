import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import {
  TrendingUp,
  Users,
  Shield,
  Settings,
  FileText,
  Bot,
  Zap,
  Target,
  CheckCircle
} from 'lucide-react';
import { useEnterpriseAgents } from '@/hooks/useEnterpriseAgents';
import { useToast } from '@/hooks/use-toast';

interface AgentTemplate {
  type: string;
  name: string;
  description: string;
  icon: React.ElementType;
  specialization: string;
  capabilities: string[];
  useCase: string;
  riskLevel: 'low' | 'medium' | 'high';
  estimatedROI: string;
}

const agentTemplates: AgentTemplate[] = [
  {
    type: 'finance',
    name: 'Finance Agent',
    description: 'Automates financial analysis, budget monitoring, and cost optimization',
    icon: TrendingUp,
    specialization: 'Budget analysis, cost optimization, and financial compliance monitoring',
    capabilities: ['Budget Analysis', 'Cost Optimization', 'Financial Reporting', 'Expense Tracking', 'ROI Calculation'],
    useCase: 'Reducing manual financial analysis by 75% and identifying cost savings opportunities',
    riskLevel: 'medium',
    estimatedROI: '$120K/year savings'
  },
  {
    type: 'security',
    name: 'Security Agent',
    description: 'Monitors threats, automates incident response, and ensures compliance',
    icon: Shield,
    specialization: 'Threat detection, incident response automation, and security compliance',
    capabilities: ['Threat Detection', 'Incident Response', 'Compliance Monitoring', 'Risk Assessment', 'Security Reporting'],
    useCase: 'Reducing incident response time from hours to minutes, 24/7 monitoring',
    riskLevel: 'high',
    estimatedROI: '$200K/year savings'
  },
  {
    type: 'hr',
    name: 'HR Agent',
    description: 'Streamlines recruitment, onboarding, and employee management',
    icon: Users,
    specialization: 'Employee onboarding, policy compliance, and HR workflow automation',
    capabilities: ['Employee Onboarding', 'Policy Management', 'Performance Tracking', 'Compliance Checking', 'Document Processing'],
    useCase: 'Reducing onboarding time from 2 weeks to 3 days, automating compliance checks',
    riskLevel: 'low',
    estimatedROI: '$80K/year savings'
  },
  {
    type: 'operations',
    name: 'Operations Agent',
    description: 'Manages infrastructure, automates deployments, and monitors systems',
    icon: Settings,
    specialization: 'Infrastructure monitoring, deployment automation, and system maintenance',
    capabilities: ['Infrastructure Monitoring', 'Deployment Automation', 'System Maintenance', 'Performance Optimization', 'Capacity Planning'],
    useCase: 'Reducing deployment failures by 90%, automating routine maintenance tasks',
    riskLevel: 'high',
    estimatedROI: '$150K/year savings'
  },
  {
    type: 'legal',
    name: 'Legal Agent',
    description: 'Automates contract analysis, compliance checking, and legal research',
    icon: FileText,
    specialization: 'Contract analysis, regulatory compliance, and legal document processing',
    capabilities: ['Contract Analysis', 'Compliance Checking', 'Legal Research', 'Document Review', 'Risk Assessment'],
    useCase: 'Reducing contract review time from days to hours, ensuring regulatory compliance',
    riskLevel: 'medium',
    estimatedROI: '$100K/year savings'
  }
];

const SpecializedAgentTemplates: React.FC = () => {
  const { createAgent } = useEnterpriseAgents();
  const { toast } = useToast();
  const [selectedTemplate, setSelectedTemplate] = useState<AgentTemplate | null>(null);
  const [showCreateDialog, setShowCreateDialog] = useState(false);

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'low': return 'bg-green-100 text-green-800';
      case 'medium': return 'bg-yellow-100 text-yellow-800';
      case 'high': return 'bg-red-100 text-red-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const handleCreateFromTemplate = async (formData: FormData) => {
    if (!selectedTemplate) return;

    const agentData = {
      agent_name: formData.get('name') as string,
      agent_type: selectedTemplate.type,
      specialization: selectedTemplate.specialization,
      capabilities: selectedTemplate.capabilities
    };

    const newAgent = await createAgent(agentData);
    if (newAgent) {
      setShowCreateDialog(false);
      setSelectedTemplate(null);
      toast({
        title: "Agent created successfully",
        description: `Your ${selectedTemplate.name} is ready for training and deployment`
      });
    }
  };

  const openCreateDialog = (template: AgentTemplate) => {
    setSelectedTemplate(template);
    setShowCreateDialog(true);
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold mb-2">Specialized Agent Templates</h2>
        <p className="text-muted-foreground">
          Deploy pre-configured agents optimized for specific business functions
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {agentTemplates.map((template) => {
          const Icon = template.icon;
          return (
            <Card key={template.type} className="hover:shadow-lg transition-shadow cursor-pointer">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex items-center space-x-3">
                    <div className="p-3 rounded-lg bg-primary/10">
                      <Icon className="w-6 h-6 text-primary" />
                    </div>
                    <div>
                      <CardTitle className="text-lg">{template.name}</CardTitle>
                      <Badge variant="outline" className={getRiskColor(template.riskLevel)}>
                        {template.riskLevel} risk
                      </Badge>
                    </div>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-muted-foreground">
                  {template.description}
                </p>

                <div>
                  <h4 className="font-semibold text-sm mb-2">Key Capabilities:</h4>
                  <div className="flex flex-wrap gap-1">
                    {template.capabilities.slice(0, 3).map((capability, idx) => (
                      <Badge key={idx} variant="secondary" className="text-xs">
                        {capability}
                      </Badge>
                    ))}
                    {template.capabilities.length > 3 && (
                      <Badge variant="secondary" className="text-xs">
                        +{template.capabilities.length - 3}
                      </Badge>
                    )}
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center text-sm">
                    <Target className="w-4 h-4 mr-2 text-blue-500" />
                    <span className="font-medium">Use Case:</span>
                  </div>
                  <p className="text-xs text-muted-foreground pl-6">
                    {template.useCase}
                  </p>
                </div>

                <div className="flex items-center justify-between pt-2">
                  <div className="text-sm">
                    <span className="font-semibold text-green-600">{template.estimatedROI}</span>
                  </div>
                  <Button 
                    size="sm" 
                    onClick={() => openCreateDialog(template)}
                    className="flex items-center space-x-1"
                  >
                    <Zap className="w-3 h-3" />
                    <span>Deploy</span>
                  </Button>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Create Agent Dialog */}
      <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              Deploy {selectedTemplate?.name}
            </DialogTitle>
          </DialogHeader>
          {selectedTemplate && (
            <form onSubmit={(e) => {
              e.preventDefault();
              handleCreateFromTemplate(new FormData(e.currentTarget));
            }} className="space-y-4">
              <div>
                <Label htmlFor="name">Agent Name</Label>
                <Input 
                  id="name" 
                  name="name" 
                  placeholder={`My ${selectedTemplate.name}`}
                  defaultValue={`${selectedTemplate.name} - ${new Date().getFullYear()}`}
                  required 
                />
              </div>
              
              <div>
                <Label>Specialization</Label>
                <Textarea 
                  value={selectedTemplate.specialization}
                  readOnly
                  className="bg-muted"
                />
              </div>

              <div>
                <Label>Pre-configured Capabilities</Label>
                <div className="flex flex-wrap gap-2 mt-2">
                  {selectedTemplate.capabilities.map((capability, idx) => (
                    <Badge key={idx} variant="outline">
                      {capability}
                    </Badge>
                  ))}
                </div>
              </div>

              <div className="bg-blue-50 p-4 rounded-lg">
                <h4 className="font-semibold text-sm mb-2 flex items-center">
                  <CheckCircle className="w-4 h-4 mr-2 text-blue-500" />
                  Expected Benefits
                </h4>
                <p className="text-sm text-blue-700">{selectedTemplate.useCase}</p>
                <p className="text-sm font-semibold text-green-600 mt-2">
                  Estimated ROI: {selectedTemplate.estimatedROI}
                </p>
              </div>

              <div className="flex space-x-2">
                <Button type="submit" className="flex-1">
                  <Bot className="w-4 h-4 mr-2" />
                  Create Agent
                </Button>
                <Button 
                  type="button" 
                  variant="outline" 
                  onClick={() => setShowCreateDialog(false)}
                >
                  Cancel
                </Button>
              </div>
            </form>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default SpecializedAgentTemplates;