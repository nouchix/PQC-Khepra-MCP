import { useState } from 'react';
import { useComplianceFrameworks } from '@/hooks/useComplianceFrameworks';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Shield, Plus, CheckCircle, AlertCircle, FileText, Clock, Target } from 'lucide-react';
import { toast } from 'sonner';

const CMMC_FRAMEWORKS = [
  { id: 'cmmc-l3', name: 'CMMC Level 3', description: 'Cybersecurity Maturity Model Certification Level 3', controls: 134 },
  { id: 'nist-800-171', name: 'NIST SP 800-171', description: 'Protecting Controlled Unclassified Information', controls: 110 },
  { id: 'nist-800-172', name: 'NIST SP 800-172', description: 'Enhanced Security Requirements', controls: 24 },
  { id: 'nist-800-53', name: 'NIST SP 800-53', description: 'Security and Privacy Controls', controls: 330 },
  { id: 'fedramp-high', name: 'FedRAMP High', description: 'Federal Risk and Authorization Management Program', controls: 325 }
];

const SECURITY_DOMAINS = [
  'Access Control', 'Awareness and Training', 'Audit and Accountability', 'Configuration Management',
  'Identification and Authentication', 'Incident Response', 'Maintenance', 'Media Protection',
  'Personnel Security', 'Physical and Environmental Protection', 'Risk Assessment', 'Security Assessment',
  'System and Communications Protection', 'System and Information Integrity'
];

export const ComplianceFrameworkManager = () => {
  const { frameworks, assessments, loading, createFramework, createAssessment, getFrameworkCompliance } = useComplianceFrameworks();
  const [showCreateFramework, setShowCreateFramework] = useState(false);
  const [showCreateAssessment, setShowCreateAssessment] = useState(false);
  const [newFramework, setNewFramework] = useState({
    name: '',
    category: 'regulatory',
    version: '1.0',
    description: '',
    authority: ''
  });
  const [newAssessment, setNewAssessment] = useState({
    name: '',
    assessment_type: 'internal',
    description: '',
    framework_id: '',
    assessor_name: '',
    assessor_organization: '',
    target_completion_date: ''
  });

  const handleCreateFramework = async (e: React.FormEvent) => {
    e.preventDefault();
    const { error } = await createFramework({
      ...newFramework,
      metadata: {},
      enabled: true,
      organization_id: null
    });
    
    if (error) {
      toast.error('Failed to create framework: ' + error);
    } else {
      toast.success('Compliance framework created successfully');
      setShowCreateFramework(false);
      setNewFramework({ name: '', category: 'regulatory', version: '1.0', description: '', authority: '' });
    }
  };

  const handleCreateAssessment = async (e: React.FormEvent) => {
    e.preventDefault();
    const { error } = await createAssessment({
      ...newAssessment,
      status: 'PLANNED',
      start_date: new Date().toISOString().split('T')[0],
      target_completion_date: newAssessment.target_completion_date || null,
      recommendations: null,
      organization_id: null,
      actual_completion_date: null,
      compliance_level: null,
      findings_summary: null,
      next_assessment_due: null,
      overall_score: null,
      created_by: null,
      scope_description: null
    });
    
    if (error) {
      toast.error('Failed to create assessment: ' + error);
    } else {
      toast.success('Compliance assessment created successfully');
      setShowCreateAssessment(false);
      setNewAssessment({
        name: '', assessment_type: 'internal', description: '', framework_id: '',
        assessor_name: '', assessor_organization: '', target_completion_date: ''
      });
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'COMPLETED': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'IN_PROGRESS': return <Clock className="h-4 w-4 text-blue-500" />;
      case 'PLANNED': return <Target className="h-4 w-4 text-yellow-500" />;
      default: return <AlertCircle className="h-4 w-4 text-red-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'COMPLETED': return 'bg-green-500/10 text-green-500 border-green-500/20';
      case 'IN_PROGRESS': return 'bg-blue-500/10 text-blue-500 border-blue-500/20';
      case 'PLANNED': return 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20';
      default: return 'bg-red-500/10 text-red-500 border-red-500/20';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="text-slate-400">Loading compliance frameworks...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Shield className="h-6 w-6 text-blue-400" />
              <div>
                <CardTitle className="text-white">Enterprise STIG & Compliance Framework Management</CardTitle>
                <CardDescription className="text-slate-400">
                  200+ STIGs • CMMC Level 1-3 • NIST 800-53/171 • Continuous Monitoring • Automated Remediation
                </CardDescription>
              </div>
            </div>
            <div className="flex space-x-2">
              <Dialog open={showCreateFramework} onOpenChange={setShowCreateFramework}>
                <DialogTrigger asChild>
                  <Button variant="outline" size="sm" className="border-slate-600">
                    <Plus className="h-4 w-4 mr-2" />
                    Add Framework
                  </Button>
                </DialogTrigger>
                <DialogContent className="bg-slate-800 border-slate-700">
                  <DialogHeader>
                    <DialogTitle className="text-white">Create Compliance Framework</DialogTitle>
                  </DialogHeader>
                  <form onSubmit={handleCreateFramework} className="space-y-4">
                    <div>
                      <Label htmlFor="framework-name" className="text-slate-300">Framework Name</Label>
                      <Select value={newFramework.name} onValueChange={(value) => {
                        const selected = CMMC_FRAMEWORKS.find(f => f.name === value);
                        setNewFramework(prev => ({
                          ...prev,
                          name: value,
                          description: selected?.description || prev.description
                        }));
                      }}>
                        <SelectTrigger className="bg-slate-700 border-slate-600">
                          <SelectValue placeholder="Select a framework" />
                        </SelectTrigger>
                        <SelectContent>
                          {CMMC_FRAMEWORKS.map(framework => (
                            <SelectItem key={framework.id} value={framework.name}>
                              {framework.name} ({framework.controls} controls)
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div>
                      <Label htmlFor="framework-category" className="text-slate-300">Category</Label>
                      <Select value={newFramework.category} onValueChange={(value) => setNewFramework(prev => ({...prev, category: value}))}>
                        <SelectTrigger className="bg-slate-700 border-slate-600">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="regulatory">Regulatory</SelectItem>
                          <SelectItem value="industry">Industry Standard</SelectItem>
                          <SelectItem value="internal">Internal Policy</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div>
                      <Label htmlFor="framework-version" className="text-slate-300">Version</Label>
                      <Input
                        id="framework-version"
                        value={newFramework.version}
                        onChange={(e) => setNewFramework(prev => ({...prev, version: e.target.value}))}
                        className="bg-slate-700 border-slate-600"
                        placeholder="1.0"
                      />
                    </div>
                    <div>
                      <Label htmlFor="framework-authority" className="text-slate-300">Authority</Label>
                      <Input
                        id="framework-authority"
                        value={newFramework.authority}
                        onChange={(e) => setNewFramework(prev => ({...prev, authority: e.target.value}))}
                        className="bg-slate-700 border-slate-600"
                        placeholder="e.g., DoD, NIST"
                      />
                    </div>
                    <div>
                      <Label htmlFor="framework-description" className="text-slate-300">Description</Label>
                      <Textarea
                        id="framework-description"
                        value={newFramework.description}
                        onChange={(e) => setNewFramework(prev => ({...prev, description: e.target.value}))}
                        className="bg-slate-700 border-slate-600"
                        rows={3}
                      />
                    </div>
                    <Button type="submit" className="w-full">Create Framework</Button>
                  </form>
                </DialogContent>
              </Dialog>
            </div>
          </div>
        </CardHeader>
      </Card>

      <Tabs defaultValue="frameworks" className="w-full">
        <TabsList className="grid w-full grid-cols-2 bg-slate-800 border-slate-700">
          <TabsTrigger value="frameworks" className="text-slate-300">Frameworks</TabsTrigger>
          <TabsTrigger value="assessments" className="text-slate-300">Assessments</TabsTrigger>
        </TabsList>

        <TabsContent value="frameworks" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {frameworks.map((framework) => {
              const compliance = getFrameworkCompliance(framework.id);
              return (
                <Card key={framework.id} className="bg-slate-800/50 border-slate-700">
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-white text-sm">{framework.name}</CardTitle>
                      <Badge variant="outline" className="text-xs">
                        {framework.category}
                      </Badge>
                    </div>
                    <CardDescription className="text-slate-400 text-xs">
                      {framework.description}
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      <div>
                        <div className="flex justify-between text-xs mb-1">
                          <span className="text-slate-300">Compliance Score</span>
                          <span className="text-blue-400">{compliance.score}%</span>
                        </div>
                        <Progress value={compliance.score} className="h-2" />
                      </div>
                      <div className="flex justify-between text-xs">
                        <span className="text-slate-400">Controls</span>
                        <span className="text-slate-300">{compliance.implemented}/{compliance.total}</span>
                      </div>
                      <div className="flex justify-between text-xs">
                        <span className="text-slate-400">Version</span>
                        <span className="text-slate-300">{framework.version}</span>
                      </div>
                      {framework.authority && (
                        <div className="flex justify-between text-xs">
                          <span className="text-slate-400">Authority</span>
                          <span className="text-slate-300">{framework.authority}</span>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </TabsContent>

        <TabsContent value="assessments" className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold text-white">Compliance Assessments</h3>
            <Dialog open={showCreateAssessment} onOpenChange={setShowCreateAssessment}>
              <DialogTrigger asChild>
                <Button variant="outline" size="sm" className="border-slate-600">
                  <Plus className="h-4 w-4 mr-2" />
                  New Assessment
                </Button>
              </DialogTrigger>
              <DialogContent className="bg-slate-800 border-slate-700">
                <DialogHeader>
                  <DialogTitle className="text-white">Create Compliance Assessment</DialogTitle>
                </DialogHeader>
                <form onSubmit={handleCreateAssessment} className="space-y-4">
                  <div>
                    <Label htmlFor="assessment-name" className="text-slate-300">Assessment Name</Label>
                    <Input
                      id="assessment-name"
                      value={newAssessment.name}
                      onChange={(e) => setNewAssessment(prev => ({...prev, name: e.target.value}))}
                      className="bg-slate-700 border-slate-600"
                      placeholder="CMMC Level 3 Initial Assessment"
                      required
                    />
                  </div>
                  <div>
                    <Label htmlFor="assessment-type" className="text-slate-300">Assessment Type</Label>
                    <Select value={newAssessment.assessment_type} onValueChange={(value) => setNewAssessment(prev => ({...prev, assessment_type: value}))}>
                      <SelectTrigger className="bg-slate-700 border-slate-600">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="internal">Internal Assessment</SelectItem>
                        <SelectItem value="external">External Assessment</SelectItem>
                        <SelectItem value="self">Self-Assessment</SelectItem>
                        <SelectItem value="third_party">Third-Party Assessment</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label htmlFor="framework-select" className="text-slate-300">Framework</Label>
                    <Select value={newAssessment.framework_id} onValueChange={(value) => setNewAssessment(prev => ({...prev, framework_id: value}))}>
                      <SelectTrigger className="bg-slate-700 border-slate-600">
                        <SelectValue placeholder="Select framework" />
                      </SelectTrigger>
                      <SelectContent>
                        {frameworks.map(framework => (
                          <SelectItem key={framework.id} value={framework.id}>
                            {framework.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label htmlFor="assessor-name" className="text-slate-300">Assessor Name</Label>
                    <Input
                      id="assessor-name"
                      value={newAssessment.assessor_name}
                      onChange={(e) => setNewAssessment(prev => ({...prev, assessor_name: e.target.value}))}
                      className="bg-slate-700 border-slate-600"
                      placeholder="Lead Assessor"
                    />
                  </div>
                  <div>
                    <Label htmlFor="assessor-org" className="text-slate-300">Assessor Organization</Label>
                    <Input
                      id="assessor-org"
                      value={newAssessment.assessor_organization}
                      onChange={(e) => setNewAssessment(prev => ({...prev, assessor_organization: e.target.value}))}
                      className="bg-slate-700 border-slate-600"
                      placeholder="Internal Team / External Auditor"
                    />
                  </div>
                  <div>
                    <Label htmlFor="target-date" className="text-slate-300">Target Completion Date</Label>
                    <Input
                      id="target-date"
                      type="date"
                      value={newAssessment.target_completion_date}
                      onChange={(e) => setNewAssessment(prev => ({...prev, target_completion_date: e.target.value}))}
                      className="bg-slate-700 border-slate-600"
                    />
                  </div>
                  <div>
                    <Label htmlFor="assessment-description" className="text-slate-300">Description</Label>
                    <Textarea
                      id="assessment-description"
                      value={newAssessment.description}
                      onChange={(e) => setNewAssessment(prev => ({...prev, description: e.target.value}))}
                      className="bg-slate-700 border-slate-600"
                      rows={3}
                      placeholder="Assessment scope and objectives"
                    />
                  </div>
                  <Button type="submit" className="w-full">Create Assessment</Button>
                </form>
              </DialogContent>
            </Dialog>
          </div>
          
          <div className="grid grid-cols-1 gap-4">
            {assessments.map((assessment) => (
              <Card key={assessment.id} className="bg-slate-800/50 border-slate-700">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <FileText className="h-5 w-5 text-blue-400" />
                      <CardTitle className="text-white">{assessment.name}</CardTitle>
                    </div>
                    <Badge className={getStatusColor(assessment.status)}>
                      {getStatusIcon(assessment.status)}
                      <span className="ml-1">{assessment.status}</span>
                    </Badge>
                  </div>
                  <CardDescription className="text-slate-400">
                    {assessment.description}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-slate-400">Type:</span>
                      <span className="text-slate-300 ml-2">{assessment.assessment_type}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Assessor:</span>
                      <span className="text-slate-300 ml-2">{assessment.assessor_name || 'TBD'}</span>
                    </div>
                    {assessment.target_completion_date && (
                      <div>
                        <span className="text-slate-400">Target Date:</span>
                        <span className="text-slate-300 ml-2">
                          {new Date(assessment.target_completion_date).toLocaleDateString()}
                        </span>
                      </div>
                    )}
                    {assessment.overall_score && (
                      <div>
                        <span className="text-slate-400">Score:</span>
                        <span className="text-slate-300 ml-2">{assessment.overall_score}%</span>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))}
            {assessments.length === 0 && (
              <Card className="bg-slate-800/50 border-slate-700">
                <CardContent className="text-center py-8">
                  <FileText className="h-12 w-12 text-slate-500 mx-auto mb-4" />
                  <p className="text-slate-400">No compliance assessments found</p>
                  <p className="text-slate-500 text-sm">Create your first assessment to get started</p>
                </CardContent>
              </Card>
            )}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};