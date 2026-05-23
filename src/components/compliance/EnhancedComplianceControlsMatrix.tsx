import { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Shield, Search, Filter, Bot, CheckCircle, AlertTriangle, Clock, Zap } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";

interface NISTControl {
  id: string;
  control_id: string;
  title: string;
  description: string;
  family: string;
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  baseline_low: boolean;
  baseline_moderate: boolean;
  baseline_high: boolean;
  baseline_privacy: boolean;
  automation_possible: boolean;
  stig_mappings: any[];
  cmmc_mappings: any[];
  implementation_status?: string;
}

interface ComplianceStats {
  total: number;
  implemented: number;
  inProgress: number;
  notStarted: number;
  aiRecommended: number;
}

export const EnhancedComplianceControlsMatrix: React.FC = () => {
  const [controls, setControls] = useState<NISTControl[]>([]);
  const [filteredControls, setFilteredControls] = useState<NISTControl[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedFamily, setSelectedFamily] = useState('all');
  const [selectedBaseline, setSelectedBaseline] = useState('all');
  const [stats, setStats] = useState<ComplianceStats>({ total: 0, implemented: 0, inProgress: 0, notStarted: 0, aiRecommended: 0 });
  const [activeTab, setActiveTab] = useState('overview');
  const { toast } = useToast();

  const controlFamilies = [
    { code: 'AC', name: 'Access Control', color: 'bg-blue-500' },
    { code: 'AT', name: 'Awareness and Training', color: 'bg-green-500' },
    { code: 'AU', name: 'Audit and Accountability', color: 'bg-purple-500' },
    { code: 'CA', name: 'Assessment, Authorization, and Monitoring', color: 'bg-orange-500' },
    { code: 'CM', name: 'Configuration Management', color: 'bg-red-500' },
    { code: 'CP', name: 'Contingency Planning', color: 'bg-yellow-500' },
    { code: 'IA', name: 'Identification and Authentication', color: 'bg-pink-500' },
    { code: 'IR', name: 'Incident Response', color: 'bg-indigo-500' },
    { code: 'MA', name: 'Maintenance', color: 'bg-teal-500' },
    { code: 'MP', name: 'Media Protection', color: 'bg-cyan-500' },
    { code: 'PE', name: 'Physical and Environmental Protection', color: 'bg-lime-500' },
    { code: 'PL', name: 'Planning', color: 'bg-amber-500' },
    { code: 'PS', name: 'Personnel Security', color: 'bg-emerald-500' },
    { code: 'RA', name: 'Risk Assessment', color: 'bg-violet-500' },
    { code: 'SA', name: 'System and Services Acquisition', color: 'bg-fuchsia-500' },
    { code: 'SC', name: 'System and Communications Protection', color: 'bg-rose-500' },
    { code: 'SI', name: 'System and Information Integrity', color: 'bg-sky-500' },
    { code: 'SR', name: 'Supply Chain Risk Management', color: 'bg-slate-500' }
  ];

  useEffect(() => {
    fetchNISTControls();
  }, []);

  useEffect(() => {
    filterControls();
  }, [controls, searchTerm, selectedFamily, selectedBaseline]);

  const fetchNISTControls = async () => {
    try {
      const { data, error } = await supabase
        .from('nist_controls')
        .select('*')
        .order('control_id');

      if (error) throw error;

      const transformedControls = (data || []).map(d => ({
        ...d,
        priority: (d.priority as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL') || 'MEDIUM',
        stig_mappings: Array.isArray(d.stig_mappings) ? d.stig_mappings : [],
        cmmc_mappings: Array.isArray(d.cmmc_mappings) ? d.cmmc_mappings : []
      }));
      setControls(transformedControls);
      calculateStats(transformedControls);
    } catch (error) {
      console.error('Error fetching NIST controls:', error);
      toast({
        title: "Error",
        description: "Failed to load compliance controls",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const calculateStats = (controlsData: NISTControl[]) => {
    const total = controlsData.length;
    const implemented = controlsData.filter(c => c.implementation_status === 'implemented').length;
    const inProgress = controlsData.filter(c => c.implementation_status === 'in_progress').length;
    const notStarted = controlsData.filter(c => !c.implementation_status || c.implementation_status === 'not_started').length;
    const aiRecommended = controlsData.filter(c => c.automation_possible).length;

    setStats({ total, implemented, inProgress, notStarted, aiRecommended });
  };

  const filterControls = () => {
    let filtered = controls;

    if (searchTerm) {
      filtered = filtered.filter(control =>
        control.control_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        control.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
        control.description.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    if (selectedFamily !== 'all') {
      filtered = filtered.filter(control => control.family === selectedFamily);
    }

    if (selectedBaseline !== 'all') {
      filtered = filtered.filter(control => {
        switch (selectedBaseline) {
          case 'low': return control.baseline_low;
          case 'moderate': return control.baseline_moderate;
          case 'high': return control.baseline_high;
          case 'privacy': return control.baseline_privacy;
          default: return true;
        }
      });
    }

    setFilteredControls(filtered);
  };

  const getImplementationIcon = (status?: string) => {
    switch (status) {
      case 'implemented': return <CheckCircle className="h-4 w-4 text-green-400" />;
      case 'in_progress': return <Clock className="h-4 w-4 text-yellow-400" />;
      default: return <AlertTriangle className="h-4 w-4 text-red-400" />;
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'CRITICAL': return 'bg-red-500/10 text-red-400 border-red-500/30';
      case 'HIGH': return 'bg-orange-500/10 text-orange-400 border-orange-500/30';
      case 'MEDIUM': return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30';
      case 'LOW': return 'bg-green-500/10 text-green-400 border-green-500/30';
      default: return 'bg-gray-500/10 text-gray-400 border-gray-500/30';
    }
  };

  const triggerAIAnalysis = async () => {
    try {
      toast({
        title: "AI Analysis Started",
        description: "Analyzing compliance gaps and generating recommendations...",
      });

      const { data, error } = await supabase.functions.invoke('ai-compliance-analyzer', {
        body: { 
          organization_id: 'current', // This would be dynamic in real implementation
          analysis_type: 'comprehensive'
        }
      });

      if (error) throw error;

      toast({
        title: "AI Analysis Complete",
        description: "Generated recommendations for priority controls",
      });
      
      fetchNISTControls(); // Refresh data
    } catch (error) {
      toast({
        title: "Analysis Failed",
        description: "Could not complete AI analysis",
        variant: "destructive"
      });
    }
  };

  if (loading) {
    return (
      <Card className="bg-black/40 border-primary/30">
        <CardContent className="p-8">
          <div className="flex items-center justify-center">
            <div className="animate-spin h-8 w-8 border-2 border-primary border-t-transparent rounded-full"></div>
            <span className="ml-3 text-primary">Loading compliance matrix...</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header Stats */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <Card className="bg-gradient-to-r from-blue-500/10 to-blue-600/10 border-blue-500/30">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-blue-300 text-sm">Total Controls</p>
                <p className="text-2xl font-bold text-blue-400">{stats.total}</p>
              </div>
              <Shield className="h-8 w-8 text-blue-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-r from-green-500/10 to-green-600/10 border-green-500/30">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-green-300 text-sm">Implemented</p>
                <p className="text-2xl font-bold text-green-400">{stats.implemented}</p>
              </div>
              <CheckCircle className="h-8 w-8 text-green-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-r from-yellow-500/10 to-yellow-600/10 border-yellow-500/30">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-yellow-300 text-sm">In Progress</p>
                <p className="text-2xl font-bold text-yellow-400">{stats.inProgress}</p>
              </div>
              <Clock className="h-8 w-8 text-yellow-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-r from-red-500/10 to-red-600/10 border-red-500/30">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-red-300 text-sm">Not Started</p>
                <p className="text-2xl font-bold text-red-400">{stats.notStarted}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-red-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-r from-purple-500/10 to-purple-600/10 border-purple-500/30">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-purple-300 text-sm">AI Ready</p>
                <p className="text-2xl font-bold text-purple-400">{stats.aiRecommended}</p>
              </div>
              <Bot className="h-8 w-8 text-purple-400" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Progress Overview */}
      <Card className="bg-black/40 border-primary/30">
        <CardContent className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Implementation Progress</h3>
            <Button onClick={triggerAIAnalysis} variant="outline" size="sm" className="border-primary/30">
              <Zap className="h-4 w-4 mr-2" />
              AI Analysis
            </Button>
          </div>
          <Progress 
            value={stats.total > 0 ? (stats.implemented / stats.total) * 100 : 0} 
            className="h-3"
          />
          <div className="flex justify-between text-sm text-muted-foreground mt-2">
            <span>{stats.implemented} of {stats.total} controls implemented</span>
            <span>{stats.total > 0 ? Math.round((stats.implemented / stats.total) * 100) : 0}% complete</span>
          </div>
        </CardContent>
      </Card>

      {/* Main Controls Matrix */}
      <Card className="bg-black/40 border-primary/30">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2 text-primary">
            <Shield className="h-5 w-5" />
            <span>NIST 800-53 Controls Matrix</span>
            <Badge variant="outline" className="ml-2 text-xs bg-primary/10 text-primary border-primary/30">
              424 Controls
            </Badge>
          </CardTitle>

          {/* Filters */}
          <div className="flex flex-wrap gap-4 mt-4">
            <div className="flex-1 min-w-64">
              <div className="relative">
                <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search controls..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10 bg-black/40 border-primary/30"
                />
              </div>
            </div>
            
            <Select value={selectedFamily} onValueChange={setSelectedFamily}>
              <SelectTrigger className="w-48 bg-black/40 border-primary/30">
                <SelectValue placeholder="Control Family" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Families</SelectItem>
                {controlFamilies.map(family => (
                  <SelectItem key={family.code} value={family.code}>
                    {family.code} - {family.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select value={selectedBaseline} onValueChange={setSelectedBaseline}>
              <SelectTrigger className="w-48 bg-black/40 border-primary/30">
                <SelectValue placeholder="Baseline" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Baselines</SelectItem>
                <SelectItem value="low">Low Impact</SelectItem>
                <SelectItem value="moderate">Moderate Impact</SelectItem>
                <SelectItem value="high">High Impact</SelectItem>
                <SelectItem value="privacy">Privacy</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>

        <CardContent>
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="overview">Controls Overview</TabsTrigger>
              <TabsTrigger value="families">By Family</TabsTrigger>
              <TabsTrigger value="implementation">Implementation View</TabsTrigger>
            </TabsList>

            <TabsContent value="overview" className="mt-6">
              <div className="space-y-3">
                {filteredControls.slice(0, 50).map((control) => (
                  <div key={control.id} className="p-4 bg-slate-800/40 rounded-lg border border-slate-600/30 hover:border-primary/30 transition-colors">
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center space-x-3">
                        {getImplementationIcon(control.implementation_status)}
                        <div>
                          <h4 className="font-semibold text-white">{control.control_id}</h4>
                          <p className="text-sm text-slate-300">{control.title}</p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Badge className={getPriorityColor(control.priority)}>
                          {control.priority}
                        </Badge>
                        {control.automation_possible && (
                          <Badge variant="outline" className="bg-purple-500/10 text-purple-400 border-purple-500/30">
                            <Bot className="h-3 w-3 mr-1" />
                            AI Ready
                          </Badge>
                        )}
                      </div>
                    </div>
                    
                    <div className="flex items-center space-x-4 text-xs text-slate-400">
                      <span>Family: {control.family}</span>
                      {control.baseline_low && <Badge variant="secondary" className="text-xs">Low</Badge>}
                      {control.baseline_moderate && <Badge variant="secondary" className="text-xs">Mod</Badge>}
                      {control.baseline_high && <Badge variant="secondary" className="text-xs">High</Badge>}
                      {control.baseline_privacy && <Badge variant="secondary" className="text-xs">Privacy</Badge>}
                      <span>STIGs: {control.stig_mappings?.length || 0}</span>
                      <span>CMMC: {control.cmmc_mappings?.length || 0}</span>
                    </div>
                  </div>
                ))}
                
                {filteredControls.length > 50 && (
                  <div className="text-center py-4">
                    <p className="text-slate-400">Showing first 50 of {filteredControls.length} controls</p>
                  </div>
                )}
              </div>
            </TabsContent>

            <TabsContent value="families" className="mt-6">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {controlFamilies.map(family => {
                  const familyControls = filteredControls.filter(c => c.family === family.code);
                  const implementedCount = familyControls.filter(c => c.implementation_status === 'implemented').length;
                  
                  return (
                    <Card key={family.code} className="bg-slate-800/40 border-slate-600/30">
                      <CardContent className="p-4">
                        <div className="flex items-center space-x-3 mb-3">
                          <div className={`w-3 h-3 rounded-full ${family.color}`}></div>
                          <div>
                            <h4 className="font-semibold text-white">{family.code}</h4>
                            <p className="text-xs text-slate-300">{family.name}</p>
                          </div>
                        </div>
                        
                        <div className="space-y-2">
                          <div className="flex justify-between text-sm">
                            <span className="text-slate-400">Controls: {familyControls.length}</span>
                            <span className="text-slate-400">Implemented: {implementedCount}</span>
                          </div>
                          <Progress 
                            value={familyControls.length > 0 ? (implementedCount / familyControls.length) * 100 : 0}
                            className="h-2"
                          />
                        </div>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            </TabsContent>

            <TabsContent value="implementation" className="mt-6">
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <Card className="bg-red-500/10 border-red-500/30">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-red-400 text-sm">High Priority - Not Implemented</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <p className="text-2xl font-bold text-red-400">
                        {filteredControls.filter(c => c.priority === 'HIGH' && (!c.implementation_status || c.implementation_status === 'not_started')).length}
                      </p>
                    </CardContent>
                  </Card>

                  <Card className="bg-yellow-500/10 border-yellow-500/30">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-yellow-400 text-sm">In Progress</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <p className="text-2xl font-bold text-yellow-400">{stats.inProgress}</p>
                    </CardContent>
                  </Card>

                  <Card className="bg-green-500/10 border-green-500/30">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-green-400 text-sm">Completed</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <p className="text-2xl font-bold text-green-400">{stats.implemented}</p>
                    </CardContent>
                  </Card>
                </div>

                <div className="text-center py-8">
                  <Button onClick={triggerAIAnalysis} size="lg" className="bg-primary hover:bg-primary/90">
                    <Bot className="h-5 w-5 mr-2" />
                    Generate AI Implementation Plan
                  </Button>
                  <p className="text-sm text-slate-400 mt-2">
                    AI will analyze your environment and create automated implementation recommendations
                  </p>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};