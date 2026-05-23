/**
 * CMMC-to-STIG Bridge Component
 * Transforms CMMC mandates into actionable STIG implementations
 */

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Checkbox } from '@/components/ui/checkbox';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { 
  Shield, 
  ArrowRight, 
  CheckCircle, 
  Clock, 
  DollarSign, 
  Settings,
  Target,
  Zap,
  FileText
} from 'lucide-react';
import { STIGCodexEngine } from '@/services/STIGCodexEngine';
import { useOrganization } from '@/hooks/useOrganization';
import { useToast } from '@/hooks/use-toast';

interface CMMCMapping {
  cmmc_control: string;
  stig_implementations: Array<{
    stig_id: string;
    platform: string;
    implementation_guidance: string;
    automation_possible: boolean;
    priority_score: number;
  }>;
}

interface ImplementationPlan {
  total_stig_rules: number;
  automated_implementations: number;
  manual_implementations: number;
  estimated_effort_hours: number;
}

export const CMMCSTIGBridge = () => {
  const { currentOrganization } = useOrganization();
  const { toast } = useToast();
  
  const [selectedCMMCLevel, setSelectedCMMCLevel] = useState<number>(2);
  const [selectedPlatforms, setSelectedPlatforms] = useState<string[]>(['windows_server']);
  const [selectedControls, setSelectedControls] = useState<string[]>([]);
  const [mappings, setMappings] = useState<CMMCMapping[]>([]);
  const [implementationPlan, setImplementationPlan] = useState<ImplementationPlan | null>(null);
  const [loading, setLoading] = useState(false);

  const cmmcControls = {
    1: ['AC.1.001', 'AC.1.002', 'IA.1.076', 'IA.1.077', 'SC.1.175'],
    2: ['AC.2.007', 'AC.2.008', 'AU.2.041', 'AU.2.042', 'IA.2.078', 'IA.2.079', 'SC.2.179'],
    3: ['AC.3.014', 'AC.3.015', 'AU.3.045', 'AU.3.046', 'CM.3.068', 'IA.3.083', 'SC.3.185']
  };

  const platformOptions = [
    { value: 'windows_server', label: 'Windows Server' },
    { value: 'linux_server', label: 'Linux Server' },
    { value: 'network_device', label: 'Network Device' },
    { value: 'database', label: 'Database' },
    { value: 'cloud_service', label: 'Cloud Service' }
  ];

  useEffect(() => {
    const controls = cmmcControls[selectedCMMCLevel as keyof typeof cmmcControls] || [];
    setSelectedControls(controls);
  }, [selectedCMMCLevel]);

  const generateMapping = async () => {
    if (!currentOrganization?.id || selectedControls.length === 0) return;

    setLoading(true);
    try {
      const result = await STIGCodexEngine.generateCMMCToSTIGMapping(
        selectedControls,
        selectedPlatforms
      );

      setMappings(result.mappings);
      setImplementationPlan(result.implementation_plan);

      toast({
        title: "CMMC-to-STIG Mapping Generated",
        description: `Generated ${result.mappings.length} control mappings with ${result.implementation_plan.total_stig_rules} STIG implementations`
      });
    } catch (error) {
      console.error('Failed to generate CMMC mapping:', error);
      toast({
        title: "Mapping Generation Failed",
        description: "Failed to generate CMMC-to-STIG mappings",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const getAutomationBadge = (automationPossible: boolean) => (
    <Badge variant={automationPossible ? "default" : "secondary"}>
      {automationPossible ? (
        <>
          <Zap className="w-3 h-3 mr-1" />
          Automatable
        </>
      ) : (
        <>
          <Settings className="w-3 h-3 mr-1" />
          Manual
        </>
      )}
    </Badge>
  );

  const getPriorityBadge = (score: number) => {
    const variant = score >= 80 ? "destructive" : score >= 60 ? "secondary" : "outline";
    const label = score >= 80 ? "High" : score >= 60 ? "Medium" : "Low";
    return <Badge variant={variant}>{label} Priority</Badge>;
  };

  return (
    <div className="space-y-6">
      {/* Configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="w-5 h-5" />
            CMMC-to-STIG Bridge
          </CardTitle>
          <CardDescription>
            Transform CMMC mandates into actionable STIG implementations
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div>
              <label className="text-sm font-medium mb-2 block">CMMC Level</label>
              <Select
                value={selectedCMMCLevel.toString()}
                onValueChange={(value) => setSelectedCMMCLevel(Number.parseInt(value))}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1">Level 1 - Basic Safeguarding</SelectItem>
                  <SelectItem value="2">Level 2 - Advanced Safeguarding</SelectItem>
                  <SelectItem value="3">Level 3 - Expert Safeguarding</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div>
              <label className="text-sm font-medium mb-2 block">Target Platforms</label>
              <div className="space-y-2 max-h-32 overflow-y-auto">
                {platformOptions.map((platform) => (
                  <div key={platform.value} className="flex items-center space-x-2">
                    <Checkbox
                      id={platform.value}
                      checked={selectedPlatforms.includes(platform.value)}
                      onCheckedChange={(checked) => {
                        if (checked) {
                          setSelectedPlatforms([...selectedPlatforms, platform.value]);
                        } else {
                          setSelectedPlatforms(selectedPlatforms.filter(p => p !== platform.value));
                        }
                      }}
                    />
                    <label htmlFor={platform.value} className="text-sm">
                      {platform.label}
                    </label>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex flex-col justify-end">
              <Button 
                onClick={generateMapping} 
                disabled={loading || selectedControls.length === 0}
                className="w-full"
              >
                {loading ? (
                  <Clock className="w-4 h-4 mr-2 animate-spin" />
                ) : (
                  <ArrowRight className="w-4 h-4 mr-2" />
                )}
                Generate Mapping
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Implementation Plan Overview */}
      {implementationPlan && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Target className="w-5 h-5" />
              Implementation Plan
            </CardTitle>
            <CardDescription>
              Overview of STIG implementations required for CMMC Level {selectedCMMCLevel}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
              <div className="text-center">
                <div className="text-2xl font-bold text-primary">
                  {implementationPlan.total_stig_rules}
                </div>
                <div className="text-sm text-muted-foreground">Total STIG Rules</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-green-600">
                  {implementationPlan.automated_implementations}
                </div>
                <div className="text-sm text-muted-foreground">Automatable</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-orange-600">
                  {implementationPlan.manual_implementations}
                </div>
                <div className="text-sm text-muted-foreground">Manual</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-600">
                  {implementationPlan.estimated_effort_hours}h
                </div>
                <div className="text-sm text-muted-foreground">Est. Effort</div>
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span>Automation Coverage</span>
                <span>
                  {Math.round((implementationPlan.automated_implementations / implementationPlan.total_stig_rules) * 100)}%
                </span>
              </div>
              <Progress 
                value={(implementationPlan.automated_implementations / implementationPlan.total_stig_rules) * 100}
                className="h-2"
              />
            </div>
          </CardContent>
        </Card>
      )}

      {/* Mappings */}
      {mappings.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>CMMC Control Mappings</CardTitle>
            <CardDescription>
              Detailed STIG implementations for each CMMC control
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="overview" className="w-full">
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="overview">Overview</TabsTrigger>
                <TabsTrigger value="detailed">Detailed View</TabsTrigger>
              </TabsList>

              <TabsContent value="overview" className="space-y-4">
                <div className="grid gap-4">
                  {mappings.map((mapping, index) => (
                    <div key={index} className="p-4 border rounded-lg">
                      <div className="flex items-center justify-between mb-3">
                        <div className="font-medium">{mapping.cmmc_control}</div>
                        <Badge variant="outline">
                          {mapping.stig_implementations.length} STIG Rules
                        </Badge>
                      </div>
                      
                      <div className="flex flex-wrap gap-2">
                        {mapping.stig_implementations.slice(0, 3).map((impl, idx) => (
                          <Badge key={idx} variant="secondary">
                            {impl.stig_id}
                          </Badge>
                        ))}
                        {mapping.stig_implementations.length > 3 && (
                          <Badge variant="outline">
                            +{mapping.stig_implementations.length - 3} more
                          </Badge>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </TabsContent>

              <TabsContent value="detailed" className="space-y-4">
                {mappings.map((mapping, index) => (
                  <Card key={index}>
                    <CardHeader>
                      <CardTitle className="text-lg">{mapping.cmmc_control}</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-3">
                        {mapping.stig_implementations.map((impl, idx) => (
                          <div key={idx} className="p-3 border rounded-lg">
                            <div className="flex items-center justify-between mb-2">
                              <div className="font-medium">{impl.stig_id}</div>
                              <div className="flex gap-2">
                                {getAutomationBadge(impl.automation_possible)}
                                {getPriorityBadge(impl.priority_score)}
                              </div>
                            </div>
                            
                            <div className="text-sm text-muted-foreground mb-2">
                              Platform: {impl.platform}
                            </div>
                            
                            <p className="text-sm">{impl.implementation_guidance}</p>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      )}
    </div>
  );
};