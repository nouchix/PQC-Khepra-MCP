import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { 
  FileText, 
  Download, 
  Calendar, 
  BarChart3, 
  Shield, 
  AlertTriangle,
  TrendingUp,
  Clock,
  CheckCircle
} from 'lucide-react';
import { ComplianceMetrics } from '@/hooks/useSTIGCompliance';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';

interface STIGComplianceReportsProps {
  organizationId: string;
  metrics?: ComplianceMetrics | null;
}

interface ReportConfiguration {
  report_type: 'executive_summary' | 'detailed_findings' | 'remediation_plan' | 'compliance_attestation' | 'comprehensive';
  scope_assets: string[];
  include_sections: string[];
  format: 'pdf' | 'html' | 'json' | 'excel';
  classification: 'UNCLASSIFIED' | 'CUI' | 'CONFIDENTIAL' | 'SECRET';
  custom_title?: string;
  custom_description?: string;
}

interface GeneratedReport {
  id: string;
  report_name: string;
  report_type: string;
  generated_at: string;
  compliance_percentage: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  status: string;
}

export const STIGComplianceReports: React.FC<STIGComplianceReportsProps> = ({
  organizationId,
  metrics
}) => {
  const [assets, setAssets] = useState<any[]>([]);
  const [reports, setReports] = useState<GeneratedReport[]>([]);
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [reportConfig, setReportConfig] = useState<ReportConfiguration>({
    report_type: 'comprehensive',
    scope_assets: [],
    include_sections: ['executive_summary', 'findings', 'recommendations', 'appendices'],
    format: 'pdf',
    classification: 'UNCLASSIFIED'
  });
  const { toast } = useToast();

  // Load assets and reports on component mount
  useEffect(() => {
    loadAssets();
    loadReports();
  }, [organizationId]);

  const loadAssets = async () => {
    try {
      const { data, error } = await supabase
        .from('environment_assets')
        .select('id, asset_name, asset_type, platform')
        .eq('organization_id', organizationId)
        .order('asset_name');

      if (error) throw error;
      setAssets(data || []);
    } catch (error) {
      console.error('Error loading assets:', error);
    }
  };

  const loadReports = async () => {
    try {
      setLoading(true);
      const { data, error } = await supabase
        .from('compliance_reports')
        .select('*')
        .eq('organization_id', organizationId)
        .order('generated_at', { ascending: false })
        .limit(20);

      if (error) throw error;
      setReports(data || []);
    } catch (error) {
      console.error('Error loading reports:', error);
      toast({
        title: "Load Error",
        description: "Failed to load compliance reports",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const generateReport = async () => {
    try {
      setGenerating(true);
      
      const { data, error } = await supabase.functions.invoke('stig-compliance-orchestrator', {
        body: {
          action: 'generate_report',
          organization_id: organizationId,
          scope_assets: reportConfig.scope_assets.length > 0 ? reportConfig.scope_assets : undefined,
          report_type: reportConfig.report_type,
          configuration: reportConfig
        }
      });

      if (error) throw error;

      toast({
        title: "Report Generated",
        description: "STIG compliance report has been generated successfully",
      });

      // Refresh reports list
      await loadReports();

      // Reset configuration
      setReportConfig(prev => ({
        ...prev,
        scope_assets: [],
        custom_title: '',
        custom_description: ''
      }));

    } catch (error) {
      console.error('Error generating report:', error);
      toast({
        title: "Report Generation Failed",
        description: "Failed to generate compliance report",
        variant: "destructive"
      });
    } finally {
      setGenerating(false);
    }
  };

  const handleAssetSelection = (assetId: string, checked: boolean) => {
    setReportConfig(prev => ({
      ...prev,
      scope_assets: checked 
        ? [...prev.scope_assets, assetId]
        : prev.scope_assets.filter(id => id !== assetId)
    }));
  };

  const handleSectionToggle = (section: string, checked: boolean) => {
    setReportConfig(prev => ({
      ...prev,
      include_sections: checked
        ? [...prev.include_sections, section]
        : prev.include_sections.filter(s => s !== section)
    }));
  };

  const selectAllAssets = () => {
    setReportConfig(prev => ({
      ...prev,
      scope_assets: assets.map(asset => asset.id)
    }));
  };

  const getReportTypeDescription = (type: string) => {
    switch (type) {
      case 'executive_summary':
        return 'High-level overview for executive leadership';
      case 'detailed_findings':
        return 'Comprehensive technical findings and evidence';
      case 'remediation_plan':
        return 'Action plan for addressing findings';
      case 'compliance_attestation':
        return 'Formal compliance attestation document';
      case 'comprehensive':
        return 'Complete report with all sections';
      default:
        return 'Custom report configuration';
    }
  };

  const getComplianceColor = (percentage: number) => {
    if (percentage >= 90) return 'text-green-600';
    if (percentage >= 70) return 'text-yellow-600';
    return 'text-red-600';
  };

  const reportSections = [
    { id: 'executive_summary', name: 'Executive Summary', description: 'High-level compliance overview' },
    { id: 'findings', name: 'Detailed Findings', description: 'Complete STIG finding details' },
    { id: 'recommendations', name: 'Recommendations', description: 'Remediation recommendations' },
    { id: 'trends', name: 'Compliance Trends', description: 'Historical compliance data' },
    { id: 'risk_assessment', name: 'Risk Assessment', description: 'Security risk analysis' },
    { id: 'appendices', name: 'Technical Appendices', description: 'Supporting technical data' }
  ];

  return (
    <div className="space-y-6">
      {/* Report Metrics Overview */}
      {metrics && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card>
            <CardContent className="p-4 text-center">
              <div className="flex items-center justify-center gap-2 mb-2">
                <BarChart3 className="h-5 w-5 text-blue-600" />
                <p className="text-sm font-medium">Compliance Score</p>
              </div>
              <p className={`text-2xl font-bold ${getComplianceColor(metrics.overall_compliance_percentage)}`}>
                {metrics.overall_compliance_percentage}%
              </p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4 text-center">
              <div className="flex items-center justify-center gap-2 mb-2">
                <AlertTriangle className="h-5 w-5 text-red-600" />
                <p className="text-sm font-medium">Critical Issues</p>
              </div>
              <p className="text-2xl font-bold text-red-600">{metrics.critical_findings}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4 text-center">
              <div className="flex items-center justify-center gap-2 mb-2">
                <Shield className="h-5 w-5 text-green-600" />
                <p className="text-sm font-medium">Assets Covered</p>
              </div>
              <p className="text-2xl font-bold">{metrics.total_assets}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4 text-center">
              <div className="flex items-center justify-center gap-2 mb-2">
                <TrendingUp className="h-5 w-5 text-blue-600" />
                <p className="text-sm font-medium">Recent Scans</p>
              </div>
              <p className="text-2xl font-bold">{metrics.recent_scans}</p>
            </CardContent>
          </Card>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Report Configuration */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileText className="h-5 w-5" />
              Generate New Report
            </CardTitle>
            <CardDescription>
              Configure and generate a new STIG compliance report
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label htmlFor="report_type" className="text-sm font-medium">Report Type</Label>
              <Select
                value={reportConfig.report_type}
                onValueChange={(value) => setReportConfig(prev => ({ 
                  ...prev, 
                  report_type: value as any 
                }))}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="executive_summary">Executive Summary</SelectItem>
                  <SelectItem value="detailed_findings">Detailed Findings</SelectItem>
                  <SelectItem value="remediation_plan">Remediation Plan</SelectItem>
                  <SelectItem value="compliance_attestation">Compliance Attestation</SelectItem>
                  <SelectItem value="comprehensive">Comprehensive Report</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground mt-1">
                {getReportTypeDescription(reportConfig.report_type)}
              </p>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label htmlFor="format" className="text-sm font-medium">Format</Label>
                <Select
                  value={reportConfig.format}
                  onValueChange={(value) => setReportConfig(prev => ({ 
                    ...prev, 
                    format: value as any 
                  }))}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="pdf">PDF</SelectItem>
                    <SelectItem value="html">HTML</SelectItem>
                    <SelectItem value="json">JSON</SelectItem>
                    <SelectItem value="excel">Excel</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label htmlFor="classification" className="text-sm font-medium">Classification</Label>
                <Select
                  value={reportConfig.classification}
                  onValueChange={(value) => setReportConfig(prev => ({ 
                    ...prev, 
                    classification: value as any 
                  }))}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="UNCLASSIFIED">UNCLASSIFIED</SelectItem>
                    <SelectItem value="CUI">CUI</SelectItem>
                    <SelectItem value="CONFIDENTIAL">CONFIDENTIAL</SelectItem>
                    <SelectItem value="SECRET">SECRET</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div>
              <Label htmlFor="custom_title" className="text-sm font-medium">Custom Title (Optional)</Label>
              <Input
                id="custom_title"
                value={reportConfig.custom_title || ''}
                onChange={(e) => setReportConfig(prev => ({ 
                  ...prev, 
                  custom_title: e.target.value 
                }))}
                placeholder="Custom report title..."
              />
            </div>

            <div>
              <Label htmlFor="custom_description" className="text-sm font-medium">Description (Optional)</Label>
              <Textarea
                id="custom_description"
                value={reportConfig.custom_description || ''}
                onChange={(e) => setReportConfig(prev => ({ 
                  ...prev, 
                  custom_description: e.target.value 
                }))}
                placeholder="Report description or executive summary..."
                rows={3}
              />
            </div>

            {/* Report Sections */}
            <div>
              <Label className="text-sm font-medium">Include Sections</Label>
              <div className="grid grid-cols-1 gap-2 mt-2">
                {reportSections.map((section) => (
                  <label key={section.id} className="flex items-center space-x-2">
                    <Checkbox
                      checked={reportConfig.include_sections.includes(section.id)}
                      onCheckedChange={(checked) => 
                        handleSectionToggle(section.id, checked as boolean)
                      }
                    />
                    <div className="flex-1">
                      <p className="text-sm font-medium">{section.name}</p>
                      <p className="text-xs text-muted-foreground">{section.description}</p>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            {/* Asset Scope */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <Label className="text-sm font-medium">Asset Scope</Label>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={selectAllAssets}
                >
                  Select All ({assets.length})
                </Button>
              </div>
              <div className="max-h-32 overflow-y-auto border rounded p-2">
                {assets.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No assets available</p>
                ) : (
                  assets.map((asset) => (
                    <label key={asset.id} className="flex items-center space-x-2 py-1">
                      <Checkbox
                        checked={reportConfig.scope_assets.includes(asset.id)}
                        onCheckedChange={(checked) => 
                          handleAssetSelection(asset.id, checked as boolean)
                        }
                      />
                      <span className="text-sm">{asset.asset_name}</span>
                      <Badge variant="outline" className="text-xs">
                        {asset.asset_type}
                      </Badge>
                    </label>
                  ))
                )}
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                {reportConfig.scope_assets.length === 0 
                  ? 'All assets will be included' 
                  : `${reportConfig.scope_assets.length} assets selected`}
              </p>
            </div>

            <Button
              onClick={generateReport}
              disabled={generating}
              className="w-full"
            >
              <FileText className="h-4 w-4 mr-2" />
              {generating ? 'Generating Report...' : 'Generate Report'}
            </Button>
          </CardContent>
        </Card>

        {/* Recent Reports */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Calendar className="h-5 w-5" />
              Recent Reports
            </CardTitle>
            <CardDescription>
              Previously generated compliance reports
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3 max-h-96 overflow-y-auto">
              {loading ? (
                <div className="text-center py-8">
                  <Clock className="h-8 w-8 mx-auto text-muted-foreground animate-spin mb-4" />
                  <p>Loading reports...</p>
                </div>
              ) : reports.length === 0 ? (
                <div className="text-center py-8">
                  <FileText className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                  <p className="text-lg font-medium">No Reports Generated</p>
                  <p className="text-muted-foreground">
                    Generate your first compliance report to get started.
                  </p>
                </div>
              ) : (
                reports.map((report) => (
                  <div key={report.id} className="border rounded-lg p-4">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <h3 className="font-medium">{report.report_name}</h3>
                        <div className="flex items-center gap-2 mt-1">
                          <Badge variant="outline">{report.report_type.replaceAll('_', ' ')}</Badge>
                          <Badge className={`${getComplianceColor(report.compliance_percentage)} bg-transparent border`}>
                            {report.compliance_percentage}% compliant
                          </Badge>
                        </div>
                        <p className="text-sm text-muted-foreground mt-1">
                          Generated: {new Date(report.generated_at).toLocaleString()}
                        </p>
                        <div className="flex items-center gap-4 text-xs text-muted-foreground mt-2">
                          <span className="flex items-center gap-1">
                            <AlertTriangle className="h-3 w-3 text-red-500" />
                            {report.critical_findings} critical
                          </span>
                          <span className="flex items-center gap-1">
                            <AlertTriangle className="h-3 w-3 text-yellow-500" />
                            {report.high_findings} high
                          </span>
                          <span className="flex items-center gap-1">
                            <AlertTriangle className="h-3 w-3 text-blue-500" />
                            {report.medium_findings} medium
                          </span>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge 
                          variant={report.status === 'GENERATED' ? 'default' : 'secondary'}
                        >
                          {report.status}
                        </Badge>
                        <Button size="sm" variant="outline">
                          <Download className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Report Templates Info */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <BarChart3 className="h-5 w-5" />
            Report Templates
          </CardTitle>
          <CardDescription>
            Available compliance report templates and their contents
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div className="border rounded-lg p-4">
              <h3 className="font-medium mb-2">Executive Summary</h3>
              <p className="text-sm text-muted-foreground mb-3">
                High-level compliance overview for leadership and stakeholders.
              </p>
              <ul className="text-xs space-y-1">
                <li>• Compliance score overview</li>
                <li>• Critical findings summary</li>
                <li>• Risk assessment</li>
                <li>• Recommendations</li>
              </ul>
            </div>
            
            <div className="border rounded-lg p-4">
              <h3 className="font-medium mb-2">Detailed Findings</h3>
              <p className="text-sm text-muted-foreground mb-3">
                Technical report with complete STIG finding details.
              </p>
              <ul className="text-xs space-y-1">
                <li>• Complete finding inventory</li>
                <li>• Evidence documentation</li>
                <li>• Technical details</li>
                <li>• Remediation steps</li>
              </ul>
            </div>
            
            <div className="border rounded-lg p-4">
              <h3 className="font-medium mb-2">Remediation Plan</h3>
              <p className="text-sm text-muted-foreground mb-3">
                Action-oriented plan for addressing compliance gaps.
              </p>
              <ul className="text-xs space-y-1">
                <li>• Prioritized action items</li>
                <li>• Resource requirements</li>
                <li>• Timeline estimates</li>
                <li>• Success metrics</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};