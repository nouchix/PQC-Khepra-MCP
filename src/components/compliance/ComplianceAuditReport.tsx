import { useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  FileText,
  Download,
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  TrendingUp,
  BarChart3
} from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

interface ComplianceGap {
  id: string;
  control_id: string;
  title: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'OPEN' | 'IN_PROGRESS' | 'CLOSED';
  finding: string;
  recommendation: string;
  target_date: string;
}

interface AuditReportData {
  assessment_name: string;
  framework: string;
  assessment_date: string;
  overall_score: number;
  compliance_level: string;
  total_controls: number;
  implemented_controls: number;
  gaps: ComplianceGap[];
  executive_summary: string;
}

export const ComplianceAuditReport = () => {
  const [activeReport, setActiveReport] = useState<string>("executive");

  // Awaiting telemetry for real report data
  const reportData: AuditReportData = {
    assessment_name: "Pending Assessment",
    framework: "Pending Framework",
    assessment_date: "Pending",
    overall_score: 0,
    compliance_level: "Pending Execution",
    total_controls: 0,
    implemented_controls: 0,
    gaps: [],
    executive_summary: "Awaiting telemetry to generate executive summary."
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'HIGH': return <AlertTriangle className="h-4 w-4 text-red-400" />;
      case 'MEDIUM': return <Clock className="h-4 w-4 text-yellow-400" />;
      case 'LOW': return <CheckCircle className="h-4 w-4 text-green-400" />;
      default: return <Shield className="h-4 w-4 text-gray-400" />;
    }
  };

  const getStatusBadge = (status: string) => {
    const variants = {
      'OPEN': 'bg-red-500/20 text-red-400 border-red-500/30',
      'IN_PROGRESS': 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
      'CLOSED': 'bg-green-500/20 text-green-400 border-green-500/30'
    };
    return variants[status as keyof typeof variants] || variants.OPEN;
  };

  const exportReport = (format: 'pdf' | 'xlsx') => {
    // Implementation would generate and download report
    console.log(`Exporting report as ${format}`);
  };

  return (
    <div className="space-y-6">
      {/* Report Header */}
      <Card className="bg-gradient-to-r from-blue-900/40 to-purple-900/40 border-blue-500/30">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-white text-2xl">
                {reportData.assessment_name}
              </CardTitle>
              <p className="text-gray-300 mt-1">
                Framework: {reportData.framework} | Assessment Date: {reportData.assessment_date}
              </p>
            </div>
            <div className="flex items-center space-x-3">
              <Button onClick={() => exportReport('pdf')} className="bg-blue-600 hover:bg-blue-700">
                <Download className="h-4 w-4 mr-2" />
                Export PDF
              </Button>
              <Button
                onClick={() => exportReport('xlsx')}
                variant="outline"
                className="border-blue-500/30 text-blue-400 hover:bg-blue-500/10"
              >
                <FileText className="h-4 w-4 mr-2" />
                Export Excel
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="text-center">
              <div className="text-3xl font-bold text-white">{reportData.overall_score}%</div>
              <div className="text-sm text-gray-400">Overall Score</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-green-400">{reportData.implemented_controls}</div>
              <div className="text-sm text-gray-400">Controls Implemented</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-yellow-400">{reportData.total_controls - reportData.implemented_controls}</div>
              <div className="text-sm text-gray-400">Gaps Identified</div>
            </div>
            <div className="text-center">
              <Badge className="bg-green-500/20 text-green-400 border-green-500/30 text-lg px-4 py-2">
                {reportData.compliance_level}
              </Badge>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Report Content */}
      <Tabs value={activeReport} onValueChange={setActiveReport}>
        <TabsList className="grid w-full grid-cols-4 bg-black/40 border-slate-700">
          <TabsTrigger value="executive" className="data-[state=active]:bg-blue-600">
            <TrendingUp className="h-4 w-4 mr-2" />
            Executive Summary
          </TabsTrigger>
          <TabsTrigger value="detailed" className="data-[state=active]:bg-blue-600">
            <BarChart3 className="h-4 w-4 mr-2" />
            Detailed Findings
          </TabsTrigger>
          <TabsTrigger value="gaps" className="data-[state=active]:bg-blue-600">
            <AlertTriangle className="h-4 w-4 mr-2" />
            Gap Analysis
          </TabsTrigger>
          <TabsTrigger value="recommendations" className="data-[state=active]:bg-blue-600">
            <CheckCircle className="h-4 w-4 mr-2" />
            Recommendations
          </TabsTrigger>
        </TabsList>

        <TabsContent value="executive" className="space-y-6 mt-6">
          <Card className="bg-black/40 border-slate-700/50">
            <CardHeader>
              <CardTitle className="text-white">Executive Summary</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-300 leading-relaxed">
                {reportData.executive_summary}
              </p>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
                <div className="text-center p-4 bg-green-500/10 rounded-lg border border-green-500/20">
                  <div className="text-2xl font-bold text-green-400">{reportData.implemented_controls}</div>
                  <div className="text-sm text-gray-400">Controls Implemented</div>
                </div>
                <div className="text-center p-4 bg-yellow-500/10 rounded-lg border border-yellow-500/20">
                  <div className="text-2xl font-bold text-yellow-400">{reportData.total_controls - reportData.implemented_controls}</div>
                  <div className="text-sm text-gray-400">Gaps To Address</div>
                </div>
                <div className="text-center p-4 bg-blue-500/10 rounded-lg border border-blue-500/20">
                  <div className="text-2xl font-bold text-blue-400">0</div>
                  <div className="text-sm text-gray-400">Days to Target</div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="gaps" className="space-y-6 mt-6">
          <div className="space-y-4">
            {reportData.gaps.map((gap) => (
              <Card key={gap.id} className="bg-black/40 border-slate-700/50">
                <CardContent className="p-6">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        {getSeverityIcon(gap.severity)}
                        <h3 className="text-white font-semibold">{gap.control_id}: {gap.title}</h3>
                        <Badge className={getStatusBadge(gap.status)}>
                          {gap.status.replaceAll('_', ' ')}
                        </Badge>
                      </div>

                      <div className="space-y-2">
                        <div>
                          <span className="text-gray-400 text-sm font-medium">Finding: </span>
                          <span className="text-gray-300">{gap.finding}</span>
                        </div>
                        <div>
                          <span className="text-gray-400 text-sm font-medium">Recommendation: </span>
                          <span className="text-gray-300">{gap.recommendation}</span>
                        </div>
                        <div>
                          <span className="text-gray-400 text-sm font-medium">Target Date: </span>
                          <span className="text-blue-400">{gap.target_date}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="detailed" className="space-y-6 mt-6">
          <Card className="bg-black/40 border-slate-700/50">
            <CardHeader>
              <CardTitle className="text-white">Control Family Breakdown</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {[{ family: 'Pending Families', implemented: 0, total: 0, percentage: 0 }].map((family) => (
                  <div key={family.family} className="space-y-2">
                    <div className="flex justify-between">
                      <span className="text-gray-300">{family.family}</span>
                      <span className="text-white">{family.implemented}/{family.total} ({family.percentage}%)</span>
                    </div>
                    <div className="w-full bg-gray-700 rounded-full h-2">
                      <div
                        className="bg-blue-600 h-2 rounded-full"
                        style={{ width: `${family.percentage}%` }}
                      ></div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="recommendations" className="space-y-6 mt-6">
          <Card className="bg-black/40 border-slate-700/50">
            <CardHeader>
              <CardTitle className="text-white">Priority Recommendations</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
                  <h4 className="text-red-400 font-semibold mb-2">High Priority</h4>
                  <ul className="space-y-1 text-gray-300">
                    <li>Pending evaluation</li>
                  </ul>
                </div>

                <div className="p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
                  <h4 className="text-yellow-400 font-semibold mb-2">Medium Priority</h4>
                  <ul className="space-y-1 text-gray-300">
                    <li>Pending evaluation</li>
                  </ul>
                </div>

                <div className="p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg">
                  <h4 className="text-blue-400 font-semibold mb-2">Low Priority</h4>
                  <ul className="space-y-1 text-gray-300">
                    <li>Pending evaluation</li>
                  </ul>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};