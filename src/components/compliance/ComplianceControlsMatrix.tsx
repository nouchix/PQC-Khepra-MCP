import { useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Search,
  Filter,
  Download,
  Shield,
  CheckCircle,
  AlertTriangle,
  Clock,
  Eye,
  Edit
} from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

interface ComplianceControl {
  id: string;
  control_id: string;
  title: string;
  family: string;
  implementation_status: 'IMPLEMENTED' | 'PARTIAL' | 'NOT_IMPLEMENTED' | 'NOT_APPLICABLE';
  test_status: 'PASSED' | 'FAILED' | 'NOT_TESTED';
  priority: 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  implementation_guidance: string;
  evidence_required: string[];
  last_tested: string;
  next_test_due: string;
  responsible_party: string;
}

export const ComplianceControlsMatrix = () => {
  const [searchTerm, setSearchTerm] = useState("");
  const [filterFamily, setFilterFamily] = useState("ALL");
  const [filterStatus, setFilterStatus] = useState("ALL");

  // Awaiting telemetry for real data
  const pendingControls: ComplianceControl[] = [];

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'IMPLEMENTED': return <CheckCircle className="h-4 w-4 text-green-400" />;
      case 'PARTIAL': return <Clock className="h-4 w-4 text-yellow-400" />;
      case 'NOT_IMPLEMENTED': return <AlertTriangle className="h-4 w-4 text-red-400" />;
      case 'PASSED': return <CheckCircle className="h-4 w-4 text-green-400" />;
      case 'FAILED': return <AlertTriangle className="h-4 w-4 text-red-400" />;
      case 'NOT_TESTED': return <Clock className="h-4 w-4 text-gray-400" />;
      default: return <Shield className="h-4 w-4 text-gray-400" />;
    }
  };

  const getStatusBadge = (status: string, type: 'implementation' | 'test') => {
    const implementationVariants = {
      'IMPLEMENTED': 'bg-green-500/20 text-green-400 border-green-500/30',
      'PARTIAL': 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
      'NOT_IMPLEMENTED': 'bg-red-500/20 text-red-400 border-red-500/30',
      'NOT_APPLICABLE': 'bg-gray-500/20 text-gray-400 border-gray-500/30'
    };

    const testVariants = {
      'PASSED': 'bg-green-500/20 text-green-400 border-green-500/30',
      'FAILED': 'bg-red-500/20 text-red-400 border-red-500/30',
      'NOT_TESTED': 'bg-gray-500/20 text-gray-400 border-gray-500/30'
    };

    const variants = type === 'implementation' ? implementationVariants : testVariants;
    return variants[status as keyof typeof variants] || (type === 'implementation' ? implementationVariants.NOT_APPLICABLE : testVariants.NOT_TESTED);
  };

  const filteredControls = pendingControls.filter(control => {
    const matchesSearch = control.control_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      control.title.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesFamily = filterFamily === "ALL" || control.family === filterFamily;
    const matchesStatus = filterStatus === "ALL" || control.implementation_status === filterStatus;

    return matchesSearch && matchesFamily && matchesStatus;
  });

  const families = [...new Set(pendingControls.map(c => c.family))];

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card className="bg-gradient-to-r from-blue-900/40 to-purple-900/40 border-blue-500/30">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-white text-2xl">
                Compliance Controls Matrix
              </CardTitle>
              <p className="text-gray-300 mt-1">
                CMMC 2.0 Level 2 Controls Status and Testing
              </p>
            </div>
            <Button className="bg-blue-600 hover:bg-blue-700">
              <Download className="h-4 w-4 mr-2" />
              Export Matrix
            </Button>
          </div>
        </CardHeader>
      </Card>

      {/* Filters */}
      <Card className="bg-black/40 border-slate-700/50">
        <CardContent className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
              <Input
                placeholder="Search controls..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10 bg-slate-800 border-slate-600 text-white"
              />
            </div>

            <select
              value={filterFamily}
              onChange={(e) => setFilterFamily(e.target.value)}
              className="px-3 py-2 bg-slate-800 border border-slate-600 rounded-md text-white"
            >
              <option value="ALL">All Families</option>
              {families.map(family => (
                <option key={family} value={family}>{family}</option>
              ))}
            </select>

            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="px-3 py-2 bg-slate-800 border border-slate-600 rounded-md text-white"
            >
              <option value="ALL">All Statuses</option>
              <option value="IMPLEMENTED">Implemented</option>
              <option value="PARTIAL">Partial</option>
              <option value="NOT_IMPLEMENTED">Not Implemented</option>
            </select>

            <div className="flex items-center text-gray-300">
              <Filter className="h-4 w-4 mr-2" />
              Showing {filteredControls.length} of {pendingControls.length} controls
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Controls Matrix */}
      <div className="space-y-4">
        {filteredControls.map((control) => (
          <Card key={control.id} className="bg-black/40 border-slate-700/50 hover:border-blue-500/30 transition-colors">
            <CardContent className="p-6">
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
                {/* Control Info */}
                <div className="lg:col-span-4">
                  <div className="flex items-center space-x-2 mb-2">
                    <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30">
                      {control.control_id}
                    </Badge>
                    <Badge className={
                      control.priority === 'HIGH'
                        ? 'bg-red-500/20 text-red-400 border-red-500/30'
                        : control.priority === 'MEDIUM'
                          ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
                          : 'bg-gray-500/20 text-gray-400 border-gray-500/30'
                    }>
                      {control.priority}
                    </Badge>
                  </div>
                  <h3 className="text-white font-semibold mb-1">{control.title}</h3>
                  <p className="text-gray-400 text-sm">{control.family}</p>
                </div>

                {/* Implementation Status */}
                <div className="lg:col-span-2">
                  <div className="text-xs text-gray-400 mb-1">Implementation</div>
                  <div className="flex items-center space-x-2">
                    {getStatusIcon(control.implementation_status)}
                    <Badge className={getStatusBadge(control.implementation_status, 'implementation')}>
                      {control.implementation_status.replaceAll('_', ' ')}
                    </Badge>
                  </div>
                </div>

                {/* Test Status */}
                <div className="lg:col-span-2">
                  <div className="text-xs text-gray-400 mb-1">Test Status</div>
                  <div className="flex items-center space-x-2">
                    {getStatusIcon(control.test_status)}
                    <Badge className={getStatusBadge(control.test_status, 'test')}>
                      {control.test_status.replaceAll('_', ' ')}
                    </Badge>
                  </div>
                </div>

                {/* Testing Dates */}
                <div className="lg:col-span-2">
                  <div className="text-xs text-gray-400 mb-1">Last Tested</div>
                  <div className="text-white text-sm">{control.last_tested}</div>
                  <div className="text-xs text-gray-400 mt-1">Next Due</div>
                  <div className="text-blue-400 text-sm">{control.next_test_due}</div>
                </div>

                {/* Actions */}
                <div className="lg:col-span-2 flex items-center space-x-2">
                  <Button size="sm" variant="outline" className="border-slate-600 text-white hover:bg-slate-700">
                    <Eye className="h-3 w-3 mr-1" />
                    View
                  </Button>
                  <Button size="sm" variant="outline" className="border-slate-600 text-white hover:bg-slate-700">
                    <Edit className="h-3 w-3 mr-1" />
                    Edit
                  </Button>
                </div>
              </div>

              {/* Expandable Details */}
              <div className="mt-4 pt-4 border-t border-slate-700">
                <Tabs defaultValue="description" className="w-full">
                  <TabsList className="grid w-full grid-cols-3 bg-slate-800/50">
                    <TabsTrigger value="description">Description</TabsTrigger>
                    <TabsTrigger value="guidance">Guidance</TabsTrigger>
                    <TabsTrigger value="evidence">Evidence</TabsTrigger>
                  </TabsList>

                  <TabsContent value="description" className="mt-4">
                    <p className="text-gray-300 text-sm">{control.description}</p>
                  </TabsContent>

                  <TabsContent value="guidance" className="mt-4">
                    <p className="text-gray-300 text-sm">{control.implementation_guidance}</p>
                    <div className="mt-2">
                      <span className="text-blue-400 text-xs">Responsible: </span>
                      <span className="text-white text-sm">{control.responsible_party}</span>
                    </div>
                  </TabsContent>

                  <TabsContent value="evidence" className="mt-4">
                    <div className="flex flex-wrap gap-2">
                      {control.evidence_required.map((evidence) => (
                        <Badge key={evidence} className="bg-purple-500/20 text-purple-400 border-purple-500/30">
                          {evidence}
                        </Badge>
                      ))}
                    </div>
                  </TabsContent>
                </Tabs>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Summary Stats */}
      <Card className="bg-black/40 border-slate-700/50">
        <CardHeader>
          <CardTitle className="text-white">Matrix Summary</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-green-400">
                {pendingControls.filter(c => c.implementation_status === 'IMPLEMENTED').length}
              </div>
              <div className="text-sm text-gray-400">Implemented</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-yellow-400">
                {pendingControls.filter(c => c.implementation_status === 'PARTIAL').length}
              </div>
              <div className="text-sm text-gray-400">Partial</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-red-400">
                {pendingControls.filter(c => c.implementation_status === 'NOT_IMPLEMENTED').length}
              </div>
              <div className="text-sm text-gray-400">Not Implemented</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-400">
                {pendingControls.length > 0 ? Math.round((pendingControls.filter(c => c.implementation_status === 'IMPLEMENTED').length / pendingControls.length) * 100) : 0}%
              </div>
              <div className="text-sm text-gray-400">Overall Progress</div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};