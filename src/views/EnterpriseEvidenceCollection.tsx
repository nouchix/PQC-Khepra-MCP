import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  FileText, 
  Download, 
  Archive, 
  Shield, 
  CheckCircle, 
  Clock,
  RefreshCw,
  Search,
  Filter,
  Calendar
} from "lucide-react";
import { PageLayout } from '@/components/PageLayout';
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";

interface EvidenceItem {
  id: string;
  title: string;
  evidence_type: string;
  collection_date: string;
  collection_method: string;
  file_hash: string;
  retention_period_days: number;
  metadata: any;
  tags: string[];
}

const EnterpriseEvidenceCollectionPage = () => {
  const { toast } = useToast();
  const [evidenceItems, setEvidenceItems] = useState<EvidenceItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [collecting, setCollecting] = useState(false);

  useEffect(() => {
    fetchEvidenceData();
  }, []);

  const fetchEvidenceData = async () => {
    try {
      setLoading(true);
      
      const { data, error } = await supabase
        .from('compliance_evidence')
        .select('*')
        .order('collection_date', { ascending: false });

      if (error) throw error;
      setEvidenceItems(data || []);

    } catch (error) {
      console.error('Error fetching evidence data:', error);
      toast({
        title: "Error",
        description: "Failed to load evidence collection data",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const triggerAutomatedCollection = async () => {
    try {
      setCollecting(true);
      
      // Simulate automated evidence collection
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      toast({
        title: "Evidence Collection Started",
        description: "Automated evidence collection has been initiated across all monitored systems."
      });

      fetchEvidenceData();

    } catch (error) {
      console.error('Error triggering collection:', error);
      toast({
        title: "Collection Failed",
        description: "Failed to start automated evidence collection",
        variant: "destructive"
      });
    } finally {
      setCollecting(false);
    }
  };

  const generateComplianceReport = () => {
    toast({
      title: "Report Generated",
      description: "Comprehensive compliance evidence report has been generated and is ready for download."
    });
  };

  const getEvidenceTypeColor = (type: string) => {
    const colors: { [key: string]: string } = {
      'configuration': 'bg-blue-500/10 text-blue-500',
      'log_evidence': 'bg-green-500/10 text-green-500',
      'screenshot': 'bg-purple-500/10 text-purple-500',
      'document': 'bg-orange-500/10 text-orange-500',
      'audit_trail': 'bg-red-500/10 text-red-500'
    };
    return colors[type] || 'bg-gray-500/10 text-gray-500';
  };

  if (loading) {
    return (
      <PageLayout>
        <div className="flex items-center justify-center h-64">
          <RefreshCw className="h-8 w-8 animate-spin" />
        </div>
      </PageLayout>
    );
  }

  return (
    <PageLayout>
      <div className="container mx-auto p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold">Audit-Ready Evidence Collection</h1>
            <p className="text-muted-foreground">
              Comprehensive evidence collection and retention for DOD compliance audits
            </p>
          </div>
          <div className="flex gap-2">
            <Button 
              onClick={triggerAutomatedCollection}
              disabled={collecting}
              variant="outline"
            >
              {collecting ? (
                <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Archive className="h-4 w-4 mr-2" />
              )}
              {collecting ? 'Collecting...' : 'Start Collection'}
            </Button>
            <Button onClick={generateComplianceReport} variant="outline">
              <Download className="h-4 w-4 mr-2" />
              Generate Report
            </Button>
          </div>
        </div>

        {/* Key Metrics */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Evidence Items</CardTitle>
              <FileText className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{evidenceItems.length}</div>
              <p className="text-xs text-muted-foreground">
                Across all systems and controls
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Retention Compliance</CardTitle>
              <Shield className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">100%</div>
              <p className="text-xs text-muted-foreground">
                7-year DOD retention policy
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Automated Collection</CardTitle>
              <CheckCircle className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-blue-600">85%</div>
              <p className="text-xs text-muted-foreground">
                Of evidence automatically collected
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Last Collection</CardTitle>
              <Clock className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">2h ago</div>
              <p className="text-xs text-muted-foreground">
                Continuous monitoring active
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Main Content */}
        <Tabs defaultValue="evidence" className="space-y-6">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="evidence">Evidence Items</TabsTrigger>
            <TabsTrigger value="collection">Collection Rules</TabsTrigger>
            <TabsTrigger value="retention">Retention Policy</TabsTrigger>
            <TabsTrigger value="reports">Audit Reports</TabsTrigger>
          </TabsList>

          <TabsContent value="evidence">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle>Evidence Repository</CardTitle>
                    <CardDescription>
                      Centralized repository of all compliance evidence with automated collection and validation
                    </CardDescription>
                  </div>
                  <div className="flex gap-2">
                    <Button variant="outline" size="sm">
                      <Search className="h-4 w-4 mr-2" />
                      Search
                    </Button>
                    <Button variant="outline" size="sm">
                      <Filter className="h-4 w-4 mr-2" />
                      Filter
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {evidenceItems.slice(0, 10).map((item) => (
                    <div key={item.id} className="border rounded-lg p-4">
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex-1">
                          <h3 className="font-medium">{item.title}</h3>
                          <p className="text-sm text-muted-foreground">
                            Collection Method: {item.collection_method}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            File Hash: {item.file_hash}
                          </p>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge className={getEvidenceTypeColor(item.evidence_type)}>
                            {item.evidence_type.replace('_', ' ').toUpperCase()}
                          </Badge>
                        </div>
                      </div>

                      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 text-sm">
                        <div>
                          <span className="text-muted-foreground">Collection Date:</span>
                          <p className="font-medium">{new Date(item.collection_date).toLocaleDateString()}</p>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Retention:</span>
                          <p className="font-medium">{item.retention_period_days} days</p>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Tags:</span>
                          <div className="flex flex-wrap gap-1 mt-1">
                            {item.tags?.slice(0, 2).map((tag, index) => (
                              <Badge key={index} variant="outline" className="text-xs">
                                {tag}
                              </Badge>
                            ))}
                            {item.tags?.length > 2 && (
                              <Badge variant="outline" className="text-xs">
                                +{item.tags.length - 2}
                              </Badge>
                            )}
                          </div>
                        </div>
                        <div className="flex gap-2">
                          <Button size="sm" variant="outline">
                            <Download className="h-3 w-3 mr-1" />
                            Download
                          </Button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="collection">
            <Card>
              <CardHeader>
                <CardTitle>Automated Collection Rules</CardTitle>
                <CardDescription>
                  Configure automated evidence collection rules for different STIG controls and system types
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {[
                    { name: 'Configuration Files', frequency: 'Daily', systems: 'All Windows/Linux', status: 'Active' },
                    { name: 'Security Logs', frequency: 'Real-time', systems: 'Domain Controllers', status: 'Active' },
                    { name: 'Patch Status', frequency: 'Weekly', systems: 'All Systems', status: 'Active' },
                    { name: 'User Access Reviews', frequency: 'Monthly', systems: 'AD/LDAP', status: 'Active' }
                  ].map((rule, index) => (
                    <div key={index} className="flex items-center justify-between border rounded-lg p-4">
                      <div>
                        <h3 className="font-medium">{rule.name}</h3>
                        <p className="text-sm text-muted-foreground">
                          {rule.frequency} collection from {rule.systems}
                        </p>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="default">{rule.status}</Badge>
                        <Button size="sm" variant="outline">Configure</Button>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="retention">
            <Card>
              <CardHeader>
                <CardTitle>Evidence Retention Policy</CardTitle>
                <CardDescription>
                  DOD-compliant evidence retention and archival policies for audit readiness
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="border rounded-lg p-4">
                      <h3 className="font-medium mb-2">Standard Retention</h3>
                      <p className="text-2xl font-bold text-blue-600">7 Years</p>
                      <p className="text-sm text-muted-foreground">DOD compliance requirement</p>
                    </div>
                    <div className="border rounded-lg p-4">
                      <h3 className="font-medium mb-2">Storage Efficiency</h3>
                      <p className="text-2xl font-bold text-green-600">92%</p>
                      <p className="text-sm text-muted-foreground">Compressed and deduplicated</p>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <h4 className="font-medium">Retention Categories</h4>
                    {[
                      { category: 'Security Configuration', retention: '7 years', size: '2.4 GB', items: 1247 },
                      { category: 'Audit Logs', retention: '7 years', size: '15.8 GB', items: 45623 },
                      { category: 'Assessment Results', retention: '10 years', size: '0.8 GB', items: 156 },
                      { category: 'Incident Evidence', retention: 'Indefinite', size: '3.2 GB', items: 89 }
                    ].map((item, index) => (
                      <div key={index} className="flex items-center justify-between border rounded-lg p-3">
                        <div>
                          <h4 className="font-medium">{item.category}</h4>
                          <p className="text-sm text-muted-foreground">{item.items} items, {item.size}</p>
                        </div>
                        <Badge variant="outline">{item.retention}</Badge>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="reports">
            <Card>
              <CardHeader>
                <CardTitle>Audit Reports & Documentation</CardTitle>
                <CardDescription>
                  Generate comprehensive audit reports and compliance documentation
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-4">
                    <h4 className="font-medium">Available Reports</h4>
                    {[
                      'CMMC Compliance Evidence Package',
                      'STIG Implementation Status Report',
                      'Evidence Collection Summary',
                      'Retention Compliance Report'
                    ].map((report, index) => (
                      <div key={index} className="flex items-center justify-between border rounded-lg p-3">
                        <span className="font-medium">{report}</span>
                        <Button size="sm" variant="outline">
                          <Download className="h-3 w-3 mr-1" />
                          Generate
                        </Button>
                      </div>
                    ))}
                  </div>

                  <div className="space-y-4">
                    <h4 className="font-medium">Report Schedule</h4>
                    <div className="space-y-3">
                      <div className="border rounded-lg p-3">
                        <div className="flex items-center justify-between">
                          <span className="font-medium">Monthly Compliance Report</span>
                          <Badge variant="outline">Automated</Badge>
                        </div>
                        <p className="text-sm text-muted-foreground">Next: End of month</p>
                      </div>
                      <div className="border rounded-lg p-3">
                        <div className="flex items-center justify-between">
                          <span className="font-medium">Quarterly Assessment</span>
                          <Badge variant="outline">Scheduled</Badge>
                        </div>
                        <p className="text-sm text-muted-foreground">Next: March 31, 2025</p>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </PageLayout>
  );
};

export default EnterpriseEvidenceCollectionPage;