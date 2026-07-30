
import { useEffect, useState } from 'react';
import { ConsoleLayout } from '@/components/console/ConsoleLayout';
import { DashboardToggle } from '@/components/DashboardToggle';
import { useOrganizationContext } from '@/components/OrganizationProvider';
import { supabase } from '@/integrations/supabase/client';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { FileText, Download, Upload, Calendar, Shield, Loader2 } from 'lucide-react';

interface EvidenceRow {
  id: string;
  title: string;
  description: string | null;
  evidence_type: string;
  collection_method: string | null;
  collection_date: string;
}

const EvidenceCollectionMVP = () => {
  const { currentOrganization: _currentOrganization } = useOrganizationContext();

  const [evidenceItems, setEvidenceItems] = useState<EvidenceRow[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchEvidence();
  }, []);

  const fetchEvidence = async () => {
    try {
      setLoading(true);
      const { data, error } = await supabase
        .from('compliance_evidence')
        .select('id, title, description, evidence_type, collection_method, collection_date')
        .order('collection_date', { ascending: false })
        .limit(25);

      if (error) throw error;
      setEvidenceItems(data || []);
    } catch (error) {
      console.error('Failed to load evidence collection data:', error);
      setEvidenceItems([]);
    } finally {
      setLoading(false);
    }
  };

  const tabs = [
    { id: 'stig-dashboard', title: 'STIG Dashboard', path: '/stig-dashboard' },
    { id: 'asset-scanning', title: 'Asset Scanning', path: '/asset-scanning' },
    { id: 'compliance-reports', title: 'Reports', path: '/compliance-reports' },
    { id: 'evidence-collection', title: 'Evidence', path: '/evidence-collection', isActive: true },
    { id: 'billing', title: 'Billing', path: '/billing' },
  ];

  const collectedToday = evidenceItems.filter((item) => {
    if (!item.collection_date) return false;
    const collected = new Date(item.collection_date);
    const now = new Date();
    return (
      collected.getFullYear() === now.getFullYear() &&
      collected.getMonth() === now.getMonth() &&
      collected.getDate() === now.getDate()
    );
  }).length;

  return (
    <ConsoleLayout
      currentSection="evidence-collection"
      browserNav={{
        title: 'Evidence Collection',
        subtitle: 'Automated STIG compliance evidence gathering',
        tabs,
        showAddTab: false,
        rightContent: <DashboardToggle />
      }}
    >
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground">Evidence Collection</h1>
            <p className="text-muted-foreground">Automated collection and management of STIG compliance evidence</p>
          </div>
          <div className="flex space-x-3">
            <Button variant="outline" className="flex items-center space-x-2">
              <Upload className="h-4 w-4" />
              <span>Upload Evidence</span>
            </Button>
            <Button className="flex items-center space-x-2 bg-primary">
              <Shield className="h-4 w-4" />
              <span>Auto-Collect</span>
            </Button>
          </div>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Total Evidence</p>
                  <p className="text-2xl font-bold text-foreground">{loading ? '--' : evidenceItems.length}</p>
                </div>
                <FileText className="h-8 w-8 text-primary" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Collected Today</p>
                  <p className="text-2xl font-bold text-green-400">{loading ? '--' : collectedToday}</p>
                </div>
                <Download className="h-8 w-8 text-green-400" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Pending Collection</p>
                  <p className="text-2xl font-bold text-yellow-400">--</p>
                  <p className="text-xs text-muted-foreground mt-1">Not tracked yet</p>
                </div>
                <Calendar className="h-8 w-8 text-yellow-400" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">STIG Rules Covered</p>
                  <p className="text-2xl font-bold text-primary">--</p>
                  <p className="text-xs text-muted-foreground mt-1">Not tracked yet</p>
                </div>
                <Shield className="h-8 w-8 text-primary" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Evidence List */}
        <Card>
          <CardHeader>
            <CardTitle>Recent Evidence</CardTitle>
            <CardDescription>
              Latest collected compliance evidence for STIG implementation
            </CardDescription>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="flex items-center justify-center py-12 text-muted-foreground">
                <Loader2 className="h-6 w-6 animate-spin mr-2" />
                Loading evidence...
              </div>
            ) : evidenceItems.length === 0 ? (
              <div className="text-center py-12 text-muted-foreground">
                <FileText className="h-10 w-10 mx-auto mb-3 opacity-50" />
                <p>No evidence has been collected yet.</p>
                <p className="text-sm">Use Auto-Collect or Upload Evidence to get started.</p>
              </div>
            ) : (
              <div className="space-y-4">
                {evidenceItems.map((item) => (
                  <div key={item.id} className="flex items-center justify-between p-4 border border-border rounded-lg">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3">
                        <h3 className="font-medium text-foreground">{item.title}</h3>
                        <Badge variant="outline">{item.evidence_type}</Badge>
                      </div>
                      {item.description && (
                        <p className="text-sm text-muted-foreground mt-1">{item.description}</p>
                      )}
                      <div className="flex items-center space-x-4 mt-2 text-xs text-muted-foreground">
                        {item.collection_method && <span>Method: {item.collection_method}</span>}
                        <span>Collected: {new Date(item.collection_date).toLocaleDateString()}</span>
                      </div>
                    </div>
                    <div className="flex space-x-2">
                      <Button variant="outline" size="sm">
                        <Download className="h-4 w-4" />
                      </Button>
                      <Button variant="outline" size="sm">
                        <FileText className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </ConsoleLayout>
  );
};

export default EvidenceCollectionMVP;
