
import { ConsoleLayout } from '@/components/console/ConsoleLayout';
import { DashboardToggle } from '@/components/DashboardToggle';
import { useOrganizationContext } from '@/components/OrganizationProvider';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { FileText, Download, Upload, Calendar, Shield } from 'lucide-react';

const EvidenceCollectionMVP = () => {
  const { currentOrganization } = useOrganizationContext();

  const tabs = [
    { id: 'stig-dashboard', title: 'STIG Dashboard', path: '/stig-dashboard' },
    { id: 'asset-scanning', title: 'Asset Scanning', path: '/asset-scanning' },
    { id: 'compliance-reports', title: 'Reports', path: '/compliance-reports' },
    { id: 'evidence-collection', title: 'Evidence', path: '/evidence-collection', isActive: true },
    { id: 'billing', title: 'Billing', path: '/billing' },
  ];

  // Mock evidence data
  const evidenceItems = [
    {
      id: '1',
      title: 'System Configuration Snapshot',
      type: 'Configuration',
      stig_rule: 'RHEL-08-010020',
      collection_date: '2024-01-15',
      status: 'collected',
      description: 'Current system configuration state for password policy compliance'
    },
    {
      id: '2',
      title: 'Access Control List Export',
      type: 'Access Control',
      stig_rule: 'RHEL-08-020240',
      collection_date: '2024-01-14',
      status: 'pending',
      description: 'User access permissions and group memberships'
    },
    {
      id: '3',
      title: 'Audit Log Sample',
      type: 'Audit Log',
      stig_rule: 'RHEL-08-030180',
      collection_date: '2024-01-13',
      status: 'collected',
      description: 'System audit trail for security events monitoring'
    }
  ];

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'collected': return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'pending': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'failed': return 'bg-red-500/20 text-red-400 border-red-500/30';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

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
                  <p className="text-2xl font-bold text-foreground">156</p>
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
                  <p className="text-2xl font-bold text-green-400">23</p>
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
                  <p className="text-2xl font-bold text-yellow-400">8</p>
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
                  <p className="text-2xl font-bold text-primary">142</p>
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
            <div className="space-y-4">
              {evidenceItems.map((item) => (
                <div key={item.id} className="flex items-center justify-between p-4 border border-border rounded-lg">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3">
                      <h3 className="font-medium text-foreground">{item.title}</h3>
                      <Badge variant="outline">{item.type}</Badge>
                      <Badge 
                        variant="outline" 
                        className={getStatusColor(item.status)}
                      >
                        {item.status}
                      </Badge>
                    </div>
                    <p className="text-sm text-muted-foreground mt-1">{item.description}</p>
                    <div className="flex items-center space-x-4 mt-2 text-xs text-muted-foreground">
                      <span>STIG Rule: {item.stig_rule}</span>
                      <span>Collected: {item.collection_date}</span>
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
          </CardContent>
        </Card>
      </div>
    </ConsoleLayout>
  );
};

export default EvidenceCollectionMVP;