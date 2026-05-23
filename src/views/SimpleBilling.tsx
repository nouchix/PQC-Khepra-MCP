
import { ConsoleLayout } from '@/components/console/ConsoleLayout';
import { DashboardToggle } from '@/components/DashboardToggle';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { CreditCard, TrendingUp, Download, Clock } from 'lucide-react';

const SimpleBilling = () => {
  const tabs = [
    { id: 'stig-dashboard', title: 'STIG Dashboard', path: '/stig-dashboard' },
    { id: 'asset-scanning', title: 'Asset Scanning', path: '/asset-scanning' },
    { id: 'compliance-reports', title: 'Reports', path: '/compliance-reports' },
    { id: 'evidence-collection', title: 'Evidence', path: '/evidence-collection' },
    { id: 'billing', title: 'Billing', path: '/billing', isActive: true },
  ];

  return (
    <ConsoleLayout 
      currentSection="billing"
      browserNav={{
        title: 'Billing & Usage',
        subtitle: 'Simple usage-based billing for STIG compliance automation',
        tabs,
        showAddTab: false,
        rightContent: <DashboardToggle />
      }}
    >
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground">Billing & Usage</h1>
            <p className="text-muted-foreground">Track usage and manage billing for STIG compliance services</p>
          </div>
          <Button variant="outline" className="flex items-center space-x-2">
            <Download className="h-4 w-4" />
            <span>Download Invoice</span>
          </Button>
        </div>

        {/* Current Plan */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span>Current Plan</span>
              <Badge variant="outline" className="bg-primary/20 text-primary border-primary/30">
                STIG Professional
              </Badge>
            </CardTitle>
            <CardDescription>
              Professional STIG compliance automation with unlimited assets
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="text-center">
                <div className="text-2xl font-bold text-foreground">$299</div>
                <div className="text-sm text-muted-foreground">per month</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-primary">Unlimited</div>
                <div className="text-sm text-muted-foreground">assets scanned</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-green-400">Active</div>
                <div className="text-sm text-muted-foreground">next billing: Jan 15</div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Usage Summary */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Assets Scanned</p>
                  <p className="text-2xl font-bold text-foreground">42</p>
                  <p className="text-xs text-green-400">+8 this month</p>
                </div>
                <TrendingUp className="h-8 w-8 text-primary" />
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">STIG Rules Checked</p>
                  <p className="text-2xl font-bold text-foreground">1,247</p>
                  <p className="text-xs text-blue-400">automated</p>
                </div>
                <Clock className="h-8 w-8 text-blue-400" />
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Reports Generated</p>
                  <p className="text-2xl font-bold text-foreground">15</p>
                  <p className="text-xs text-purple-400">this month</p>
                </div>
                <Download className="h-8 w-8 text-purple-400" />
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Compliance Score</p>
                  <p className="text-2xl font-bold text-green-400">87%</p>
                  <p className="text-xs text-green-400">improving</p>
                </div>
                <CreditCard className="h-8 w-8 text-green-400" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Billing History */}
        <Card>
          <CardHeader>
            <CardTitle>Billing History</CardTitle>
            <CardDescription>
              Recent invoices and payment history
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {[
                { date: '2024-01-01', amount: '$299.00', status: 'paid', period: 'Jan 2024' },
                { date: '2023-12-01', amount: '$299.00', status: 'paid', period: 'Dec 2023' },
                { date: '2023-11-01', amount: '$299.00', status: 'paid', period: 'Nov 2023' },
              ].map((invoice, index) => (
                <div key={index} className="flex items-center justify-between p-4 border border-border rounded-lg">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3">
                      <span className="font-medium text-foreground">Invoice for {invoice.period}</span>
                      <Badge 
                        variant="outline" 
                        className="bg-green-500/20 text-green-400 border-green-500/30"
                      >
                        {invoice.status}
                      </Badge>
                    </div>
                    <p className="text-sm text-muted-foreground">Billed on {invoice.date}</p>
                  </div>
                  <div className="flex items-center space-x-4">
                    <span className="font-medium text-foreground">{invoice.amount}</span>
                    <Button variant="outline" size="sm">
                      <Download className="h-4 w-4" />
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

export default SimpleBilling;