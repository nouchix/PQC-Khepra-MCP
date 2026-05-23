
import { useEffect, useState } from 'react';
import { ConsoleLayout } from '@/components/console/ConsoleLayout';
import { DashboardToggle } from '@/components/DashboardToggle';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { CreditCard, TrendingUp, Download, Clock, Shield, Award, Loader2 } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

const ASAF_API = (import.meta as any).env?.VITE_ASAF_API_URL
  ?? process.env.NEXT_PUBLIC_ASAF_API_URL
  ?? '';
const ASAF_KEY = (import.meta as any).env?.VITE_ASAF_API_KEY
  ?? process.env.NEXT_PUBLIC_ASAF_API_KEY
  ?? '';

const PLANS = [
  {
    name: 'Free',
    price: '$0',
    description: 'Scan any AI agent deployment. Get your exposure report.',
    features: ['Unlimited scans', 'Exposure report', 'Basic risk score', 'Community support'],
    cta: 'Current Plan',
    ctaVariant: 'outline' as const,
    highlight: false,
    action: 'free' as const,
  },
  {
    name: 'Certify',
    price: '$99',
    description: 'Full compliance audit + ADINKHEPRA certification badge.',
    features: ['Everything in Free', 'Full NIST/STIG audit', 'ADINKHEPRA badge (PDF + API)', 'Shareable attestation report', 'Email support'],
    cta: 'Upgrade to Certify',
    ctaVariant: 'default' as const,
    highlight: true,
    action: 'checkout' as const,
  },
  {
    name: 'Enterprise',
    price: '$499',
    description: 'Continuous monitoring + attestation API + team seats.',
    features: ['Everything in Certify', 'Continuous monitoring', 'Attestation API access', 'Up to 10 team seats', 'Priority support', 'Custom compliance frameworks'],
    cta: 'Contact Sales',
    ctaVariant: 'outline' as const,
    highlight: false,
    action: 'contact' as const,
  },
];

interface UsageStats {
  scansTotal: number | null;
  dagNodes: number | null;
  licenseScore: number | null;
  loading: boolean;
  error: string | null;
}

async function fetchUsageStats(): Promise<{ scansTotal: number; dagNodes: number; licenseScore: number | null }> {
  if (!ASAF_API) throw new Error('NEXT_PUBLIC_ASAF_API_URL is not configured');

  const headers: HeadersInit = ASAF_KEY ? { Authorization: ASAF_KEY } : {};

  const [scansRes, healthRes] = await Promise.all([
    fetch(`${ASAF_API}/api/v1/scans?page=1&page_size=1`, { headers }),
    fetch(`${ASAF_API}/health`, { headers }),
  ]);

  if (!scansRes.ok) throw new Error(`Scans API ${scansRes.status}`);
  if (!healthRes.ok) throw new Error(`Health API ${healthRes.status}`);

  const scansData = await scansRes.json();
  const healthData = await healthRes.json();

  return {
    scansTotal: scansData.total ?? 0,
    dagNodes: healthData.dag_nodes ?? 0,
    licenseScore: null, // No score endpoint yet — hide until available
  };
}

const SimpleBilling = () => {
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState<UsageStats>({
    scansTotal: null,
    dagNodes: null,
    licenseScore: null,
    loading: true,
    error: null,
  });
  const { toast } = useToast();

  useEffect(() => {
    fetchUsageStats()
      .then(data => setStats({ scansTotal: data.scansTotal, dagNodes: data.dagNodes, licenseScore: data.licenseScore, loading: false, error: null }))
      .catch(err => setStats(s => ({ ...s, loading: false, error: err.message })));
  }, []);

  const handleCheckout = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const data = await res.json();
      if (data.url) {
        window.location.href = data.url;
      } else {
        throw new Error(data.error || 'Checkout unavailable');
      }
    } catch (e: any) {
      toast({ title: 'Checkout error', description: e.message, variant: 'destructive' });
      setLoading(false);
    }
  };

  const tabs = [
    { id: 'asset-scanning', title: 'Scan', path: '/asset-scanning' },
    { id: 'compliance-reports', title: 'Reports', path: '/compliance-reports' },
    { id: 'billing', title: 'Billing', path: '/billing', isActive: true },
  ];

  const statCell = (value: number | null, suffix = '') => {
    if (stats.loading) return <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />;
    if (value === null || stats.error) return <span className="text-2xl font-bold text-muted-foreground">—</span>;
    return <p className="text-2xl font-bold text-foreground">{value.toLocaleString()}{suffix}</p>;
  };

  return (
    <ConsoleLayout
      currentSection="billing"
      browserNav={{
        title: 'Plans & Billing',
        subtitle: 'ASAF by NouchiX — Agentic Security Attestation Framework',
        tabs,
        showAddTab: false,
        rightContent: <DashboardToggle />
      }}
    >
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground">Plans & Billing</h1>
            <p className="text-muted-foreground">One price. One sell point. Earn your ADINKHEPRA certification.</p>
          </div>
        </div>

        {/* Pricing Plans */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {PLANS.map((plan) => (
            <Card key={plan.name} className={plan.highlight ? 'border-primary ring-1 ring-primary' : ''}>
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <span>{plan.name}</span>
                  {plan.highlight && (
                    <Badge className="bg-primary/20 text-primary border-primary/30">
                      Most Popular
                    </Badge>
                  )}
                </CardTitle>
                <div className="text-3xl font-bold">{plan.price}<span className="text-sm font-normal text-muted-foreground">/mo</span></div>
                <CardDescription>{plan.description}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <ul className="space-y-2 text-sm">
                  {plan.features.map((f) => (
                    <li key={f} className="flex items-center gap-2 text-muted-foreground">
                      <Shield className="h-3.5 w-3.5 text-primary shrink-0" />
                      {f}
                    </li>
                  ))}
                </ul>
                <Button
                  variant={plan.ctaVariant}
                  className="w-full"
                  disabled={plan.action === 'checkout' && loading}
                  onClick={() => {
                    if (plan.action === 'checkout') handleCheckout();
                    if (plan.action === 'contact') window.location.href = 'mailto:skone@alumni.albany.edu?subject=ASAF Enterprise';
                  }}
                >
                  {plan.action === 'checkout' && loading ? 'Redirecting...' : plan.cta}
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* ADINKHEPRA badge callout */}
        <Card className="border-yellow-500/30 bg-yellow-950/10">
          <CardContent className="p-6 flex items-center gap-4">
            <Award className="h-10 w-10 text-yellow-400 shrink-0" />
            <div>
              <div className="font-semibold text-yellow-400">What is the ADINKHEPRA badge?</div>
              <p className="text-sm text-muted-foreground">
                A post-quantum cryptographic attestation seal issued by ASAF. Tamper-proof, timestamped, and verifiable by auditors, customers, and insurers.
                Think SOC2 — but automated, continuous, and built for agentic AI.
              </p>
            </div>
          </CardContent>
        </Card>

        {/* Usage Summary — live from backend */}
        {stats.error && (
          <p className="text-xs text-red-400 font-mono">Usage stats unavailable: {stats.error}</p>
        )}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Scans Run</p>
                  {statCell(stats.scansTotal)}
                  <p className="text-xs text-muted-foreground mt-1">total in your org</p>
                </div>
                <TrendingUp className="h-8 w-8 text-primary" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">DAG Audit Nodes</p>
                  {statCell(stats.dagNodes)}
                  <p className="text-xs text-muted-foreground mt-1">immutable audit records</p>
                </div>
                <Clock className="h-8 w-8 text-blue-400" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Billing History — empty state until Stripe webhooks populate real invoices */}
        <Card>
          <CardHeader>
            <CardTitle>Billing History</CardTitle>
            <CardDescription>Invoices issued after your first payment will appear here.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col items-center justify-center py-12 text-center gap-3">
              <CreditCard className="h-10 w-10 text-muted-foreground/40" />
              <p className="text-sm text-muted-foreground">No invoices yet.</p>
              <p className="text-xs text-muted-foreground/60">
                Upgrade to Certify to generate your first invoice. Invoices are delivered by Stripe and stored here automatically.
              </p>
              <Button variant="outline" size="sm" onClick={handleCheckout} disabled={loading}>
                <Download className="h-3.5 w-3.5 mr-2" />
                {loading ? 'Redirecting...' : 'Get Certify Plan'}
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </ConsoleLayout>
  );
};

export default SimpleBilling;
