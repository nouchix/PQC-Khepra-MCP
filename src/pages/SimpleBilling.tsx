"use client";

import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ConsoleLayout } from '@/components/console/ConsoleLayout';
import { DashboardToggle } from '@/components/DashboardToggle';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  CreditCard, TrendingUp, Download, Clock, Shield, Award, Loader2,
  Zap, Users, Globe, Lock, Star, Microscope, BookOpen, Rocket,
  ArrowRight, ChevronRight,
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/hooks/useAuth';

const ASAF_API = (import.meta as any).env?.VITE_ASAF_API_URL
  ?? process.env.NEXT_PUBLIC_ASAF_API_URL
  ?? '';
const ASAF_KEY = (import.meta as any).env?.VITE_ASAF_API_KEY
  ?? process.env.NEXT_PUBLIC_ASAF_API_KEY
  ?? '';

// ── Platform Plans (SaaS) ─────────────────────────────────────────────────────
// Canonical Stripe price IDs — see src/app/api/checkout/route.ts
const PLATFORM_PLANS = [
  {
    name: 'Free',
    icon: Shield,
    price: '$0',
    priceSuffix: '/mo',
    description: 'Scan any AI agent deployment. Get your exposure report.',
    features: ['Unlimited scans', 'Exposure report', 'Basic risk score', 'Community support'],
    cta: 'Current Plan',
    ctaVariant: 'outline' as const,
    highlight: false,
    action: 'free' as const,
    planKey: '',
    badge: '',
  },
  {
    name: 'Certify',
    icon: Award,
    price: '$99',
    priceSuffix: ' one-time',
    description: 'Full compliance audit + ADINKHEPRA certification badge.',
    features: [
      'Everything in Free',
      'Full NIST/STIG audit (36,195 controls)',
      'ADINKHEPRA badge (PDF + API)',
      'ML-DSA-65 signed attestation',
      'Shareable with CISOs & auditors',
      'Email support',
    ],
    cta: 'Earn Your ADINKHEPRA Seal',
    ctaVariant: 'default' as const,
    highlight: true,
    action: 'checkout' as const,
    planKey: 'certify',
    badge: 'Most Popular',
  },
  {
    name: 'Starter',
    icon: Zap,
    price: '$299',
    priceSuffix: '/mo',
    description: 'Continuous monitoring + DAG history + anomaly alerts.',
    features: [
      'Everything in Certify',
      'DAG audit history (unlimited)',
      'KASA behavioral anomaly detection',
      'Slack & PagerDuty alerts',
      'SIEM integration (Splunk, Elastic)',
    ],
    cta: 'Start Monitoring',
    ctaVariant: 'outline' as const,
    highlight: false,
    action: 'checkout' as const,
    planKey: 'starter',
    badge: '',
  },
  {
    name: 'Enterprise',
    icon: Users,
    price: '$500',
    priceSuffix: '/mo',
    description: 'Attestation API + team seats + custom compliance frameworks.',
    features: [
      'Everything in Starter',
      'Attestation API access',
      'Up to 10 team seats (RBAC)',
      'Custom compliance frameworks',
      'SOC 2 / EU AI Act / ISO 42001',
      'Priority support',
    ],
    cta: 'Upgrade to Enterprise',
    ctaVariant: 'outline' as const,
    highlight: false,
    action: 'checkout' as const,
    planKey: 'enterprise',
    badge: '',
  },
  {
    name: 'Professional',
    icon: Star,
    price: '$999',
    priceSuffix: '/mo',
    description: 'Full Agentic SOC — SOAR engine, multi-agent orchestration, playbooks.',
    features: [
      'Everything in Enterprise',
      'SOAR engine + signed playbooks',
      'Multi-agent orchestration',
      'AI drift detection',
      'CI/CD integrity enforcement',
      'Threat intelligence ingestion',
    ],
    cta: 'Get Professional',
    ctaVariant: 'outline' as const,
    highlight: false,
    action: 'checkout' as const,
    planKey: 'professional',
    badge: 'Full SOC',
  },
  {
    name: 'Sovereign',
    icon: Lock,
    price: '$2,999',
    priceSuffix: '/mo',
    description: 'Air-gapped bare-metal ASAF with Sovereign MCP server. DoD/CMMC.',
    features: [
      'Everything in Professional',
      'Sovereign MCP server (72 tools)',
      'Air-gapped deployment',
      'ADINKHEPRA ASAF compliance graph',
      'CMMC L2/L3 pentest workloads',
      'DR/BC + IR workloads',
    ],
    cta: 'Go Sovereign',
    ctaVariant: 'outline' as const,
    highlight: false,
    action: 'checkout' as const,
    planKey: 'sovereign',
    badge: 'DoD Ready',
  },
];

// ── Professional Services ─────────────────────────────────────────────────────
// One-time engagements — bridge between SaaS and ASAF Enterprise contracts
const SERVICE_PLANS = [
  {
    name: 'Diagnostic Assessment',
    icon: Microscope,
    price: '$1,500',
    description: 'Hands-on technical assessment of your AI agent security posture.',
    deliverables: [
      'Full STIG gap analysis report',
      'Prioritised remediation roadmap',
      'CMMC control mapping',
      'Live expert review session (2hr)',
    ],
    cta: 'Book Assessment',
    planKey: 'diagnostic',
    color: 'border-blue-500/30 bg-blue-950/10',
    accentColor: 'text-blue-400',
    badgeColor: 'bg-blue-950/40 text-blue-400 border-blue-500/30',
  },
  {
    name: 'Advisory Package',
    icon: BookOpen,
    price: '$5,000',
    description: 'Strategic CMMC/STIG advisory engagement with C-suite deliverables.',
    deliverables: [
      'CMMC Level 2/3 readiness roadmap',
      'C-suite briefing deck',
      'Supply chain risk assessment',
      'Policy declaration templates',
    ],
    cta: 'Start Advisory',
    planKey: 'advisory',
    color: 'border-violet-500/30 bg-violet-950/10',
    accentColor: 'text-violet-400',
    badgeColor: 'bg-violet-950/40 text-violet-400 border-violet-500/30',
  },
  {
    name: 'Deadline Sprint',
    icon: Rocket,
    price: '$15,000',
    description: '30-day intensive audit + remediation. Walk into your CMMC audit confident.',
    deliverables: [
      '30-day embedded engagement',
      'Full CMMC audit preparation',
      'Live remediation execution',
      'C3PAO evidence package',
    ],
    cta: 'Launch Sprint',
    planKey: 'deadline_sprint',
    color: 'border-amber-500/30 bg-amber-950/10',
    accentColor: 'text-amber-400',
    badgeColor: 'bg-amber-950/40 text-amber-400 border-amber-500/30',
  },
];

interface UsageStats {
  scansTotal: number | null;
  dagNodes: number | null;
  loading: boolean;
  error: string | null;
}

async function fetchUsageStats(): Promise<{ scansTotal: number; dagNodes: number }> {
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
  return { scansTotal: scansData.total ?? 0, dagNodes: healthData.dag_nodes ?? 0 };
}

// ── Component ─────────────────────────────────────────────────────────────────
const SimpleBilling = () => {
  const [loading, setLoading] = useState<string>(''); // which planKey is checking out
  const [stats, setStats] = useState<UsageStats>({ scansTotal: null, dagNodes: null, loading: true, error: null });
  const { toast } = useToast();
  const { user } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    fetchUsageStats()
      .then(data => setStats({ scansTotal: data.scansTotal, dagNodes: data.dagNodes, loading: false, error: null }))
      .catch(err => setStats(s => ({ ...s, loading: false, error: err.message })));
  }, []);

  // After returning from auth with a pending plan, auto-trigger checkout
  useEffect(() => {
    const pendingPlan = sessionStorage.getItem('billing_plan_pending');
    if (user && pendingPlan) {
      sessionStorage.removeItem('billing_plan_pending');
      // Small delay so the page renders before redirecting to Stripe
      setTimeout(() => handleCheckout(pendingPlan), 300);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user]);

  const handleCheckout = async (planKey: string) => {
    // Gate checkout behind auth — unauthenticated users see the billing page
    // (marketing shock-and-awe) but must sign in to pay
    if (!user) {
      sessionStorage.setItem('billing_plan_pending', planKey);
      navigate(`/auth?redirect=/billing&plan=${planKey}`);
      return;
    }
    setLoading(planKey);
    try {
      const res = await fetch('/api/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ plan: planKey }),
      });
      const data = await res.json();
      if (data.url) {
        window.location.href = data.url;
      } else {
        throw new Error(data.error || 'Checkout unavailable');
      }
    } catch (e: any) {
      toast({ title: 'Checkout error', description: e.message, variant: 'destructive' });
      setLoading('');
    }
  };

  const tabs = [
    { id: 'asset-scanning', title: 'Scan', path: '/asset-scanning' },
    { id: 'compliance-reports', title: 'Reports', path: '/compliance-reports' },
    { id: 'billing', title: 'Billing', path: '/billing', isActive: true },
  ];

  const statCell = (value: number | null) => {
    if (stats.loading) return <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />;
    if (value === null || stats.error) return <span className="text-2xl font-bold text-muted-foreground">—</span>;
    return <p className="text-2xl font-bold text-foreground">{value.toLocaleString()}</p>;
  };

  return (
    <ConsoleLayout
      currentSection="billing"
      browserNav={{
        title: 'Plans & Billing',
        subtitle: 'SouHimBou AI — Agentic Security Operations Center',
        tabs,
        showAddTab: false,
        rightContent: <DashboardToggle />,
      }}
    >
      <div className="space-y-10">

        {/* ── Header ──────────────────────────────────────────────────────── */}
        <div>
          <h1 className="text-2xl font-bold text-foreground">Plans & Billing</h1>
          <p className="text-muted-foreground mt-1">
            72 live MCP tools · ML-DSA-65 PQC attestation · 36,195 STIG/CMMC mappings
          </p>
        </div>

        {/* ── Section 1: Platform Plans ────────────────────────────────────── */}
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <div className="h-px flex-1 bg-border" />
            <span className="text-xs font-semibold uppercase tracking-widest text-muted-foreground px-3">
              Platform — SouHimBou AI
            </span>
            <div className="h-px flex-1 bg-border" />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {PLATFORM_PLANS.map((plan) => {
              const Icon = plan.icon;
              const isLoading = loading === plan.planKey;
              return (
                <Card
                  key={plan.name}
                  className={`relative flex flex-col transition-all duration-200 hover:shadow-md ${
                    plan.highlight
                      ? 'border-primary ring-1 ring-primary shadow-sm shadow-primary/20'
                      : 'hover:border-muted-foreground/30'
                  }`}
                >
                  {plan.badge && (
                    <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                      <Badge className="bg-primary/20 text-primary border-primary/40 px-3 text-xs font-semibold">
                        {plan.badge}
                      </Badge>
                    </div>
                  )}
                  <CardHeader className="pb-2 pt-5">
                    <div className="flex items-center gap-2 mb-1">
                      <Icon className={`h-4 w-4 ${plan.highlight ? 'text-primary' : 'text-muted-foreground'}`} />
                      <CardTitle className="text-base">{plan.name}</CardTitle>
                    </div>
                    <div className="flex items-baseline gap-1">
                      <span className="text-3xl font-black text-foreground">{plan.price}</span>
                      <span className="text-sm text-muted-foreground">{plan.priceSuffix}</span>
                    </div>
                    <CardDescription className="text-xs leading-relaxed">{plan.description}</CardDescription>
                  </CardHeader>
                  <CardContent className="flex flex-col flex-1 gap-4">
                    <ul className="space-y-1.5 flex-1">
                      {plan.features.map((f) => (
                        <li key={f} className="flex items-start gap-2 text-xs text-muted-foreground">
                          <ChevronRight className="h-3 w-3 text-primary shrink-0 mt-0.5" />
                          {f}
                        </li>
                      ))}
                    </ul>
                    <Button
                      variant={plan.ctaVariant}
                      size="sm"
                      className={`w-full text-xs ${plan.highlight ? 'bg-primary text-primary-foreground hover:bg-primary/90' : ''}`}
                      disabled={plan.action === 'free' || isLoading}
                      onClick={() => {
                        if (plan.action === 'checkout') handleCheckout(plan.planKey);
                      }}
                    >
                      {isLoading ? (
                        <><Loader2 className="h-3 w-3 mr-1.5 animate-spin" />Redirecting…</>
                      ) : (
                        <>{plan.cta} {plan.action === 'checkout' && <ArrowRight className="h-3 w-3 ml-1.5" />}</>
                      )}
                    </Button>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </div>

        {/* ── Section 2: Professional Services ─────────────────────────────── */}
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <div className="h-px flex-1 bg-border" />
            <span className="text-xs font-semibold uppercase tracking-widest text-muted-foreground px-3">
              Professional Services — One-Time Engagements
            </span>
            <div className="h-px flex-1 bg-border" />
          </div>

          <p className="text-xs text-muted-foreground max-w-2xl">
            Hands-on expert engagements that bridge self-serve SaaS and full enterprise contracts.
            All deliverables are ML-DSA-65 signed and C3PAO-ready.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {SERVICE_PLANS.map((svc) => {
              const Icon = svc.icon;
              const isLoading = loading === svc.planKey;
              return (
                <Card key={svc.name} className={`border ${svc.color} transition-all duration-200 hover:shadow-md`}>
                  <CardHeader className="pb-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Icon className={`h-4 w-4 ${svc.accentColor}`} />
                        <CardTitle className="text-sm">{svc.name}</CardTitle>
                      </div>
                      <Badge className={`text-xs ${svc.badgeColor}`}>one-time</Badge>
                    </div>
                    <div className="flex items-baseline gap-1 mt-2">
                      <span className="text-2xl font-black text-foreground">{svc.price}</span>
                    </div>
                    <CardDescription className="text-xs">{svc.description}</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <ul className="space-y-1.5">
                      {svc.deliverables.map((d) => (
                        <li key={d} className="flex items-start gap-2 text-xs text-muted-foreground">
                          <ChevronRight className={`h-3 w-3 ${svc.accentColor} shrink-0 mt-0.5`} />
                          {d}
                        </li>
                      ))}
                    </ul>
                    <Button
                      size="sm"
                      variant="outline"
                      className={`w-full text-xs border ${svc.color.replace('bg-', 'hover:bg-')} ${svc.accentColor}`}
                      disabled={isLoading}
                      onClick={() => handleCheckout(svc.planKey)}
                    >
                      {isLoading ? (
                        <><Loader2 className="h-3 w-3 mr-1.5 animate-spin" />Redirecting…</>
                      ) : (
                        <>{svc.cta} <ArrowRight className="h-3 w-3 ml-1.5" /></>
                      )}
                    </Button>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </div>

        {/* ── Section 3: ADINKHEPRA ASAF Enterprise ────────────────────────── */}
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <div className="h-px flex-1 bg-border" />
            <span className="text-xs font-semibold uppercase tracking-widest text-muted-foreground px-3">
              ADINKHEPRA ASAF — Bare-Metal Enterprise
            </span>
            <div className="h-px flex-1 bg-border" />
          </div>

          <Card className="border-[#d4af37]/30 bg-gradient-to-br from-[#d4af37]/5 to-transparent">
            <CardContent className="p-6">
              <div className="flex flex-col md:flex-row md:items-center gap-6">
                <div className="flex-1 space-y-3">
                  <div className="flex items-center gap-2">
                    <Globe className="h-5 w-5 text-[#d4af37]" />
                    <span className="font-semibold text-foreground">Sovereign Bare-Metal Deployment</span>
                    <Badge className="bg-[#d4af37]/20 text-[#d4af37] border-[#d4af37]/40 text-xs">DoD / DIB</Badge>
                  </div>
                  <p className="text-sm text-muted-foreground max-w-xl">
                    ADINKHEPRA ASAF answers one question: <strong className="text-foreground">"Will I pass my CMMC audit?"</strong>{' '}
                    Air-gapped, zero egress, sovereign MCP server included. Flat annual pricing.
                  </p>
                  <div className="grid grid-cols-3 gap-3 text-xs">
                    {[
                      { tier: 'Pilot', price: '$25K/yr', desc: '1 program office' },
                      { tier: 'Program', price: '$75K/yr', desc: 'Full CMMC L2 program' },
                      { tier: 'Enterprise', price: '$150K–$250K/yr', desc: 'Multi-site, CMMC L3' },
                    ].map((t) => (
                      <div key={t.tier} className="bg-[#d4af37]/5 border border-[#d4af37]/20 rounded-lg p-3 text-center">
                        <div className="font-semibold text-[#d4af37]">{t.tier}</div>
                        <div className="font-bold text-foreground mt-0.5">{t.price}</div>
                        <div className="text-muted-foreground mt-0.5">{t.desc}</div>
                      </div>
                    ))}
                  </div>
                </div>
                <div className="flex flex-col gap-3 min-w-[180px]">
                  <Button
                    className="w-full bg-gradient-to-r from-[#d4af37] to-[#b8860b] text-black font-bold hover:opacity-90"
                    onClick={() => window.location.href = 'mailto:skone@alumni.albany.edu?subject=ADINKHEPRA%20ASAF%20Pilot%20Program&body=I%27m%20interested%20in%20the%20ADINKHEPRA%20ASAF%20pilot%20program%20for%20CMMC%20compliance.'}
                  >
                    Contact Sales
                    <ArrowRight className="h-4 w-4 ml-2" />
                  </Button>
                  <p className="text-xs text-center text-muted-foreground">
                    SDVOSB · $5M sole-source vehicle available
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* ── ADINKHEPRA Badge Callout ──────────────────────────────────────── */}
        <Card className="border-yellow-500/30 bg-yellow-950/10">
          <CardContent className="p-5 flex items-center gap-4">
            <Award className="h-9 w-9 text-yellow-400 shrink-0" />
            <div>
              <div className="font-semibold text-yellow-400 text-sm">What is the ADINKHEPRA badge?</div>
              <p className="text-xs text-muted-foreground mt-0.5">
                A post-quantum cryptographic attestation seal issued by SouHimBou AI. Tamper-proof, timestamped,
                and verifiable by auditors, customers, and insurers. Think SOC2 — but automated, continuous, and
                built for agentic AI.
              </p>
            </div>
          </CardContent>
        </Card>

        {/* ── Usage Summary ─────────────────────────────────────────────────── */}
        {stats.error && (
          <p className="text-xs text-red-400 font-mono">Usage stats unavailable: {stats.error}</p>
        )}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Card>
            <CardContent className="p-5">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Scans Run</p>
                  {statCell(stats.scansTotal)}
                  <p className="text-xs text-muted-foreground mt-1">total in your org</p>
                </div>
                <TrendingUp className="h-7 w-7 text-primary" />
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-5">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">DAG Audit Nodes</p>
                  {statCell(stats.dagNodes)}
                  <p className="text-xs text-muted-foreground mt-1">immutable audit records</p>
                </div>
                <Clock className="h-7 w-7 text-blue-400" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* ── Billing History ───────────────────────────────────────────────── */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Billing History</CardTitle>
            <CardDescription>Invoices issued after your first payment will appear here.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col items-center justify-center py-10 text-center gap-3">
              <CreditCard className="h-9 w-9 text-muted-foreground/40" />
              <p className="text-sm text-muted-foreground">No invoices yet.</p>
              <p className="text-xs text-muted-foreground/60 max-w-xs">
                Upgrade to Certify to generate your first invoice. Invoices are delivered by Stripe and stored here automatically.
              </p>
              <Button variant="outline" size="sm" onClick={() => handleCheckout('certify')} disabled={loading === 'certify'}>
                {loading === 'certify' ? <><Loader2 className="h-3 w-3 mr-1.5 animate-spin" />Redirecting…</> : <><Download className="h-3.5 w-3.5 mr-2" />Get Certify ($99 one-time)</>}
              </Button>
            </div>
          </CardContent>
        </Card>

      </div>
    </ConsoleLayout>
  );
};

export default SimpleBilling;
