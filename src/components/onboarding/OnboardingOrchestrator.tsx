import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useSearchParams } from '@/lib/router-compat';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { useToast } from '@/hooks/use-toast';
import { Shield, Search, CheckCircle, AlertTriangle, XCircle, ArrowRight, Lock } from 'lucide-react';

const API_BASE = process.env.NEXT_PUBLIC_ASAF_API_URL || 'http://localhost:45444';
const API_KEY = process.env.NEXT_PUBLIC_ASAF_API_KEY || '';

type Step = 'input' | 'scanning' | 'results' | 'upgrade';

interface ScanResult {
  scan_id: string;
  risk_score: number;
  exposed: boolean;
  auth_weakness: boolean;
  open_integrations: number;
  findings: { severity: 'critical' | 'high' | 'medium' | 'low'; text: string }[];
  certified: boolean;
}

const SCAN_PHASES = [
  'Checking port exposure...',
  'Fingerprinting gateway...',
  'Auditing auth configuration...',
  'Mapping integration blast radius...',
  'Running NIST/STIG controls...',
  'Generating risk score...',
];

async function triggerScan(target: string): Promise<string> {
  const res = await fetch(`${API_BASE}/api/v1/scans/trigger`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': API_KEY },
    body: JSON.stringify({ target_url: target, scan_type: 'full' }),
  });
  if (!res.ok) throw new Error(`Scan failed: ${res.status}`);
  const data = await res.json();
  return data.scan_id;
}

async function pollScan(scanId: string): Promise<ScanResult> {
  const res = await fetch(`${API_BASE}/api/v1/scans/${scanId}`, {
    headers: { 'Authorization': API_KEY },
  });
  if (!res.ok) throw new Error(`Poll failed: ${res.status}`);
  return res.json();
}

const OnboardingOrchestrator: React.FC = () => {
  const [step, setStep] = useState<Step>('input');
  const [target, setTarget] = useState('');
  const [email, setEmail] = useState('');
  const [scanId, setScanId] = useState<string | null>(null);
  const [phase, setPhase] = useState(0);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [checkingOut, setCheckingOut] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const navigate = useNavigate();
  const { toast } = useToast();
  const [searchParams] = useSearchParams();

  // Handle Stripe return: session_id in URL means payment succeeded
  useEffect(() => {
    const sessionId = searchParams.get('stripe_session_id');
    if (sessionId) {
      toast({ title: 'Payment successful!', description: 'Your ADINKHEPRA certification is being processed.' });
      navigate('/compliance-reports');
    }
  }, [searchParams, navigate, toast]);

  // Animate scan phases
  useEffect(() => {
    if (step !== 'scanning') return;
    const interval = setInterval(() => {
      setPhase(p => {
        const next = p + 1;
        setProgress(Math.round((next / SCAN_PHASES.length) * 90));
        return next < SCAN_PHASES.length ? next : p;
      });
    }, 1400);
    return () => clearInterval(interval);
  }, [step]);

  // Poll scan result
  useEffect(() => {
    if (!scanId || step !== 'scanning') return;
    pollRef.current = setInterval(async () => {
      try {
        const data = await pollScan(scanId);
        if (data.certified !== undefined) {
          clearInterval(pollRef.current!);
          setProgress(100);
          setTimeout(() => {
            setResult(data);
            setStep('results');
          }, 600);
        }
      } catch {
        // keep polling, transient error
      }
    }, 2500);
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [scanId, step]);

  const handleScan = async () => {
    if (!target.trim()) return;
    setError(null);
    setResult(null);
    setScanId(null);
    setStep('scanning');
    setPhase(0);
    setProgress(5);
    try {
      const id = await triggerScan(target.trim());
      setScanId(id);
    } catch (e: any) {
      setError(
        `Scan failed: ${e.message}. ` +
        `Ensure NEXT_PUBLIC_ASAF_API_URL points to your running ASAF backend (currently: ${API_BASE}).`
      );
      setStep('input');
    }
  };

  const handleCheckout = async () => {
    setCheckingOut(true);
    try {
      const res = await fetch('/api/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });
      const data = await res.json();
      if (data.url) {
        window.location.href = data.url;
      } else {
        throw new Error(data.error || 'Checkout unavailable');
      }
    } catch (e: any) {
      toast({ title: 'Checkout error', description: e.message, variant: 'destructive' });
      setCheckingOut(false);
    }
  };

  // ── Step: Input ──────────────────────────────────────────────────────────────
  if (step === 'input') {
    return (
      <div className="min-h-screen bg-[#0a0a0a] flex items-center justify-center px-4">
        <div className="w-full max-w-lg space-y-8">
          <div className="text-center space-y-3">
            <div className="flex justify-center">
              <div className="p-3 rounded-xl bg-cyan-950/40 border border-cyan-500/20">
                <Search className="h-8 w-8 text-[#00ffff]" />
              </div>
            </div>
            <h1 className="text-3xl font-bold text-white">Scan your AI agent deployment</h1>
            <p className="text-gray-400">Enter any IP, domain, or hostname. We'll check it for exposure in under 60 seconds — free, no account needed.</p>
          </div>

          {error && (
            <div className="bg-red-950/40 border border-red-500/30 rounded-xl p-4 text-sm text-red-400 font-mono break-all">
              {error}
            </div>
          )}

          <div className="space-y-4 bg-[#111] border border-gray-800 rounded-xl p-6">
            <div className="space-y-2">
              <label className="text-sm text-gray-400 font-medium">Target host or IP</label>
              <Input
                placeholder="192.168.1.100 or myagent.company.com"
                value={target}
                onChange={e => setTarget(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleScan()}
                className="bg-[#0a0a0a] border-gray-700 text-white placeholder:text-gray-600 font-mono"
              />
              <p className="text-xs text-gray-600">OpenClaw default port (18789) checked automatically. Custom ports also supported.</p>
            </div>
            <div className="space-y-2">
              <label className="text-sm text-gray-400 font-medium">Email <span className="text-gray-600">(optional — to receive your report)</span></label>
              <Input
                type="email"
                placeholder="you@company.com"
                value={email}
                onChange={e => setEmail(e.target.value)}
                className="bg-[#0a0a0a] border-gray-700 text-white placeholder:text-gray-600"
              />
            </div>
            <Button
              onClick={handleScan}
              disabled={!target.trim()}
              className="w-full bg-gradient-to-r from-[#00ffff] to-[#0088ff] text-black font-bold py-5"
            >
              <Shield className="h-4 w-4 mr-2" />
              Start Free Scan
            </Button>
            <p className="text-xs text-center text-gray-600">No account required. No credit card. Results in ~60s.</p>
          </div>
        </div>
      </div>
    );
  }

  // ── Step: Scanning ───────────────────────────────────────────────────────────
  if (step === 'scanning') {
    return (
      <div className="min-h-screen bg-[#0a0a0a] flex items-center justify-center px-4">
        <div className="w-full max-w-md space-y-8 text-center">
          <div className="space-y-2">
            <div className="flex justify-center">
              <div className="p-3 rounded-xl bg-cyan-950/40 border border-cyan-500/20 animate-pulse">
                <Shield className="h-8 w-8 text-[#00ffff]" />
              </div>
            </div>
            <h2 className="text-2xl font-bold text-white">Scanning <span className="text-[#00ffff] font-mono">{target}</span></h2>
          </div>
          <div className="space-y-3">
            <Progress value={progress} className="h-2" />
            <p className="text-sm text-gray-400 font-mono">{SCAN_PHASES[Math.min(phase, SCAN_PHASES.length - 1)]}</p>
          </div>
          <div className="space-y-2 text-left bg-[#111] border border-gray-800 rounded-xl p-4">
            {SCAN_PHASES.slice(0, phase + 1).map((p, i) => (
              <div key={i} className="flex items-center gap-2 text-sm">
                <CheckCircle className="h-3.5 w-3.5 text-green-400 shrink-0" />
                <span className="text-gray-400">{p}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  // ── Step: Results ────────────────────────────────────────────────────────────
  if (step === 'results' && result) {
    const riskColor = result.risk_score >= 70 ? 'text-red-400' : result.risk_score >= 40 ? 'text-yellow-400' : 'text-green-400';
    const severityIcon = (s: string) => {
      if (s === 'critical') return <XCircle className="h-3.5 w-3.5 text-red-500 shrink-0" />;
      if (s === 'high') return <AlertTriangle className="h-3.5 w-3.5 text-orange-400 shrink-0" />;
      return <AlertTriangle className="h-3.5 w-3.5 text-yellow-400 shrink-0" />;
    };

    return (
      <div className="min-h-screen bg-[#0a0a0a] flex items-center justify-center px-4 py-12">
        <div className="w-full max-w-lg space-y-6">
          {/* Risk score */}
          <div className="text-center space-y-2">
            <h2 className="text-2xl font-bold text-white">Scan complete — <span className="font-mono text-[#00ffff]">{target}</span></h2>
            <div className="flex items-center justify-center gap-3">
              <span className="text-gray-400 text-sm">Risk Score</span>
              <span className={`text-4xl font-black ${riskColor}`}>{result.risk_score}<span className="text-lg">/100</span></span>
              {result.exposed && <Badge className="bg-red-950/40 text-red-400 border-red-500/30">Exposed</Badge>}
            </div>
          </div>

          {/* Findings */}
          <div className="bg-[#111] border border-gray-800 rounded-xl p-5 space-y-3">
            <div className="text-sm font-semibold text-gray-300">{result.findings.length} findings</div>
            {result.findings.map((f, i) => (
              <div key={i} className="flex items-start gap-2 text-sm">
                {severityIcon(f.severity)}
                <span className="text-gray-300">{f.text}</span>
                <Badge className={`ml-auto shrink-0 text-xs ${
                  f.severity === 'critical' ? 'bg-red-950/40 text-red-400 border-red-500/30' :
                  f.severity === 'high' ? 'bg-orange-950/40 text-orange-400 border-orange-500/30' :
                  'bg-yellow-950/40 text-yellow-400 border-yellow-500/30'
                }`}>{f.severity}</Badge>
              </div>
            ))}
          </div>

          {/* Free result footer */}
          <div className="bg-[#111] border border-gray-800 rounded-xl p-5 space-y-4">
            <div className="flex items-start gap-3">
              <Lock className="h-5 w-5 text-[#d4af37] shrink-0 mt-0.5" />
              <div>
                <div className="font-semibold text-white">Get your ADINKHEPRA certification</div>
                <p className="text-sm text-gray-400 mt-1">
                  Earn a cryptographically-signed badge that proves this deployment is enterprise-safe.
                  Share it with your CISO, auditors, and customers. Renews automatically.
                </p>
              </div>
            </div>
            {email && (
              <Input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="your@email.com"
                className="bg-[#0a0a0a] border-gray-700 text-white"
              />
            )}
            {!email && (
              <Input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="Enter email to get certified"
                className="bg-[#0a0a0a] border-gray-700 text-white placeholder:text-gray-600"
              />
            )}
            <Button
              onClick={handleCheckout}
              disabled={checkingOut}
              className="w-full bg-gradient-to-r from-[#d4af37] to-[#b8860b] text-black font-bold py-5"
            >
              {checkingOut ? 'Redirecting to Stripe...' : (
                <>Get ADINKHEPRA Certified — $99/mo <ArrowRight className="h-4 w-4 ml-2" /></>
              )}
            </Button>
            <p className="text-xs text-center text-gray-600">
              Billed monthly via Stripe. Cancel anytime. Certification issued within minutes of payment.
            </p>
          </div>

          <div className="flex gap-3">
            <Button variant="outline" className="flex-1 border-gray-700 text-gray-400" onClick={() => { setStep('input'); setTarget(''); setResult(null); }}>
              Scan another target
            </Button>
            <Button variant="outline" className="flex-1 border-gray-700 text-gray-400" onClick={() => navigate('/compliance-reports')}>
              View dashboard
            </Button>
          </div>
        </div>
      </div>
    );
  }

  return null;
};

export default OnboardingOrchestrator;
