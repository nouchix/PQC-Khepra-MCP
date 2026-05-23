import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { Button } from '@/components/ui/button';
import { useKhepraAPI } from '@/hooks/useKhepraAPI';
import { useKhepraLicenseUpdates } from '@/hooks/useKhepraWebSocket';
import {
  Key,
  CheckCircle,
  AlertTriangle,
  XCircle,
  Activity,
  Shield,
  Zap,
  Lock,
  Building2,
  Cpu,
  Loader2,
} from 'lucide-react';

interface KhepraLicenseWidgetProps {
  deploymentUrl: string;
  apiKey: string;
}

const FEATURE_ICONS: Record<string, React.ReactNode> = {
  'premium-pqc': <Shield className="h-4 w-4 text-primary" />,
  'community-pqc': <Shield className="h-4 w-4 opacity-50" />,
  'white-box-crypto': <Lock className="h-4 w-4 text-cyan-400" />,
  'stig-validation': <CheckCircle className="h-4 w-4 text-emerald-400" />,
  'stig-nist': <CheckCircle className="h-4 w-4 text-emerald-400" />,
  'real-time-monitoring': <Zap className="h-4 w-4 text-orange-400" />,
  'threat-detection': <Zap className="h-4 w-4 text-red-400" />,
  'advanced-reporting': <Building2 className="h-4 w-4 text-blue-400" />,
  'api-access': <Cpu className="h-4 w-4 text-purple-400" />,
  'sso-rbac': <Lock className="h-4 w-4 text-cyan-400" />,
  'auto-remediation': <Zap className="h-4 w-4 text-emerald-400" />,
};

export function KhepraLicenseWidget({ deploymentUrl, apiKey }: KhepraLicenseWidgetProps) {
  const { license, heartbeat } = useKhepraAPI(deploymentUrl, apiKey);
  const { licenseUpdates } = useKhepraLicenseUpdates(deploymentUrl);

  const latestUpdate = licenseUpdates.at(-1);
  const data = license.data;

  const handleHeartbeat = async () => {
    try {
      await heartbeat.mutateAsync();
    } catch (error) {
      console.error('Heartbeat failed:', error);
    }
  };

  if (license.isLoading) {
    return (
      <Card className="glass-card animate-pulse border-white/5">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-xl font-black italic">
            <Key className="h-5 w-5 text-primary" />
            LICENSE STATUS
          </CardTitle>
        </CardHeader>
        <CardContent className="h-48 flex items-center justify-center">
          <Loader2 className="h-8 w-8 animate-spin text-primary/20" />
        </CardContent>
      </Card>
    );
  }

  if (license.isError || !data) {
    return (
      <Card className="glass-card border-red-500/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-red-500 font-black italic">
            <XCircle className="h-5 w-5" />
            LICENSE ERROR
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-red-400">
            Failed to retrieve license status. Node sync interrupted.
          </p>
        </CardContent>
      </Card>
    );
  }

  const getTierBadge = (tier: string) => {
    const configs: Record<string, { bg: string, text: string, border: string }> = {
      community: { bg: 'bg-slate-500/10', text: 'text-slate-400', border: 'border-slate-500/20' },
      khepri: { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/20' },
      ra: { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/20' },
      atum: { bg: 'bg-purple-500/10', text: 'text-purple-400', border: 'border-purple-500/20' },
      osiris: { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/20' },
    };

    const cfg = configs[tier] || configs.community;

    return (
      <Badge variant="outline" className={`${cfg.bg} ${cfg.text} ${cfg.border} uppercase px-3 py-1 text-[10px] font-black tracking-widest`}>
        {tier}
      </Badge>
    );
  };

  const getStatusIndicator = () => {
    if (data.revoked) {
      return (
        <div className="flex items-center gap-2 text-red-500">
          <XCircle className="h-5 w-5" />
          <span className="font-black italic uppercase tracking-tighter">Revoked</span>
        </div>
      );
    }

    if (!data.is_valid) {
      return (
        <div className="flex items-center gap-2 text-red-500">
          <XCircle className="h-5 w-5" />
          <span className="font-black italic uppercase tracking-tighter">Invalid</span>
        </div>
      );
    }

    if (data.days_remaining <= 7 && data.days_remaining > 0) {
      return (
        <div className="flex items-center gap-2 text-orange-500">
          <AlertTriangle className="h-5 w-5" />
          <span className="font-black italic uppercase tracking-tighter">Expiring Soon</span>
        </div>
      );
    }

    return (
      <div className="flex items-center gap-2 text-emerald-400">
        <CheckCircle className="h-5 w-5" />
        <span className="font-black italic uppercase tracking-tighter">Active Protocol</span>
      </div>
    );
  };

  const daysProgress = data.days_remaining === 0 && data.tier === 'osiris'
    ? 100
    : Math.min(100, (data.days_remaining / 365) * 100);

  return (
    <Card className="glass-card overflow-hidden border-white/5 shadow-2xl">
      <CardHeader className="border-b border-white/5 bg-white/2">
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2 text-xl font-black italic">
              <Key className="h-5 w-5 text-primary" />
              LICENSE STATUS
            </CardTitle>
            <CardDescription className="text-muted-foreground uppercase text-[10px] tracking-widest font-bold">
              Merkaba Tier: <span className="text-white">{data.organization}</span>
            </CardDescription>
          </div>
          {getTierBadge(data.tier)}
        </div>
      </CardHeader>
      <CardContent className="p-6 space-y-6">
        {/* Status Indicator */}
        <div className="flex items-center justify-between bg-white/5 p-4 rounded-xl border border-white/5">
          {getStatusIndicator()}
          <span className="text-[10px] text-muted-foreground font-mono bg-black/40 px-3 py-1 rounded-full border border-white/5">
            NODE: {data.machine_id.slice(0, 12)}...
          </span>
        </div>

        {/* Days Remaining / Progress */}
        <div className="space-y-3">
          <div className="flex justify-between text-[10px] uppercase font-bold tracking-widest">
            <span className="text-muted-foreground text-primary/60">Solar Phase Remaining</span>
            <span className="text-white">
              {data.days_remaining === 0 && data.tier === 'osiris'
                ? 'Perpetual (Eternal Sun)'
                : `${data.days_remaining} terrestrial days`}
            </span>
          </div>
          <Progress
            value={daysProgress}
            className="h-1.5 [&>div]:bg-primary bg-white/5"
          />
        </div>

        <Separator className="bg-white/5" />

        {/* License Details */}
        <div className="grid grid-cols-2 gap-6 text-[10px] uppercase font-bold tracking-widest">
          <div>
            <span className="text-muted-foreground block mb-1">Solar Birth</span>
            <div className="text-white font-mono">
              {new Date(data.issued_at).toLocaleDateString()}
            </div>
          </div>
          <div>
            <span className="text-muted-foreground block mb-1">Sunset Phase</span>
            <div className="text-white font-mono">
              {data.days_remaining === 0 && data.tier === 'osiris'
                ? '∞ OSIRIS RISE'
                : new Date(data.expires_at).toLocaleDateString()}
            </div>
          </div>
          {data.last_heartbeat && (
            <div className="col-span-2">
              <div className="flex items-center justify-between bg-white/5 p-3 rounded-lg">
                <div>
                  <span className="text-muted-foreground block mb-0.5">Last Sync Heartbeat</span>
                  <div className="text-emerald-400 font-mono">
                    {new Date(data.last_heartbeat).toLocaleString()}
                  </div>
                </div>
                <Button
                  variant="ghost"
                  onClick={handleHeartbeat}
                  disabled={heartbeat.isPending}
                  className="h-9 px-4 text-[9px] font-black tracking-widest bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/20 transition-all rounded-full"
                >
                  <Activity className={`h-3 w-3 mr-2 ${heartbeat.isPending ? 'animate-pulse' : ''}`} />
                  SYNC
                </Button>
              </div>
            </div>
          )}
        </div>

        <Separator className="bg-white/5" />

        {/* Features */}
        <div className="space-y-3">
          <h4 className="text-[10px] uppercase font-black tracking-widest text-primary">Deity Authorities</h4>
          <div className="grid grid-cols-2 gap-2">
            {data.features.map((feature) => (
              <div
                key={feature}
                className="flex items-center gap-2 text-[9px] font-bold uppercase tracking-widest bg-white/5 border border-white/5 rounded-lg px-3 py-2 text-muted-foreground hover:text-white hover:bg-white/10 transition-all"
              >
                {FEATURE_ICONS[feature] || <CheckCircle className="h-3 w-3 text-primary/60" />}
                <span className="truncate">
                  {feature.replaceAll('-', ' ')}
                </span>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
