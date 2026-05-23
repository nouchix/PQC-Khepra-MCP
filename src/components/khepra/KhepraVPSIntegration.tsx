import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';

import { useKhepraAPI } from '@/hooks/useKhepraAPI';
import {
    Server,
    Shield,
    Globe,
    Key,
    RefreshCw,
    CheckCircle,
    XCircle,
    Info,
    ExternalLink,
} from 'lucide-react';

interface KhepraVPSIntegrationProps {
    config: {
        deploymentUrl: string;
        apiKey: string;
    };
    updateConfig: (url: string, key: string) => Promise<void>;
    isUpdating: boolean;
}

export function KhepraVPSIntegration({ config, updateConfig, isUpdating }: KhepraVPSIntegrationProps) {
    const [url, setUrl] = useState(config.deploymentUrl);
    const [key, setKey] = useState(config.apiKey);

    const { health } = useKhepraAPI(url, key);
    const isConnected = health.data?.status === 'healthy';

    useEffect(() => {
        setUrl(config.deploymentUrl);
        setKey(config.apiKey);
    }, [config]);

    const handleSave = async () => {
        await updateConfig(url, key);
    };

    return (
        <Card className="glass-card overflow-hidden border-white/5 shadow-2xl group animate-fade-in">
            <div className="h-1 bg-gradient-to-r from-primary via-primary/50 to-transparent opacity-50" />
            <CardHeader className="border-b border-white/5 bg-white/2">
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                        <div className="p-3 rounded-xl bg-primary/10 border border-primary/20 shadow-lg shadow-primary/10">
                            <Server className="h-6 w-6 text-primary" />
                        </div>
                        <div>
                            <CardTitle className="text-2xl font-black italic tracking-tight uppercase">Private Deployment</CardTitle>
                            <CardDescription className="text-[10px] uppercase font-bold tracking-[0.2em] text-muted-foreground">
                                Hybrid Orchestration • Isolated Security Node
                            </CardDescription>
                        </div>
                    </div>
                    <Badge
                        variant="outline"
                        className={isConnected
                            ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30 font-black italic uppercase text-[10px] px-3 py-1"
                            : "bg-white/5 text-muted-foreground border-white/10 font-black italic uppercase text-[10px] px-3 py-1"
                        }
                    >
                        {isConnected ? (
                            <span className="flex items-center gap-1.5 animate-pulse">
                                <CheckCircle className="h-3 w-3" /> LINKED
                            </span>
                        ) : (
                            <span className="flex items-center gap-1.5 opacity-50">
                                <XCircle className="h-3 w-3" /> DETACHED
                            </span>
                        )}
                    </Badge>
                </div>
            </CardHeader>
            <CardContent className="p-8 space-y-8">
                <div className="flex items-start gap-4 p-4 bg-primary/5 border border-primary/10 rounded-xl">
                    <Info className="h-5 w-5 text-primary mt-0.5" />
                    <div className="space-y-1">
                        <h4 className="text-xs font-black uppercase tracking-widest text-primary">Hybrid Protocol Active</h4>
                        <p className="text-[11px] text-muted-foreground leading-relaxed">
                            SouHimBou.AI is currently orchestrating security maneuvers through your private Khepra node.
                            All PQC handshakes and audit trails are persisted to your local DAG constellation.
                        </p>
                    </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                    <div className="space-y-3">
                        <Label htmlFor="vps-url" className="text-[10px] uppercase font-black tracking-widest text-primary/80 flex items-center gap-2">
                            <Globe className="h-3 w-3" />
                            Deployment Endpoint
                        </Label>
                        <Input
                            id="vps-url"
                            placeholder="https://khepra.internal.cloud"
                            value={url}
                            onChange={(e) => setUrl(e.target.value)}
                            className="bg-white/5 border-white/10 h-12 font-mono text-sm focus:ring-primary/20"
                        />
                    </div>

                    <div className="space-y-3">
                        <Label htmlFor="vps-key" className="text-[10px] uppercase font-black tracking-widest text-primary/80 flex items-center gap-2">
                            <Key className="h-3 w-3" />
                            Secret Environment Key
                        </Label>
                        <div className="relative">
                            <Input
                                id="vps-key"
                                type="password"
                                placeholder="kp_live_xxxxxxxxxxxx"
                                value={key}
                                onChange={(e) => setKey(e.target.value)}
                                className="bg-white/5 border-white/10 h-12 font-mono text-sm pr-12 focus:ring-primary/20"
                            />
                            <div className="absolute right-4 top-3.5 opacity-20 group-hover:opacity-100 transition-opacity">
                                <Shield className="h-5 w-5 text-primary" />
                            </div>
                        </div>
                    </div>
                </div>

                {health.data && (
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-6 p-6 bg-black/40 rounded-2xl border border-white/5">
                        <div className="space-y-1.5">
                            <span className="text-[9px] uppercase font-black tracking-widest text-muted-foreground block">Version</span>
                            <span className="text-sm font-mono font-bold text-white italic">{health.data.version || '0.0.0-PROTOTYPE'}</span>
                        </div>
                        <div className="space-y-1.5">
                            <span className="text-[9px] uppercase font-black tracking-widest text-muted-foreground block">Ledger Depth</span>
                            <span className="text-sm font-mono font-bold text-primary italic">{health.data.dag_nodes || 0} BLOCKS</span>
                        </div>
                        <div className="space-y-1.5">
                            <span className="text-[9px] uppercase font-black tracking-widest text-muted-foreground block">Merkaba Auth</span>
                            <span className="text-sm font-mono font-bold text-emerald-400 italic uppercase">AUTHORIZED</span>
                        </div>
                        <div className="space-y-1.5">
                            <span className="text-[9px] uppercase font-black tracking-widest text-muted-foreground block">Runtime</span>
                            <span className="text-sm font-mono font-bold text-white italic">
                                {Math.floor(health.data.uptime_seconds / 3600)}H {Math.floor((health.data.uptime_seconds % 3600) / 60)}M
                            </span>
                        </div>
                    </div>
                )}
            </CardContent>
            <CardFooter className="bg-black/60 border-t border-white/5 p-6 flex flex-col sm:flex-row items-center justify-between gap-6">
                <div className="flex items-center gap-4">
                    {url && (
                        <Button
                            variant="link"
                            size="sm"
                            className="text-[10px] uppercase font-black tracking-widest text-primary/60 hover:text-primary p-0 h-auto"
                            onClick={() => globalThis.open(`${url}/health`, '_blank')}
                        >
                            <ExternalLink className="h-3 w-3 mr-2" /> Raw Telemetry Stream
                        </Button>
                    )}
                </div>
                <div className="flex items-center gap-4 w-full sm:w-auto">
                    <Button
                        variant="outline"
                        className="flex-1 sm:flex-none h-11 border-white/10 bg-white/5 hover:bg-white/10 text-[10px] font-black uppercase tracking-widest px-6"
                        onClick={() => health.refetch()}
                        disabled={health.isRefetching || !url}
                    >
                        <RefreshCw className={`h-3 w-3 mr-2 ${health.isRefetching ? 'animate-spin' : ''}`} />
                        Verify Handshake
                    </Button>
                    <Button
                        className="flex-1 sm:flex-none h-11 bg-primary hover:bg-primary-glow text-primary-foreground text-[10px] font-black uppercase tracking-widest px-8 shadow-lg shadow-primary/20"
                        onClick={handleSave}
                        disabled={isUpdating || !url || (url === config?.deploymentUrl && key === config?.apiKey)}
                    >
                        {isUpdating ? <RefreshCw className="h-4 w-4 mr-2 animate-spin" /> : <CheckCircle className="h-4 w-4 mr-2" />}
                        COMMIT CONFIG
                    </Button>
                </div>
            </CardFooter>
        </Card>
    );
}
