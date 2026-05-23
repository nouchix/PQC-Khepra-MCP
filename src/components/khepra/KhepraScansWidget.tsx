import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useKhepraAPI } from '@/hooks/useKhepraAPI';
import { useKhepraScanUpdates, ScanUpdate } from '@/hooks/useKhepraWebSocket';
import {
  Play,
  CheckCircle,
  XCircle,
  Clock,
  Loader2,
  Shield,
  Bug,
  Lock,
  RefreshCw,
  Wifi,
  WifiOff,
  AlertCircle,
} from 'lucide-react';

interface KhepraScansWidgetProps {
  deploymentUrl: string;
  apiKey: string;
}

export function KhepraScansWidget({ deploymentUrl, apiKey }: KhepraScansWidgetProps) {
  const [targetUrl, setTargetUrl] = useState('');
  const [scanType, setScanType] = useState<string>('basic');

  const { triggerScan, health, license } = useKhepraAPI(deploymentUrl, apiKey);
  const { isConnected, scanUpdates, connectionError } = useKhepraScanUpdates(deploymentUrl);

  const handleTriggerScan = () => {
    if (!targetUrl) return;

    triggerScan.mutate({
      target_url: targetUrl,
      scan_type: scanType as any,
      priority: 5,
    });

    setTargetUrl('');
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'queued':
        return <Clock className="h-4 w-4 text-yellow-500" />;
      case 'running':
        return <Loader2 className="h-4 w-4 text-blue-500 animate-spin" />;
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'failed':
        return <XCircle className="h-4 w-4 text-red-500" />;
      default:
        return <Clock className="h-4 w-4 text-gray-500" />;
    }
  };

  const getStatusBadge = (status: string) => {
    const variants: Record<string, 'default' | 'secondary' | 'destructive' | 'outline'> = {
      queued: 'outline',
      running: 'secondary',
      completed: 'default',
      failed: 'destructive',
    };
    return (
      <Badge variant={variants[status] || 'outline'}>
        {status}
      </Badge>
    );
  };

  const currentTier = license.data?.tier || 'community';
  const isKhepri = currentTier === 'community' || currentTier === 'khepri';

  return (
    <Card className="glass-card overflow-hidden border-white/5 shadow-2xl">
      <CardHeader className="border-b border-white/5 bg-white/2">
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2 text-xl font-black italic">
              <Shield className="h-5 w-5 text-primary" />
              SECURITY SCANS
            </CardTitle>
            <CardDescription className="text-muted-foreground uppercase text-[10px] tracking-widest font-bold">
              Autonomous vulnerability discovery • Ra Core
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            {isConnected ? (
              <Badge variant="outline" className="text-primary border-primary/30 bg-primary/10 animate-pulse uppercase text-[9px]">
                <Wifi className="h-3 w-3 mr-1" />
                Live Sync
              </Badge>
            ) : (
              <Badge variant="outline" className="text-red-400 border-red-500/30 bg-red-500/10 uppercase text-[9px]">
                <WifiOff className="h-3 w-3 mr-1" />
                Air-Gapped
              </Badge>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-6 space-y-6">
        {/* New Scan Form */}
        <div className="flex flex-col gap-3">
          <div className="flex gap-2">
            <Input
              placeholder="Target URL / Enterprise IP"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              className="flex-1 bg-white/5 border-white/10 h-11 font-mono text-sm placeholder:text-muted-foreground/30"
            />
            <Select value={scanType} onValueChange={setScanType}>
              <SelectTrigger className="w-40 bg-white/5 border-white/10 h-11 text-xs font-bold">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="glass-card text-white border-white/10">
                <SelectItem value="basic">Basic Check</SelectItem>
                <SelectItem value="eval">Evaluation</SelectItem>
                <SelectItem value="full" disabled={isKhepri}>
                  Full Audit {isKhepri && '🔒'}
                </SelectItem>
                <SelectItem value="crypto" disabled={isKhepri}>
                  Crypto Scan {isKhepri && '🔒'}
                </SelectItem>
                <SelectItem value="stig" disabled={isKhepri}>
                  STIG Config {isKhepri && '🔒'}
                </SelectItem>
              </SelectContent>
            </Select>
            <Button
              onClick={handleTriggerScan}
              disabled={!targetUrl || triggerScan.isPending}
              className="bg-primary hover:bg-primary-glow text-primary-foreground font-black uppercase tracking-widest text-xs h-11 px-6 shadow-lg shadow-primary/20"
            >
              {triggerScan.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Play className="h-4 w-4" />
              )}
              <span className="ml-2">EXECUTE</span>
            </Button>
          </div>

          {triggerScan.isError && (
            <div className="bg-red-50 border border-red-100 rounded-lg p-2 text-xs text-red-600 flex items-center gap-1">
              <AlertCircle className="h-3 w-3" />
              <span>{triggerScan.error.message}</span>
            </div>
          )}
        </div>

        {/* Connection Error */}
        {connectionError && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-sm text-red-700">
            {connectionError}
          </div>
        )}

        {/* Health Status */}
        {health.data && (
          <div className="grid grid-cols-4 gap-2 text-sm">
            <div className="bg-muted rounded-lg p-2 text-center">
              <div className="text-muted-foreground">Status</div>
              <div className="font-medium capitalize">{health.data.status}</div>
            </div>
            <div className="bg-muted rounded-lg p-2 text-center">
              <div className="text-muted-foreground">DAG Nodes</div>
              <div className="font-medium">{health.data.dag_nodes}</div>
            </div>
            <div className="bg-muted rounded-lg p-2 text-center">
              <div className="text-muted-foreground">License</div>
              <div className="font-medium capitalize">{health.data.license_status}</div>
            </div>
            <div className="bg-muted rounded-lg p-2 text-center">
              <div className="text-muted-foreground">Uptime</div>
              <div className="font-medium">{Math.round(health.data.uptime_seconds / 60)}m</div>
            </div>
          </div>
        )}

        {/* Scan Updates */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <h4 className="text-sm font-medium">Recent Scans</h4>
            <Button variant="ghost" size="sm" onClick={() => health.refetch()}>
              <RefreshCw className="h-3 w-3" />
            </Button>
          </div>

          <ScrollArea className="h-64">
            {scanUpdates.length === 0 ? (
              <div className="text-center text-muted-foreground py-8">
                No scans yet. Trigger a scan to get started.
              </div>
            ) : (
              <div className="space-y-2">
                {scanUpdates.slice().reverse().map((scan: ScanUpdate, i) => (
                  <div
                    key={scan.scan_id || i}
                    className="border rounded-lg p-3 space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        {getStatusIcon(scan.status)}
                        <span className="font-mono text-xs truncate max-w-48">
                          {scan.scan_id?.slice(0, 8)}...
                        </span>
                      </div>
                      {getStatusBadge(scan.status)}
                    </div>

                    {scan.target_url && (
                      <div className="text-xs text-muted-foreground truncate">
                        {scan.target_url}
                      </div>
                    )}

                    {scan.progress !== undefined && scan.status === 'running' && (
                      <Progress value={scan.progress * 100} className="h-1" />
                    )}

                    {scan.results && (
                      <div className="flex gap-3 text-xs">
                        <div className="flex items-center gap-1 text-red-600">
                          <Bug className="h-3 w-3" />
                          {scan.results.vulnerabilities_found || 0} vulns
                        </div>
                        <div className="flex items-center gap-1 text-orange-600">
                          <Lock className="h-3 w-3" />
                          {scan.results.crypto_issues || 0} crypto
                        </div>
                        <div className="flex items-center gap-1 text-yellow-600">
                          <Shield className="h-3 w-3" />
                          {scan.results.stig_violations || 0} STIG
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </ScrollArea>
        </div>
      </CardContent>
    </Card>
  );
}
