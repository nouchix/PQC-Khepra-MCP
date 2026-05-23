import { useEffect, useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Slider } from '@/components/ui/slider';
import { useToast } from '@/components/ui/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { useSecurityEvents } from '@/hooks/useSecurityEvents';
import { useRiskScoring } from '@/hooks/useRiskScoring';
import { AlertTriangle, ActivitySquare, Rocket, Satellite, RefreshCw } from 'lucide-react';

const ThreatDetectionCenter = () => {
  const { toast } = useToast();
  const { events, refetch } = useSecurityEvents();
  const { weights, setWeights, applyScores } = useRiskScoring();
  const [syncing, setSyncing] = useState(false);

  useEffect(() => {
    refetch();
  }, []);

  const handleTaxiiSync = async () => {
    setSyncing(true);
    try {
      const { error } = await supabase.functions.invoke('stix-taxii-sync', {
        body: { action: 'sync_all' }
      });
      if (error) throw error;
      toast({ title: 'STIX/TAXII Sync Triggered', description: 'Threat indicators are being synchronized.' });
      refetch();
    } catch (e: any) {
      toast({ title: 'Sync Error', description: e.message, variant: 'destructive' });
    } finally {
      setSyncing(false);
    }
  };

  const getSeverityVariant = (severity: string) => {
    if (severity === 'CRITICAL') return 'destructive';
    if (severity === 'WARNING') return 'secondary';
    return 'outline';
  };

  const highRisk = applyScores(events).slice(0, 8);

  return (
    <div className="space-y-6">
      <Card className="card-cyber">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ActivitySquare className="h-5 w-5" />
            Threat Detection Center
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="space-y-4">
              <h3 className="font-semibold">STIX/TAXII Integration</h3>
              <p className="text-sm text-muted-foreground">Pull indicators from trusted TAXII servers and map into your threat intel.</p>
              <Button onClick={handleTaxiiSync} disabled={syncing}>
                <RefreshCw className={`h-4 w-4 mr-2 ${syncing ? 'animate-spin' : ''}`} />
                {syncing ? 'Syncing…' : 'Sync STIX/TAXII'}
              </Button>
              <Separator className="my-4" />
              <h3 className="font-semibold flex items-center gap-2"><Satellite className="h-4 w-4" /> Falco/eBPF Feed</h3>
              <p className="text-sm text-muted-foreground">Point Falco Sidekick webhook to the falco-webhook function to ingest runtime detections.</p>
              <code className="text-xs bg-muted p-2 rounded block break-all">
                {`https://xjknkjbrjgljuovaazeu.functions.supabase.co/falco-webhook`}
              </code>
            </div>

            <div className="lg:col-span-2 space-y-4">
              <h3 className="font-semibold">Top Risk Events</h3>
              <div className="space-y-2">
                {highRisk.length === 0 && <p className="text-sm text-muted-foreground">No events yet.</p>}
                {highRisk.map(ev => (
                  <div key={ev.id} className="flex items-center justify-between rounded-md border p-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <Badge variant={getSeverityVariant(ev.severity)}>
                          {ev.severity}
                        </Badge>
                        <span className="font-medium">{ev.event_type}</span>
                      </div>
                      <p className="text-xs text-muted-foreground">{ev.source_system}</p>
                    </div>
                    <div className="text-right">
                      <div className="text-2xl font-bold">{ev.risk_score_weighted}</div>
                      <div className="text-xs text-muted-foreground">weighted risk</div>
                    </div>
                  </div>
                ))}
              </div>

              <Separator className="my-2" />
              <div className="space-y-3">
                <h4 className="font-semibold flex items-center gap-2"><Rocket className="h-4 w-4" /> Risk Weighting</h4>
                {(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const).map(level => (
                  <div key={level} className="grid grid-cols-4 items-center gap-3">
                    <span className="text-sm col-span-1">{level}</span>
                    <div className="col-span-3">
                      <Slider value={[Math.round((weights.severity as any)[level] * 100)]}
                        onValueChange={v => setWeights(w => ({ ...w, severity: { ...w.severity, [level]: v[0] / 100 } }))}
                      />
                    </div>
                  </div>
                ))}
                <p className="text-xs text-muted-foreground">Tune how severity levels impact overall risk. Source boosts applied for Falco and Threat Feeds.</p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="card-cyber">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5" />
            Recent Falco Alerts
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {events.filter(e => (e.source_system || '').toLowerCase().includes('falco')).slice(0, 10).map(e => (
              <div key={e.id} className="rounded-md border p-3">
                <div className="flex items-center gap-2">
                  <Badge variant={getSeverityVariant(e.severity)}>
                    {e.severity}
                  </Badge>
                  <span className="font-medium">{e.event_type}</span>
                </div>
                <p className="text-xs text-muted-foreground mt-1">{e.source_system}</p>
              </div>
            ))}
            {events.filter(e => (e.source_system || '').toLowerCase().includes('falco')).length === 0 && (
              <p className="text-sm text-muted-foreground">No Falco events yet. Configure your webhook to start receiving alerts.</p>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default ThreatDetectionCenter;
