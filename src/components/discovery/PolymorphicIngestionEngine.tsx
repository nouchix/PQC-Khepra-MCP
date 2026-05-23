import { useState, useMemo } from 'react';
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

import {
    Shield,
    Zap,
    Globe,

    Cpu,
    Activity,
    Code,
    Link as LinkIcon,
    Layers,
    Server,
    Cloud,
    ChevronRight,
    RefreshCw,
    Terminal,

    CheckCircle
} from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { toast } from "sonner";

interface PolymorphicIngestionEngineProps {
    organizationId: string;
}

const ENVIRONMENTS = [
    { id: 'aws', name: 'AWS Cloud', icon: Cloud, color: 'text-orange-400', profile: 'aws_sdk' },
    { id: 'azure', name: 'Azure Enclave', icon: Shield, color: 'text-blue-400', profile: 'azure_api' },
    { id: 'onprem', name: 'On-Prem / Data Center', icon: Server, color: 'text-slate-400', profile: 'custom_payload' },
    { id: 'iot_scada', name: 'IoT / SCADA / ICS', icon: Cpu, color: 'text-emerald-400', profile: 'custom_payload' },
    { id: 'api_enclave', name: 'Custom API Enclave', icon: Code, color: 'text-purple-400', profile: 'custom_payload' },
];

export const PolymorphicIngestionEngine: React.FC<PolymorphicIngestionEngineProps> = ({ organizationId }) => {
    const [selectedEnv, setSelectedEnv] = useState(ENVIRONMENTS[0]);
    const [rawPayload, setRawPayload] = useState(JSON.stringify({
        "InstanceId": "i-0abcdef1234567890",
        "InstanceType": "t3.medium",
        "PlatformDetails": "Linux/UNIX",
        "PrivateIpAddress": "10.0.1.24",
        "Tags": [{ "Key": "Name", "Value": "Sentinel-Gateway-01" }]
    }, null, 2));

    const [isProcessing, setIsProcessing] = useState(false);
    const [, setTransformedData] = useState<any>(null);

    // Mock transformation preview
    const transformationPreview = useMemo(() => {
        try {
            const data = JSON.parse(rawPayload);
            if (selectedEnv.id === 'aws') {
                return {
                    asset_name: data.Tags?.find((t: any) => t.Key === 'Name')?.Value || data.InstanceId,
                    asset_type: 'server',
                    platform: 'aws',
                    operating_system: data.PlatformDetails || 'Linux',
                    ip_addresses: [data.PrivateIpAddress].filter(Boolean),
                    cmmc_scope: 'CUI Environment'
                };
            } else if (selectedEnv.id === 'iot_scada') {
                return {
                    asset_name: data.device_id || 'Industrial Controller',
                    asset_type: 'OT/SCADA',
                    platform: 'Industrial-Mesh',
                    operating_system: 'Embedded-OS',
                    ip_addresses: [data.local_ip].filter(Boolean),
                    cmmc_scope: 'Critical Infrastructure'
                };
            }
            return { ...data, status: 'generic-mapped' };
        } catch {
            return { error: 'Invalid JSON payload' };
        }
    }, [rawPayload, selectedEnv]);

    const handleIngest = async () => {
        setIsProcessing(true);
        try {
            const sourceData = Array.isArray(JSON.parse(rawPayload)) ? JSON.parse(rawPayload) : [JSON.parse(rawPayload)];

            const { data, error } = await supabase.functions.invoke('polymorphic-schema-engine', {
                body: {
                    action: 'discover_assets',
                    organizationId,
                    environmentType: selectedEnv.id,
                    sourceProfile: selectedEnv.profile,
                    sourceData: sourceData
                }
            });

            if (error) throw error;

            setTransformedData(data);
            toast.success(`Polymorphic Engine: Successfully ingested ${data.count} assets from ${selectedEnv.name}`);
        } catch (error: any) {
            console.error('Ingestion error:', error);
            toast.error(`Ingestion Failed: ${error.message}`);
        } finally {
            setIsProcessing(false);
        }
    };

    return (
        <div className="space-y-6">
            {/* Engine Status Header */}
            <div className="flex items-center justify-between p-4 bg-indigo-500/5 rounded-2xl border border-indigo-500/20">
                <div className="flex items-center gap-4">
                    <div className="p-3 bg-indigo-500/10 rounded-xl">
                        <Zap className="h-6 w-6 text-indigo-400 animate-pulse" />
                    </div>
                    <div>
                        <h3 className="text-lg font-black text-white tracking-tight">Sentinel Polymorphic Ingestion Engine</h3>
                        <p className="text-xs text-slate-400 font-bold uppercase tracking-widest">Environment-Agnostic Asset Reconciliation</p>
                    </div>
                </div>
                <Badge variant="outline" className="bg-indigo-500/10 text-indigo-400 border-indigo-500/30 px-3 py-1">
                    v2.4-STABLE
                </Badge>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                {/* Step 1: Environment Selection */}
                <div className="lg:col-span-4 space-y-4">
                    <h4 className="text-[10px] font-black text-slate-500 uppercase tracking-[0.2em]">1. Select Source Environment</h4>
                    <div className="grid gap-2">
                        {ENVIRONMENTS.map((env) => (
                            <Button
                                key={env.id}
                                variant={selectedEnv.id === env.id ? "default" : "outline"}
                                className={`h-auto p-4 justify-start gap-4 border-slate-800 transition-all ${selectedEnv.id === env.id ? "bg-indigo-600 border-indigo-500 shadow-lg shadow-indigo-600/20" : "bg-slate-950/40 hover:bg-slate-900"
                                    }`}
                                onClick={() => setSelectedEnv(env)}
                            >
                                <div className={`p-2 rounded-lg ${selectedEnv.id === env.id ? "bg-white/10" : "bg-slate-800"}`}>
                                    <env.icon className={`h-4 w-4 ${selectedEnv.id === env.id ? "text-white" : env.color}`} />
                                </div>
                                <div className="text-left">
                                    <div className="text-sm font-bold">{env.name}</div>
                                    <div className={`text-[10px] ${selectedEnv.id === env.id ? "text-indigo-100" : "text-slate-500"}`}>
                                        {env.profile === 'custom_payload' ? 'Dynamic Schema' : 'Native API Connector'}
                                    </div>
                                </div>
                                {selectedEnv.id === env.id && <ChevronRight className="h-4 w-4 ml-auto opacity-50" />}
                            </Button>
                        ))}
                    </div>

                    <Card className="bg-slate-900/50 border-slate-800 mt-6">
                        <CardContent className="p-4 space-y-3">
                            <div className="flex items-center gap-2 text-indigo-400">
                                <Shield className="h-4 w-4" />
                                <span className="text-[10px] font-black uppercase tracking-widest">Logic: Agnostic Hook</span>
                            </div>
                            <p className="text-[11px] text-slate-400 leading-relaxed">
                                The platform uses a <strong>Polymorphic Schema Engine</strong> to normalize disparate data models. Whether it's a SCADA controller or a Cloud VM, it becomes a <strong>Sentinel Standard Asset</strong>.
                            </p>
                        </CardContent>
                    </Card>
                </div>

                {/* Step 2: Payload / API Config */}
                <div className="lg:col-span-8 space-y-4">
                    <h4 className="text-[10px] font-black text-slate-500 uppercase tracking-[0.2em]">2. Interface & Transformation Preview</h4>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {/* Raw Payload Input */}
                        <div className="space-y-2">
                            <div className="flex items-center justify-between">
                                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest flex items-center gap-2">
                                    <Terminal className="h-3 w-3" /> Source Raw Data (JSON)
                                </span>
                                <Badge variant="outline" className="text-[9px] border-slate-800">SCHEMA: {selectedEnv.profile.toUpperCase()}</Badge>
                            </div>
                            <textarea
                                className="w-full h-[300px] bg-slate-950 border border-slate-800 rounded-xl p-4 text-[11px] font-mono text-emerald-400 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all outline-none"
                                value={rawPayload}
                                onChange={(e) => setRawPayload(e.target.value)}
                            />
                        </div>

                        {/* Dynamic Transformation Preview */}
                        <div className="space-y-2">
                            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest flex items-center gap-2">
                                <Activity className="h-3 w-3" /> Polymorphic Mapping Preview
                            </span>
                            <div className="w-full h-[300px] bg-indigo-950/20 border border-indigo-500/20 rounded-xl p-4 overflow-hidden relative">
                                <div className="absolute inset-0 opacity-5 pointer-events-none">
                                    <div className="w-full h-full bg-[radial-gradient(circle,rgba(99,102,241,0.2)_1px,transparent_1px)] bg-[size:20px_20px]" />
                                </div>

                                <div className="relative space-y-4">
                                    {Object.entries(transformationPreview).map(([key, val]: [string, any]) => (
                                        <div key={key} className="flex flex-col gap-1">
                                            <span className="text-[9px] font-black text-indigo-400 uppercase tracking-tighter">{key.replaceAll('_', ' ')}</span>
                                            <div className="flex items-center gap-2">
                                                <span className="text-xs font-bold text-white">{Array.isArray(val) ? val.join(', ') : String(val)}</span>
                                                <CheckCircle className="h-3 w-3 text-emerald-500/50" />
                                            </div>
                                        </div>
                                    ))}

                                    <div className="pt-4 border-t border-indigo-500/10">
                                        <div className="flex items-center gap-2">
                                            <Layers className="h-3 w-3 text-indigo-400" />
                                            <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Enrichment Ready</span>
                                        </div>
                                        <div className="flex gap-2 mt-2">
                                            <Badge className="bg-slate-800 text-slate-400 text-[9px]">STIG-GEN-01</Badge>
                                            <Badge className="bg-slate-800 text-slate-400 text-[9px]">CMMC-L2</Badge>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <Button
                        className="w-full h-14 bg-indigo-600 hover:bg-indigo-700 text-white font-black uppercase tracking-[0.2em] shadow-xl shadow-indigo-600/20 group"
                        onClick={handleIngest}
                        disabled={isProcessing}
                    >
                        {isProcessing ? (
                            <RefreshCw className="h-5 w-5 animate-spin" />
                        ) : (
                            <>
                                Initialize Environment Handshake
                                <ChevronRight className="ml-2 h-5 w-5 group-hover:translate-x-1 transition-transform" />
                            </>
                        )}
                    </Button>
                </div>
            </div>

            {/* Connection Flow Diagram (Simplified) */}
            <Card className="bg-slate-950/40 border-slate-800">
                <CardContent className="p-6">
                    <div className="flex flex-col md:flex-row items-center justify-between gap-8 opacity-60 grayscale hover:grayscale-0 hover:opacity-100 transition-all">
                        {[
                            { step: '01', title: 'Agnostic Handshake', desc: 'Secure connection via API / Webhook / Agentless Scan', icon: LinkIcon },
                            { step: '02', title: 'Polymorphic Map', desc: 'Normalize schema into Sentinel Standard Data Objects', icon: Activity },
                            { step: '03', title: 'Regulatory Overlay', desc: 'Auto-map CMMC / STIG / NIST controls to discovery', icon: Shield },
                            { step: '04', title: 'Active Ingestion', desc: 'Live monitoring & Lifecycle management starts', icon: Globe }
                        ].map((item) => (
                            <div key={item.step} className="flex-1 flex flex-col items-center text-center space-y-2">
                                <div className="w-10 h-10 rounded-full bg-slate-800 flex items-center justify-center text-indigo-400 font-black border border-slate-700">
                                    <item.icon className="h-5 w-5" />
                                </div>
                                <div className="text-[10px] font-black text-indigo-500">{item.step}</div>
                                <div className="text-xs font-bold text-white">{item.title}</div>
                                <div className="text-[9px] text-slate-500 leading-tight max-w-[150px]">{item.desc}</div>
                            </div>
                        ))}
                    </div>
                </CardContent>
            </Card>
        </div>
    );
};
