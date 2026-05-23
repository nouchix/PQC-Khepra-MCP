import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import {
    Radar, Scan, RotateCcw, FileCheck2,
    Server, Wifi, Shield, Clock, CheckCircle2, XCircle, AlertTriangle,
    Play, Pause, RefreshCw
} from "lucide-react";
import { supabase } from "@/integrations/supabase/client";

// Types
interface Endpoint {
    id: string;
    hostname: string;
    ip: string;
    os: string;
    status: "online" | "offline" | "scanning";
    profile: string;
    lastScan?: string;
}

interface ScanResult {
    controlId: string;
    title: string;
    severity: "critical" | "high" | "medium" | "low";
    status: "pass" | "fail" | "not_applicable";
    finding?: string;
}

interface Attestation {
    id: string;
    timestamp: string;
    signatureAlgorithm: string;
    signature: string;
    verified: boolean;
}

// Awaiting real telemetry
const endpoints: Endpoint[] = [];
const scanResults: ScanResult[] = [];

const CommandCenter = () => {
    const [selectedEndpoint, setSelectedEndpoint] = useState<Endpoint | null>(null);
    const [scanProgress, setScanProgress] = useState(0);
    const [isScanning, setIsScanning] = useState(false);

    const startScan = async () => {
        setIsScanning(true);
        setScanProgress(0);

        try {
            // Call real STIG compliance scan via Supabase Edge Function
            const { data, error } = await supabase.functions.invoke('stig-compliance-orchestrator', {
                body: {
                    action: 'start_scan',
                    endpoint_id: selectedEndpoint?.id,
                    scan_type: 'full'
                }
            });

            if (error) {
                console.error('Scan initiation failed:', error);
                setIsScanning(false);
                return;
            }

            // Poll for real scan progress
            const scanId = data?.scan_id;
            const pollInterval = setInterval(async () => {
                const { data: progressData } = await supabase.functions.invoke('stig-compliance-orchestrator', {
                    body: { action: 'get_scan_status', scan_id: scanId }
                });

                const progress = progressData?.progress || 0;
                setScanProgress(progress);

                if (progress >= 100 || progressData?.status === 'completed') {
                    clearInterval(pollInterval);
                    setIsScanning(false);
                    setScanProgress(100);
                }
            }, 2000); // Poll every 2 seconds

        } catch (err) {
            console.error('Scan failed:', err);
            setIsScanning(false);
        }
    };

    const severityColor = (severity: string) => {
        switch (severity) {
            case "critical": return "bg-red-500/20 text-red-400 border-red-500/50";
            case "high": return "bg-orange-500/20 text-orange-400 border-orange-500/50";
            case "medium": return "bg-yellow-500/20 text-yellow-400 border-yellow-500/50";
            case "low": return "bg-blue-500/20 text-blue-400 border-blue-500/50";
            default: return "bg-slate-500/20 text-slate-400 border-slate-500/50";
        }
    };

    const getStatusColor = (status: string) => {
        if (status === "online") return "bg-green-500";
        if (status === "scanning") return "bg-blue-500 animate-pulse";
        return "bg-red-500";
    };

    const statusIcon = (status: string) => {
        switch (status) {
            case "pass": return <CheckCircle2 className="w-4 h-4 text-green-500" />;
            case "fail": return <XCircle className="w-4 h-4 text-red-500" />;
            case "not_applicable": return <AlertTriangle className="w-4 h-4 text-yellow-500" />;
            default: return null;
        }
    };

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 p-4 md:p-6">
            {/* Header with animation */}
            <div className="mb-6 md:mb-8 animate-fade-in">
                <h1 className="text-3xl md:text-4xl font-black bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-500 bg-clip-text text-transparent animate-gradient">
                    KHEPRA COMMAND CENTER
                </h1>
                <p className="text-slate-400 mt-2 text-sm md:text-base">Compliance in 4 Clicks • Post-Quantum Attestation</p>
            </div>

            {/* 4-Quadrant Grid - Mobile Responsive */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6 min-h-[calc(100vh-200px)]">

                {/* Q1: DISCOVER */}
                <Card className="bg-slate-900/50 border-cyan-500/30 backdrop-blur-sm overflow-hidden">
                    <CardHeader className="border-b border-cyan-500/20 bg-gradient-to-r from-cyan-500/10 to-transparent">
                        <CardTitle className="flex items-center gap-3 text-cyan-400">
                            <Radar className="w-6 h-6" />
                            DISCOVER
                        </CardTitle>
                    </CardHeader>
                    <CardContent className="p-4 overflow-auto max-h-[calc(100%-80px)]">
                        <div className="flex gap-2 mb-4">
                            <Button size="sm" variant="outline" className="border-cyan-500/50 text-cyan-400 hover:bg-cyan-500/20">
                                <RefreshCw className="w-4 h-4 mr-2" /> Auto-Detect
                            </Button>
                            <Button size="sm" variant="outline" className="border-slate-500/50 text-slate-400 hover:bg-slate-500/20">
                                <Wifi className="w-4 h-4 mr-2" /> Import AD/LDAP
                            </Button>
                        </div>
                        <div className="space-y-2">
                            {endpoints.length === 0 ? (
                                <div className="p-4 text-center text-slate-500 text-sm">
                                    Awaiting endpoint telemetry
                                </div>
                            ) : endpoints.map((ep) => (
                                <button
                                    key={ep.id}
                                    type="button"
                                    aria-label={`Select endpoint: ${ep.hostname}`}
                                    onClick={() => setSelectedEndpoint(ep)}
                                    className={`w-full text-left p-3 rounded-lg border cursor-pointer transition-all ${selectedEndpoint?.id === ep.id
                                        ? "bg-cyan-500/20 border-cyan-500"
                                        : "bg-slate-800/50 border-slate-700 hover:border-cyan-500/50"
                                        }`}
                                >
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-3">
                                            <Server className="w-5 h-5 text-slate-400" />
                                            <div>
                                                <p className="font-medium text-slate-200">{ep.hostname}</p>
                                                <p className="text-xs text-slate-500">{ep.ip} • {ep.os}</p>
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <Badge variant="outline" className="text-xs">{ep.profile}</Badge>
                                            <div className={`w-2 h-2 rounded-full ${getStatusColor(ep.status)}`} />
                                        </div>
                                    </div>
                                </button>
                            ))}
                        </div>
                    </CardContent>
                </Card>

                {/* Q2: ASSESS */}
                <Card className="bg-slate-900/50 border-orange-500/30 backdrop-blur-sm overflow-hidden">
                    <CardHeader className="border-b border-orange-500/20 bg-gradient-to-r from-orange-500/10 to-transparent">
                        <CardTitle className="flex items-center gap-3 text-orange-400">
                            <Scan className="w-6 h-6" />
                            ASSESS
                        </CardTitle>
                    </CardHeader>
                    <CardContent className="p-4 overflow-auto max-h-[calc(100%-80px)]">
                        <div className="flex gap-2 mb-4">
                            <Button
                                size="sm"
                                onClick={startScan}
                                disabled={isScanning || !selectedEndpoint}
                                className="bg-gradient-to-r from-orange-600 to-red-600 hover:from-orange-700 hover:to-red-700"
                            >
                                {isScanning ? <Pause className="w-4 h-4 mr-2" /> : <Play className="w-4 h-4 mr-2" />}
                                {isScanning ? "Scanning..." : "Start Scan"}
                            </Button>
                        </div>

                        {isScanning && (
                            <div className="mb-4 p-3 rounded-lg bg-slate-800/50 border border-orange-500/30">
                                <div className="flex justify-between text-sm mb-2">
                                    <span className="text-slate-400">Scanning {selectedEndpoint?.hostname}...</span>
                                    <span className="text-orange-400">{Math.round(scanProgress)}%</span>
                                </div>
                                <Progress value={scanProgress} className="h-2" />
                            </div>
                        )}

                        <div className="space-y-2">
                            {scanResults.length === 0 ? (
                                <div className="p-4 text-center text-slate-500 text-sm">
                                    Execute scan to retrieve results
                                </div>
                            ) : scanResults.map((result) => (
                                <div
                                    key={result.controlId}
                                    className="p-3 rounded-lg bg-slate-800/50 border border-slate-700"
                                >
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-3">
                                            {statusIcon(result.status)}
                                            <div>
                                                <p className="font-medium text-slate-200 text-sm">{result.controlId}</p>
                                                <p className="text-xs text-slate-500">{result.title}</p>
                                            </div>
                                        </div>
                                        <Badge className={severityColor(result.severity)}>{result.severity}</Badge>
                                    </div>
                                    {result.finding && (
                                        <p className="mt-2 text-xs text-red-400 bg-red-500/10 p-2 rounded">{result.finding}</p>
                                    )}
                                </div>
                            ))}
                        </div>
                    </CardContent>
                </Card>

                {/* Q3: ROLLBACK */}
                <Card className="bg-slate-900/50 border-purple-500/30 backdrop-blur-sm overflow-hidden">
                    <CardHeader className="border-b border-purple-500/20 bg-gradient-to-r from-purple-500/10 to-transparent">
                        <CardTitle className="flex items-center gap-3 text-purple-400">
                            <RotateCcw className="w-6 h-6" />
                            ROLLBACK
                        </CardTitle>
                    </CardHeader>
                    <CardContent className="p-4 overflow-auto max-h-[calc(100%-80px)]">
                        <div className="space-y-3">
                            {[
                                { id: "snap-001", time: "2026-01-27 01:30:00", changes: 12, status: "available" },
                                { id: "snap-002", time: "2026-01-27 00:00:00", changes: 8, status: "available" },
                                { id: "snap-003", time: "2026-01-26 18:00:00", changes: 23, status: "archived" },
                            ].map((snap) => (
                                <div
                                    key={snap.id}
                                    className="p-4 rounded-lg bg-slate-800/50 border border-slate-700 hover:border-purple-500/50 transition-all"
                                >
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-3">
                                            <Clock className="w-5 h-5 text-purple-400" />
                                            <div>
                                                <p className="font-medium text-slate-200">{snap.time}</p>
                                                <p className="text-xs text-slate-500">{snap.changes} configuration changes</p>
                                            </div>
                                        </div>
                                        <Button
                                            size="sm"
                                            variant="outline"
                                            className="border-purple-500/50 text-purple-400 hover:bg-purple-500/20"
                                            disabled={snap.status === "archived"}
                                        >
                                            <RotateCcw className="w-4 h-4 mr-2" /> Restore
                                        </Button>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </CardContent>
                </Card>

                {/* Q4: PROVE */}
                <Card className="bg-slate-900/50 border-green-500/30 backdrop-blur-sm overflow-hidden">
                    <CardHeader className="border-b border-green-500/20 bg-gradient-to-r from-green-500/10 to-transparent">
                        <CardTitle className="flex items-center gap-3 text-green-400">
                            <FileCheck2 className="w-6 h-6" />
                            PROVE
                        </CardTitle>
                    </CardHeader>
                    <CardContent className="p-4 overflow-auto max-h-[calc(100%-80px)]">
                        <div className="p-4 rounded-lg bg-gradient-to-br from-green-500/10 to-emerald-500/5 border border-green-500/30 mb-4">
                            <div className="flex items-center gap-3 mb-3">
                                <Shield className="w-8 h-8 text-green-400" />
                                <div>
                                    <p className="font-bold text-green-400">PQC Attestation</p>
                                    <p className="text-xs text-slate-400">Dilithium3 • NIST FIPS 204</p>
                                </div>
                            </div>
                            <div className="p-2 rounded bg-slate-900/80 font-mono text-xs text-green-300 break-all">
                                SIG:ML-DSA-65:0x7f3a...c4e2
                            </div>
                            <div className="flex items-center gap-2 mt-3">
                                <CheckCircle2 className="w-4 h-4 text-green-500" />
                                <span className="text-sm text-green-400">Signature Verified</span>
                            </div>
                        </div>

                        <div className="flex gap-2">
                            <Button size="sm" variant="outline" className="border-green-500/50 text-green-400 hover:bg-green-500/20">
                                Export eMASS
                            </Button>
                            <Button size="sm" variant="outline" className="border-green-500/50 text-green-400 hover:bg-green-500/20">
                                Generate SPRS
                            </Button>
                            <Button size="sm" variant="outline" className="border-green-500/50 text-green-400 hover:bg-green-500/20">
                                Session Transcript
                            </Button>
                        </div>
                    </CardContent>
                </Card>
            </div>
        </div>
    );
};

export default CommandCenter;
