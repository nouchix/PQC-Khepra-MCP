import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Eye, Globe, Shield, Zap, Radar, Activity } from "lucide-react";

const IntelligenceSovereignty = () => {
    // Mock data - will be replaced with real API calls
    const cisaKevCount = 12;
    const shodanAssets = 8;
    const pqcScore = 65;

    return (
        <div className="space-y-6">
            {/* CISA KEV Feed */}
            <Card className="bg-slate-900/50 border-slate-800">
                <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-slate-200">
                        <Eye className="w-5 h-5" />
                        CISA Known Exploited Vulnerabilities
                    </CardTitle>
                    <CardDescription>Real-time correlation with actively exploited CVEs</CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="space-y-4">
                        <div className="flex items-center justify-between p-4 rounded-lg bg-red-950/30 border border-red-900">
                            <div>
                                <h4 className="font-medium text-red-300">Active KEV Matches</h4>
                                <p className="text-sm text-slate-400 mt-1">Vulnerabilities in your environment on CISA's list</p>
                            </div>
                            <div className="text-3xl font-bold text-red-400">{cisaKevCount}</div>
                        </div>

                        <div className="space-y-2">
                            <div className="p-3 rounded-lg bg-slate-800/50 border border-slate-700">
                                <div className="flex items-center justify-between">
                                    <div>
                                        <div className="text-sm font-medium text-slate-200">CVE-2024-1234</div>
                                        <div className="text-xs text-slate-500 mt-1">Apache Log4j RCE</div>
                                    </div>
                                    <span className="px-2 py-1 rounded text-xs font-medium bg-red-900/50 text-red-300">
                                        EXPLOITED
                                    </span>
                                </div>
                            </div>
                            <div className="p-3 rounded-lg bg-slate-800/50 border border-slate-700">
                                <div className="flex items-center justify-between">
                                    <div>
                                        <div className="text-sm font-medium text-slate-200">CVE-2024-5678</div>
                                        <div className="text-xs text-slate-500 mt-1">Windows SMB Vulnerability</div>
                                    </div>
                                    <span className="px-2 py-1 rounded text-xs font-medium bg-red-900/50 text-red-300">
                                        EXPLOITED
                                    </span>
                                </div>
                            </div>
                        </div>
                    </div>
                </CardContent>
            </Card>

            {/* Shodan External View */}
            <Card className="bg-slate-900/50 border-slate-800">
                <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-slate-200">
                        <Globe className="w-5 h-5" />
                        Shodan External Asset View
                    </CardTitle>
                    <CardDescription>Attacker's perspective of your internet-facing assets</CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="space-y-4">
                        <div className="flex items-center justify-between p-4 rounded-lg bg-orange-950/30 border border-orange-900">
                            <div>
                                <h4 className="font-medium text-orange-300">Exposed Assets</h4>
                                <p className="text-sm text-slate-400 mt-1">Internet-facing services detected</p>
                            </div>
                            <div className="text-3xl font-bold text-orange-400">{shodanAssets}</div>
                        </div>

                        <div className="space-y-2">
                            <div className="p-3 rounded-lg bg-slate-800/50 border border-slate-700">
                                <div className="flex items-center justify-between">
                                    <div>
                                        <div className="text-sm font-medium text-slate-200">192.168.1.100:22</div>
                                        <div className="text-xs text-slate-500 mt-1">SSH Server (OpenSSH 7.4)</div>
                                    </div>
                                    <span className="px-2 py-1 rounded text-xs font-medium bg-red-900/50 text-red-300">
                                        CRITICAL
                                    </span>
                                </div>
                            </div>
                            <div className="p-3 rounded-lg bg-slate-800/50 border border-slate-700">
                                <div className="flex items-center justify-between">
                                    <div>
                                        <div className="text-sm font-medium text-slate-200">192.168.1.101:443</div>
                                        <div className="text-xs text-slate-500 mt-1">HTTPS (TLS 1.2)</div>
                                    </div>
                                    <span className="px-2 py-1 rounded text-xs font-medium bg-yellow-900/50 text-yellow-300">
                                        MEDIUM
                                    </span>
                                </div>
                            </div>
                        </div>
                    </div>
                </CardContent>
            </Card>

            {/* PQC Status */}
            <Card className="bg-slate-900/50 border-slate-800">
                <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-slate-200">
                        <Shield className="w-5 h-5" />
                        Post-Quantum Cryptography Status
                    </CardTitle>
                    <CardDescription>Quantum-safety rating of cryptographic assets</CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="space-y-4">
                        <div className="flex items-center justify-between p-4 rounded-lg bg-purple-950/30 border border-purple-900">
                            <div>
                                <h4 className="font-medium text-purple-300">PQC Readiness Score</h4>
                                <p className="text-sm text-slate-400 mt-1">Percentage of quantum-safe cryptography</p>
                            </div>
                            <div className="text-3xl font-bold text-purple-400">{pqcScore}%</div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div className="p-4 rounded-lg bg-slate-800/50 border border-slate-700">
                                <div className="flex items-center gap-2 mb-2">
                                    <Zap className="w-4 h-4 text-green-500" />
                                    <h4 className="text-sm font-medium text-slate-200">Quantum-Safe</h4>
                                </div>
                                <div className="text-2xl font-bold text-green-400">15</div>
                                <div className="text-xs text-slate-500 mt-1">Kyber/Dilithium keys</div>
                            </div>

                            <div className="p-4 rounded-lg bg-slate-800/50 border border-slate-700">
                                <div className="flex items-center gap-2 mb-2">
                                    <Zap className="w-4 h-4 text-red-500" />
                                    <h4 className="text-sm font-medium text-slate-200">Legacy Crypto</h4>
                                </div>
                                <div className="text-2xl font-bold text-red-400">8</div>
                                <div className="text-xs text-slate-500 mt-1">RSA/ECDSA keys</div>
                            </div>
                        </div>

                        <button className="w-full p-3 rounded-lg bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white font-medium transition-all">
                            Start PQC Migration
                        </button>
                    </div>
                </CardContent>
            </Card>

            {/* Threat Hunting & Forensics Overlay */}
            <Card className="bg-slate-900/50 border-slate-800 relative overflow-hidden">
                <div className="absolute top-0 right-0 p-4 opacity-10">
                    <Radar className="w-24 h-24 text-red-500" />
                </div>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-slate-200">
                        <Radar className="w-5 h-5 text-red-500" />
                        Sentinel Threat Hunting
                    </CardTitle>
                    <CardDescription>Advanced behavioral forensics and cross-process analysis</CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="space-y-4">
                        <div className="p-4 rounded-lg bg-red-950/20 border border-red-900/30">
                            <div className="flex items-center gap-3">
                                <Activity className="w-5 h-5 text-red-400" />
                                <div>
                                    <h4 className="text-sm font-medium text-slate-200">Behavioral Timeline Active</h4>
                                    <p className="text-xs text-slate-400 mt-0.5">ProcDot-ready visualization of system mutations</p>
                                </div>
                            </div>
                        </div>

                        <button
                            onClick={() => globalThis.location.href = '/threat-hunting'}
                            className="w-full p-3 rounded-lg border border-red-500/50 text-red-400 hover:bg-red-500/10 font-medium transition-all flex items-center justify-center gap-2"
                        >
                            <Zap className="w-4 h-4" />
                            Launch Forensics Intelligence
                        </button>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
};

export default IntelligenceSovereignty;
