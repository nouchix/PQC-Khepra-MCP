import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { TrendingUp, DollarSign, AlertCircle, CheckCircle } from "lucide-react";

const ExecutiveSovereignty = () => {
    // Mock data - will be replaced with API calls
    const riskExposure = "$5.2M";
    const complianceScore = 78;
    const criticalFindings = 5;

    const topThreats = [
        { id: 1, title: "SSH Port 22 Exposed to Internet", severity: "CRITICAL", impact: "$1.2M" },
        { id: 2, title: "Unpatched CVE-2024-1234 (RCE)", severity: "CRITICAL", impact: "$890K" },
        { id: 3, title: "Weak TLS Configuration (Legacy Crypto)", severity: "HIGH", impact: "$650K" },
        { id: 4, title: "Missing MFA on Admin Accounts", severity: "HIGH", impact: "$420K" },
        { id: 5, title: "Outdated Windows Server 2012", severity: "MEDIUM", impact: "$310K" },
    ];

    return (
        <div className="space-y-6">
            {/* KPI Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <Card className="bg-gradient-to-br from-red-950/50 to-red-900/30 border-red-800">
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2 text-red-400">
                            <DollarSign className="w-5 h-5" />
                            Risk Exposure
                        </CardTitle>
                    </CardHeader>
                    <CardContent>
                        <div className="text-4xl font-bold text-red-300">{riskExposure}</div>
                        <p className="text-sm text-red-400/70 mt-2">Potential financial loss from current vulnerabilities</p>
                    </CardContent>
                </Card>

                <Card className="bg-gradient-to-br from-yellow-950/50 to-yellow-900/30 border-yellow-800">
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2 text-yellow-400">
                            <TrendingUp className="w-5 h-5" />
                            Compliance Score
                        </CardTitle>
                    </CardHeader>
                    <CardContent>
                        <div className="text-4xl font-bold text-yellow-300">{complianceScore}%</div>
                        <p className="text-sm text-yellow-400/70 mt-2">CMMC Level 2 - Incomplete</p>
                    </CardContent>
                </Card>

                <Card className="bg-gradient-to-br from-orange-950/50 to-orange-900/30 border-orange-800">
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2 text-orange-400">
                            <AlertCircle className="w-5 h-5" />
                            Critical Findings
                        </CardTitle>
                    </CardHeader>
                    <CardContent>
                        <div className="text-4xl font-bold text-orange-300">{criticalFindings}</div>
                        <p className="text-sm text-orange-400/70 mt-2">Require immediate executive attention</p>
                    </CardContent>
                </Card>
            </div>

            {/* Top Threats Table */}
            <Card className="bg-slate-900/50 border-slate-800">
                <CardHeader>
                    <CardTitle className="text-slate-200">Top 5 Threats</CardTitle>
                    <CardDescription>Prioritized by business impact</CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="space-y-4">
                        {topThreats.map((threat, index) => (
                            <div
                                key={threat.id}
                                className="flex items-center justify-between p-4 rounded-lg bg-slate-800/50 border border-slate-700 hover:border-slate-600 transition-colors"
                            >
                                <div className="flex items-center gap-4">
                                    <div className="flex items-center justify-center w-8 h-8 rounded-full bg-slate-700 text-slate-300 font-bold">
                                        {index + 1}
                                    </div>
                                    <div>
                                        <h4 className="font-medium text-slate-200">{threat.title}</h4>
                                        <div className="flex items-center gap-2 mt-1">
                                            <span
                                                className={`px-2 py-1 rounded text-xs font-medium ${threat.severity === "CRITICAL"
                                                        ? "bg-red-900/50 text-red-300"
                                                        : threat.severity === "HIGH"
                                                            ? "bg-orange-900/50 text-orange-300"
                                                            : "bg-yellow-900/50 text-yellow-300"
                                                    }`}
                                            >
                                                {threat.severity}
                                            </span>
                                        </div>
                                    </div>
                                </div>
                                <div className="text-right">
                                    <div className="text-lg font-bold text-red-400">{threat.impact}</div>
                                    <div className="text-xs text-slate-500">Estimated Impact</div>
                                </div>
                            </div>
                        ))}
                    </div>
                </CardContent>
            </Card>
        </div>
    );
};

export default ExecutiveSovereignty;
