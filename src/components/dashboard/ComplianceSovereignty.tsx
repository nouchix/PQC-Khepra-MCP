import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useQuery } from "@tanstack/react-query";
import { CheckCircle, XCircle, AlertCircle, FileText } from "lucide-react";

const ComplianceSovereignty = () => {
    // Fetch CMMC status from API
    const { data: cmmcData, isLoading } = useQuery({
        queryKey: ["cmmc-status"],
        queryFn: async () => {
            const response = await fetch("/api/v1/compliance/cmmc");
            return response.json();
        },
    });

    if (isLoading) {
        return <div className="text-slate-400">Loading compliance data...</div>;
    }

    const domains = cmmcData?.domains || {};

    return (
        <div className="space-y-6">
            {/* CMMC Score Card */}
            <Card className="bg-gradient-to-br from-green-950/50 to-emerald-900/30 border-green-800">
                <CardHeader>
                    <CardTitle className="text-green-400">CMMC Level 2 Scorecard</CardTitle>
                    <CardDescription>Current compliance posture</CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="flex items-center justify-between">
                        <div>
                            <div className="text-5xl font-bold text-green-300">{cmmcData?.score}%</div>
                            <p className="text-sm text-green-400/70 mt-2">{cmmcData?.level}</p>
                        </div>
                        <div className="text-right">
                            <div className="text-2xl font-bold text-slate-300">
                                {cmmcData?.controls?.passing}/{cmmcData?.controls?.total}
                            </div>
                            <p className="text-sm text-slate-500">Controls Passing</p>
                        </div>
                    </div>
                </CardContent>
            </Card>

            {/* Domain Breakdown */}
            <Card className="bg-slate-900/50 border-slate-800">
                <CardHeader>
                    <CardTitle className="text-slate-200">CMMC Domains</CardTitle>
                    <CardDescription>Compliance status by control family</CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {Object.entries(domains).map(([domain, data]: [string, any]) => (
                            <div
                                key={domain}
                                className="flex items-center justify-between p-4 rounded-lg bg-slate-800/50 border border-slate-700"
                            >
                                <div className="flex items-center gap-3">
                                    {data.status === "PASS" ? (
                                        <CheckCircle className="w-5 h-5 text-green-500" />
                                    ) : data.status === "WARN" ? (
                                        <AlertCircle className="w-5 h-5 text-yellow-500" />
                                    ) : (
                                        <XCircle className="w-5 h-5 text-red-500" />
                                    )}
                                    <div>
                                        <h4 className="font-medium text-slate-200">{domain}</h4>
                                        <p className="text-xs text-slate-500">{getDomainName(domain)}</p>
                                    </div>
                                </div>
                                <div className="text-right">
                                    <div className="text-lg font-bold text-slate-300">{data.score}%</div>
                                    <span
                                        className={`text-xs px-2 py-1 rounded ${data.status === "PASS"
                                                ? "bg-green-900/50 text-green-300"
                                                : data.status === "WARN"
                                                    ? "bg-yellow-900/50 text-yellow-300"
                                                    : "bg-red-900/50 text-red-300"
                                            }`}
                                    >
                                        {data.status}
                                    </span>
                                </div>
                            </div>
                        ))}
                    </div>
                </CardContent>
            </Card>

            {/* SSP Manager */}
            <Card className="bg-slate-900/50 border-slate-800">
                <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-slate-200">
                        <FileText className="w-5 h-5" />
                        System Security Plan (SSP)
                    </CardTitle>
                    <CardDescription>Digital SSP management and evidence collection</CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="space-y-3">
                        <button className="w-full p-4 rounded-lg bg-slate-800/50 border border-slate-700 hover:border-slate-600 transition-colors text-left">
                            <div className="flex items-center justify-between">
                                <div>
                                    <h4 className="font-medium text-slate-200">View SSP Document</h4>
                                    <p className="text-sm text-slate-500 mt-1">Last updated: 2 days ago</p>
                                </div>
                                <div className="text-green-400 text-sm font-medium">CURRENT</div>
                            </div>
                        </button>
                        <button className="w-full p-4 rounded-lg bg-slate-800/50 border border-slate-700 hover:border-slate-600 transition-colors text-left">
                            <div className="flex items-center justify-between">
                                <div>
                                    <h4 className="font-medium text-slate-200">Upload Evidence</h4>
                                    <p className="text-sm text-slate-500 mt-1">Attach POE for controls</p>
                                </div>
                                <div className="text-blue-400 text-sm font-medium">ACTION</div>
                            </div>
                        </button>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
};

// Helper function to get full domain names
const getDomainName = (code: string): string => {
    const names: Record<string, string> = {
        AC: "Access Control",
        AU: "Audit & Accountability",
        SC: "System & Communications Protection",
        IR: "Incident Response",
    };
    return names[code] || code;
};

export default ComplianceSovereignty;
