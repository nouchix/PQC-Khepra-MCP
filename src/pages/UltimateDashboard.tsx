import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Shield, AlertTriangle, Activity, Eye, MessageSquare, Settings } from "lucide-react";
import { useQuery } from "@tanstack/react-query";

// Import sovereignty modules
import ExecutiveSovereignty from "@/components/dashboard/ExecutiveSovereignty";
import ComplianceSovereignty from "@/components/dashboard/ComplianceSovereignty";
import SecOpsSovereignty from "@/components/dashboard/SecOpsSovereignty";
import IntelligenceSovereignty from "@/components/dashboard/IntelligenceSovereignty";
import AdminSovereignty from "@/components/dashboard/AdminSovereignty";
import PapyrusWizard from "@/components/dashboard/PapyrusWizard";

const UltimateDashboard = () => {
    const [activeTab, setActiveTab] = useState("executive");
    const [papyrusOpen, setPapyrusOpen] = useState(false);
    const [dagData, setDagData] = useState<any>(null);

    // Fetch dashboard health status
    const { data: healthStatus } = useQuery({
        queryKey: ["dashboard-health"],
        queryFn: async () => {
            const response = await fetch("/api/v1/");
            return response.json();
        },
        refetchInterval: 30000, // Refresh every 30s
    });

    // WebSocket connection for real-time DAG updates
    useEffect(() => {
        const protocol = globalThis.location.protocol === "https:" ? "wss:" : "ws:";
        const wsUrl = `${protocol}//${globalThis.location.host}/ws/dag`;

        const ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            console.log("WebSocket connected for real-time DAG updates");
        };

        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            setDagData(data);
        };

        ws.onerror = (error) => {
            console.error("WebSocket error:", error);
        };

        ws.onclose = () => {
            console.log("WebSocket disconnected");
        };

        return () => {
            ws.close();
        };
    }, []);

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
            {/* Header */}
            <div className="border-b border-slate-800 bg-slate-950/50 backdrop-blur-sm sticky top-0 z-40">
                <div className="container mx-auto px-6 py-4">
                    <div className="flex items-center justify-between">
                        <div>
                            <h1 className="text-3xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
                                SouHimBou AI
                            </h1>
                            <p className="text-sm text-slate-400 mt-1">
                                Trust Constellation • Single Pane of Glass
                            </p>
                        </div>
                        <div className="flex items-center gap-4">
                            <div className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800/50 border border-slate-700">
                                <div className={`w-2 h-2 rounded-full ${healthStatus?.status === "ONLINE" ? "bg-green-500" : "bg-yellow-500"} animate-pulse`} />
                                <span className="text-sm text-slate-300">
                                    {healthStatus?.status || "INITIALIZING"}
                                </span>
                            </div>
                            {dagData && (
                                <div className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800/50 border border-slate-700">
                                    <div className="w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
                                    <span className="text-sm text-slate-300">
                                        Live: {dagData.stats?.nodes || 0} nodes
                                    </span>
                                </div>
                            )}
                            <button
                                onClick={() => setPapyrusOpen(!papyrusOpen)}
                                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 transition-all"
                            >
                                <MessageSquare className="w-4 h-4" />
                                <span className="text-sm font-medium">Papyrus Guide</span>
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            {/* Main Content */}
            <div className="container mx-auto px-6 py-8">
                <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
                    <TabsList className="grid w-full grid-cols-5 bg-slate-900/50 border border-slate-800">
                        <TabsTrigger value="executive" className="data-[state=active]:bg-gradient-to-r data-[state=active]:from-cyan-600 data-[state=active]:to-blue-600">
                            <Shield className="w-4 h-4 mr-2" />
                            Executive
                        </TabsTrigger>
                        <TabsTrigger value="compliance" className="data-[state=active]:bg-gradient-to-r data-[state=active]:from-green-600 data-[state=active]:to-emerald-600">
                            <Activity className="w-4 h-4 mr-2" />
                            Compliance
                        </TabsTrigger>
                        <TabsTrigger value="secops" className="data-[state=active]:bg-gradient-to-r data-[state=active]:from-orange-600 data-[state=active]:to-red-600">
                            <AlertTriangle className="w-4 h-4 mr-2" />
                            SecOps
                        </TabsTrigger>
                        <TabsTrigger value="intelligence" className="data-[state=active]:bg-gradient-to-r data-[state=active]:from-purple-600 data-[state=active]:to-pink-600">
                            <Eye className="w-4 h-4 mr-2" />
                            Intelligence
                        </TabsTrigger>
                        <TabsTrigger value="admin" className="data-[state=active]:bg-gradient-to-r data-[state=active]:from-slate-600 data-[state=active]:to-slate-700">
                            <Settings className="w-4 h-4 mr-2" />
                            Admin
                        </TabsTrigger>
                    </TabsList>

                    <TabsContent value="executive" className="space-y-6">
                        <ExecutiveSovereignty />
                    </TabsContent>

                    <TabsContent value="compliance" className="space-y-6">
                        <ComplianceSovereignty />
                    </TabsContent>

                    <TabsContent value="secops" className="space-y-6">
                        <SecOpsSovereignty />
                    </TabsContent>

                    <TabsContent value="intelligence" className="space-y-6">
                        <IntelligenceSovereignty />
                    </TabsContent>

                    <TabsContent value="admin" className="space-y-6">
                        <AdminSovereignty />
                    </TabsContent>
                </Tabs>
            </div>

            {/* Papyrus Wizard Overlay */}
            <PapyrusWizard open={papyrusOpen} onClose={() => setPapyrusOpen(false)} currentView={activeTab} />
        </div>
    );
};

export default UltimateDashboard;
