import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useQuery } from "@tanstack/react-query";
import { Network, FileCode, AlertTriangle } from "lucide-react";
import { useState } from "react";

const SecOpsSovereignty = () => {
    const [selectedNode, setSelectedNode] = useState<string | null>(null);

    // Fetch DAG visualization data
    const { data: dagData, isLoading } = useQuery({
        queryKey: ["dag-visualize"],
        queryFn: async () => {
            const response = await fetch("/api/v1/dag/visualize");
            return response.json();
        },
    });

    // Fetch IR playbooks
    const { data: playbooks } = useQuery({
        queryKey: ["ir-playbooks"],
        queryFn: async () => {
            const response = await fetch("/api/v1/ir/playbooks");
            return response.json();
        },
    });

    if (isLoading) {
        return <div className="text-slate-400">Loading SecOps data...</div>;
    }

    return (
        <div className="space-y-6">
            {/* Trust Constellation (DAG Visualization) */}
            <Card className="bg-slate-900/50 border-slate-800">
                <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-slate-200">
                        <Network className="w-5 h-5" />
                        Trust Constellation (DAG)
                    </CardTitle>
                    <CardDescription>Interactive causal graph showing attack paths and evidence chains</CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="relative h-96 rounded-lg bg-slate-950 border border-slate-800 overflow-hidden">
                        {/* Simple SVG visualization - will be replaced with react-force-graph */}
                        <svg className="w-full h-full">
                            {/* Draw edges */}
                            {dagData?.edges?.map((edge: any, i: number) => {
                                const sourceNode = dagData.nodes.find((n: any) => n.id === edge.source);
                                const targetNode = dagData.nodes.find((n: any) => n.id === edge.target);
                                const x1 = (i * 200) + 100;
                                const y1 = 100;
                                const x2 = ((i + 1) * 200) + 100;
                                const y2 = 200;

                                return (
                                    <g key={i}>
                                        <line
                                            x1={x1}
                                            y1={y1}
                                            x2={x2}
                                            y2={y2}
                                            stroke="#475569"
                                            strokeWidth="2"
                                            markerEnd="url(#arrowhead)"
                                        />
                                        <text x={(x1 + x2) / 2} y={(y1 + y2) / 2} fill="#64748b" fontSize="10" textAnchor="middle">
                                            {edge.type}
                                        </text>
                                    </g>
                                );
                            })}

                            {/* Draw nodes */}
                            {dagData?.nodes?.map((node: any, i: number) => {
                                const x = (i * 200) + 100;
                                const y = i % 2 === 0 ? 100 : 200;
                                const color = node.status === "Critical" ? "#ef4444" : node.status === "Pending" ? "#f59e0b" : "#10b981";

                                return (
                                    <g key={node.id} onClick={() => setSelectedNode(node.id)} className="cursor-pointer">
                                        <circle
                                            cx={x}
                                            cy={y}
                                            r="30"
                                            fill={color}
                                            fillOpacity="0.2"
                                            stroke={color}
                                            strokeWidth="2"
                                        />
                                        <text x={x} y={y} fill={color} fontSize="12" textAnchor="middle" dominantBaseline="middle">
                                            {node.id.substring(0, 8)}
                                        </text>
                                        <text x={x} y={y + 50} fill="#94a3b8" fontSize="10" textAnchor="middle">
                                            {node.label}
                                        </text>
                                    </g>
                                );
                            })}

                            {/* Arrow marker definition */}
                            <defs>
                                <marker id="arrowhead" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto">
                                    <polygon points="0 0, 10 3, 0 6" fill="#475569" />
                                </marker>
                            </defs>
                        </svg>

                        {/* Stats overlay */}
                        <div className="absolute top-4 right-4 bg-slate-900/90 backdrop-blur-sm border border-slate-700 rounded-lg p-3">
                            <div className="text-xs text-slate-400">DAG Stats</div>
                            <div className="text-lg font-bold text-slate-200">{dagData?.stats?.nodes || 0} Nodes</div>
                            <div className="text-sm text-red-400">{dagData?.stats?.critical || 0} Critical</div>
                        </div>
                    </div>

                    {selectedNode && (
                        <div className="mt-4 p-4 rounded-lg bg-slate-800/50 border border-slate-700">
                            <h4 className="font-medium text-slate-200">Selected Node: {selectedNode}</h4>
                            <p className="text-sm text-slate-400 mt-1">Click nodes to view details and causal relationships</p>
                        </div>
                    )}
                </CardContent>
            </Card>

            {/* Playbook Hub */}
            <Card className="bg-slate-900/50 border-slate-800">
                <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-slate-200">
                        <FileCode className="w-5 h-5" />
                        Remediation Playbooks
                    </CardTitle>
                    <CardDescription>Automated and manual response procedures</CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="space-y-3">
                        {playbooks?.map((playbook: any) => (
                            <div
                                key={playbook.id}
                                className="flex items-center justify-between p-4 rounded-lg bg-slate-800/50 border border-slate-700 hover:border-slate-600 transition-colors"
                            >
                                <div className="flex items-center gap-3">
                                    <div className={`w-2 h-2 rounded-full ${playbook.risk_level === "CRITICAL" ? "bg-red-500" :
                                            playbook.risk_level === "HIGH" ? "bg-orange-500" :
                                                "bg-yellow-500"
                                        }`} />
                                    <div>
                                        <h4 className="font-medium text-slate-200">{playbook.name}</h4>
                                        <p className="text-xs text-slate-500 mt-1">{playbook.type}</p>
                                    </div>
                                </div>
                                <button className="px-4 py-2 rounded bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium transition-colors">
                                    Execute
                                </button>
                            </div>
                        ))}
                    </div>
                </CardContent>
            </Card>

            {/* Incident Board */}
            <Card className="bg-slate-900/50 border-slate-800">
                <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-slate-200">
                        <AlertTriangle className="w-5 h-5" />
                        Active Incidents
                    </CardTitle>
                    <CardDescription>Kanban view of ongoing IR cases</CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div className="space-y-2">
                            <h4 className="text-sm font-medium text-slate-400">OPEN</h4>
                            <div className="p-3 rounded-lg bg-red-950/30 border border-red-900">
                                <div className="text-sm font-medium text-red-300">INC-001</div>
                                <div className="text-xs text-slate-400 mt-1">Unauthorized SSH Access</div>
                            </div>
                        </div>
                        <div className="space-y-2">
                            <h4 className="text-sm font-medium text-slate-400">IN PROGRESS</h4>
                            <div className="p-3 rounded-lg bg-yellow-950/30 border border-yellow-900">
                                <div className="text-sm font-medium text-yellow-300">INC-002</div>
                                <div className="text-xs text-slate-400 mt-1">Malware Detection</div>
                            </div>
                        </div>
                        <div className="space-y-2">
                            <h4 className="text-sm font-medium text-slate-400">RESOLVED</h4>
                            <div className="p-3 rounded-lg bg-green-950/30 border border-green-900">
                                <div className="text-sm font-medium text-green-300">INC-003</div>
                                <div className="text-xs text-slate-400 mt-1">Phishing Attempt</div>
                            </div>
                        </div>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
};

export default SecOpsSovereignty;
