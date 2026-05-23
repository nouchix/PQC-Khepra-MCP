import React, { useMemo, useState } from 'react';
import {
    ReactFlow,
    Background,
    Controls,
    Edge,
    Node,
    Panel,
    NodeProps
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
    FileCode,
    Globe,
    Database,
    Activity,
    Shield,
    Clock,
    Zap,
    AlertCircle
} from "lucide-react";

interface BehaviorEvent {
    id: string;
    timestamp: string;
    pid: number;
    processName: string;
    type: 'FILE' | 'REGISTRY' | 'NETWORK';
    action: string;
    target: string;
    details?: string;
    cmmcControl?: string;
    complianceStatus?: 'VALIDATED' | 'VIOLATION' | 'PENDING';
    [key: string]: any;
}

type EventNode_T = Node<BehaviorEvent, 'event'>;

const EventNode = (props: NodeProps<EventNode_T>) => {
    const { data } = props;
    const getIcon = () => {
        switch (data.type) {
            case 'FILE': return <FileCode className="h-4 w-4 text-blue-400" />;
            case 'NETWORK': return <Globe className="h-4 w-4 text-green-400" />;
            case 'REGISTRY': return <Database className="h-4 w-4 text-purple-400" />;
            default: return <Activity className="h-4 w-4" />;
        }
    };

    const getStatusColor = () => {
        switch (data.complianceStatus) {
            case 'VALIDATED': return 'border-emerald-500/50 shadow-emerald-500/10';
            case 'VIOLATION': return 'border-red-500/50 shadow-red-500/20';
            case 'PENDING': return 'border-yellow-500/50 shadow-yellow-500/10';
            default: return 'border-slate-700';
        }
    };

    return (
        <div className={`px-4 py-3 shadow-xl rounded-xl bg-slate-900 border-2 ${getStatusColor()} min-w-[220px] backdrop-blur-md relative`}>
            {data.complianceStatus === 'VIOLATION' && (
                <div className="absolute -top-3 -right-3 p-1.5 bg-red-600 rounded-full animate-pulse ring-4 ring-red-600/20 z-10">
                    <AlertCircle className="h-4 w-4 text-white" />
                </div>
            )}

            <div className="flex items-center space-x-2 mb-2">
                <div className="p-1 rounded bg-slate-800">
                    {getIcon()}
                </div>
                <div>
                    <span className="text-[10px] font-black text-slate-500 tracking-tighter uppercase">{data.type}</span>
                    <div className="text-[10px] text-slate-400 flex items-center">
                        <Clock className="h-2 w-2 mr-1" />
                        {new Date(data.timestamp).toLocaleTimeString()}
                    </div>
                </div>
                {data.cmmcControl && (
                    <Badge variant="outline" className="ml-auto text-[9px] py-0 px-1.5 bg-blue-500/5 text-blue-400 border-blue-500/20">
                        {data.cmmcControl}
                    </Badge>
                )}
            </div>

            <div className="text-xs font-bold text-slate-100 mb-1 leading-tight truncate">
                {data.action}: <span className="text-slate-400 font-normal">{data.target}</span>
            </div>

            {data.details && (
                <div className="text-[9px] text-slate-500 italic mb-2">
                    {data.details}
                </div>
            )}

            <div className="flex items-center justify-between pt-2 border-t border-slate-800">
                <div className="text-[9px] text-slate-500 font-mono">
                    PID: <span className="text-slate-300">{data.pid}</span>
                </div>
                <div className="text-[9px] text-slate-500 bg-slate-800 px-1 rounded">
                    {data.processName}
                </div>
            </div>
        </div>
    );
};

const nodeTypes = {
    event: EventNode,
};

// Awaiting real telemetry for process behavior events
const pendingEvents: BehaviorEvent[] = [];

export const ProcessBehaviorTimeline = () => {
    const [autopilotActive, setAutopilotActive] = useState(true);

    const { nodes, edges } = useMemo(() => {
        const initialNodes: Node[] = [];
        const initialEdges: Edge[] = [];

        const processes = Array.from(new Set(pendingEvents.map(e => e.processName)));

        processes.forEach((proc, procIdx) => {
            const procEvents = pendingEvents.filter(e => e.processName === proc);

            initialNodes.push({
                id: `label-${proc}`,
                position: { x: -250, y: procIdx * 180 },
                data: { label: proc },
                style: {
                    background: 'rgba(15, 23, 42, 0.8)',
                    color: '#94a3b8',
                    border: '1px solid #334155',
                    borderRadius: '12px',
                    width: 200,
                    fontWeight: '900',
                    fontSize: '12px',
                    textTransform: 'uppercase',
                    letterSpacing: '0.05em',
                    padding: '12px',
                    textAlign: 'center',
                    boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)'
                },
                draggable: false,
            });

            procEvents.forEach((event, eventIdx) => {
                initialNodes.push({
                    id: event.id,
                    type: 'event',
                    position: { x: eventIdx * 350, y: procIdx * 180 },
                    data: event,
                });

                if (eventIdx > 0) {
                    initialEdges.push({
                        id: `edge-${procEvents[eventIdx - 1].id}-${event.id}`,
                        source: procEvents[eventIdx - 1].id,
                        target: event.id,
                        animated: true,
                        style: { stroke: '#334155', strokeWidth: 1.5 },
                    });
                }
            });
        });

        initialEdges.push({
            id: 'correlation-1-3',
            source: '1',
            target: '3',
            label: 'Spawns Process',
            animated: true,
            style: { stroke: '#f43f5e', strokeWidth: 2, strokeDasharray: '5,5' },
            labelStyle: { fill: '#f43f5e', fontWeight: 900, fontSize: '10px' }
        });

        return { nodes: initialNodes, edges: initialEdges };
    }, []);

    return (
        <Card className="w-full h-[650px] bg-slate-950 border-slate-800 overflow-hidden shadow-2xl relative">
            <CardHeader className="flex flex-row items-center justify-between border-b border-slate-800 bg-black/40 backdrop-blur-xl z-10 sticky top-0">
                <div className="flex items-center gap-4">
                    <div className="p-2 bg-blue-500/10 rounded-lg border border-blue-500/20">
                        <Activity className="h-6 w-6 text-blue-500" />
                    </div>
                    <div>
                        <CardTitle className="text-xl text-white font-black tracking-tight flex items-center">
                            Forensics Traceability Timeline
                        </CardTitle>
                        <div className="text-xs text-slate-500 mt-0.5 flex items-center uppercase font-bold tracking-widest text-[9px]">
                            <Shield className="h-3 w-3 mr-1 text-emerald-500" />
                            CMMC-Mapped Behavioral Correlation Engine
                        </div>
                    </div>
                </div>
                <div className="flex items-center gap-3">
                    <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full border transition-all ${autopilotActive ? 'bg-emerald-500/10 border-emerald-500/30' : 'bg-slate-800 border-slate-700'
                        }`}>
                        <Zap className={`h-3 w-3 ${autopilotActive ? 'text-emerald-500' : 'text-slate-500'}`} />
                        <span className="text-[10px] font-bold text-slate-300 uppercase">Compliance Autopilot</span>
                        <button
                            role="switch"
                            aria-checked={autopilotActive}
                            onClick={() => setAutopilotActive(!autopilotActive)}
                            onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') setAutopilotActive(!autopilotActive); }}
                            className={`w-8 h-4 rounded-full relative cursor-pointer transition-colors ${autopilotActive ? 'bg-emerald-600' : 'bg-slate-700'}`}
                        >
                            <div className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all ${autopilotActive ? 'right-0.5' : 'left-0.5'}`} />
                        </button>
                    </div>
                    <div className="h-8 w-px bg-slate-800 mx-2" />
                    <div className="flex space-x-1">
                        <Badge variant="outline" className="bg-slate-900 border-slate-800 text-slate-500 text-[10px]">L2-3.3.1</Badge>
                        <Badge variant="outline" className="bg-slate-900 border-slate-800 text-slate-500 text-[10px]">L2-3.14.6</Badge>
                    </div>
                </div>
            </CardHeader>
            <CardContent className="p-0 h-full relative">
                {/* @ts-ignore - ReactFlow type issues in some environments */}
                <ReactFlow
                    nodes={nodes}
                    edges={edges}
                    // @ts-ignore
                    nodeTypes={nodeTypes}
                    fitView
                    className="bg-slate-950"
                    minZoom={0.2}
                    maxZoom={2}
                >
                    <Background color="#0f172a" gap={25} />
                    <Controls className="bg-slate-900 border-slate-800" />
                    <Panel position="bottom-left" className="bg-black/80 p-3 rounded-xl border border-slate-800 backdrop-blur-md mb-20 ml-6">
                        <div className="space-y-2">
                            <div className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mb-2">Operational Integrity</div>
                            <div className="flex items-center gap-3">
                                <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]" />
                                <span className="text-[11px] text-slate-300">CMMC Evidence Validated</span>
                            </div>
                            <div className="flex items-center gap-3">
                                <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                                <span className="text-[11px] text-slate-300">Control Violation Detected</span>
                            </div>
                            <div className="flex items-center gap-3">
                                <div className="w-2 h-2 rounded-full bg-yellow-500" />
                                <span className="text-[11px] text-slate-300">Manual Review Required</span>
                            </div>
                        </div>
                    </Panel>
                    <Panel position="top-right" className="bg-emerald-500/10 p-2 rounded border border-emerald-500/20 backdrop-blur-md mt-24 mr-6">
                        <div className="flex items-center gap-2">
                            <Shield className="h-3 w-3 text-emerald-500" />
                            <div className="text-[10px] text-emerald-400 font-mono font-bold uppercase">
                                Autopilot: Evidence Collection Active
                            </div>
                        </div>
                    </Panel>
                </ReactFlow>
            </CardContent>
        </Card>
    );
};
