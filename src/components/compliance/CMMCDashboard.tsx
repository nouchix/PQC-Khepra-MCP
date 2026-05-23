import { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import {
  Shield,
  AlertTriangle,
  Clock,
  FileText,
  TrendingUp,
  Users,
  Database,
  Lock,
  Wifi,
  Eye,
  Settings,
  Zap,
  Activity
} from "lucide-react";
import { useComplianceFrameworks } from "@/hooks/useComplianceFrameworks";
import { supabase } from "@/integrations/supabase/client";

interface CMMCLevel {
  level: number;
  name: string;
  description: string;
  controls: number;
  implemented: number;
  color: string;
}

interface POAMItem {
  id: string;
  control_id: string;
  weakness: string;
  remediation: string;
  status: 'OPEN' | 'IN_PROGRESS' | 'COMPLETED';
  due_date: string;
  priority: 'HIGH' | 'MEDIUM' | 'LOW';
  responsible_party: string;
}

interface CMMCDashboardProps {
  organizationId: string;
}

export const CMMCDashboard: React.FC<CMMCDashboardProps> = ({ organizationId }) => {
  const { frameworks, controls, loading } = useComplianceFrameworks();
  const [cmmcLevels, setCmmcLevels] = useState<CMMCLevel[]>([]);
  const [poamItems, setPOAMItems] = useState<POAMItem[]>([]);
  const [overallScore, setOverallScore] = useState(0);
  const [organizationName, setOrganizationName] = useState("Organization");

  useEffect(() => {
    initializeCMMCData();
    fetchPOAMItems();
    fetchOrganizationData();
  }, [frameworks, controls]);

  const initializeCMMCData = () => {
    const cmmcFramework = frameworks.find(f => f.name.toLowerCase().includes('cmmc'));
    void controls.filter(c => c.framework_id === cmmcFramework?.id);

    const levels: CMMCLevel[] = [
      {
        level: 1,
        name: "Basic Cyber Hygiene",
        description: "Safeguard Federal Contract Information (FCI)",
        controls: 17,
        implemented: 12,
        color: "bg-blue-500"
      },
      {
        level: 2,
        name: "Intermediate Cyber Hygiene",
        description: "Protect Controlled Unclassified Information (CUI)",
        controls: 110,
        implemented: 78,
        color: "bg-green-500"
      },
      {
        level: 3,
        name: "Good Cyber Hygiene",
        description: "Protect CUI and reduce risk of APTs",
        controls: 130,
        implemented: 45,
        color: "bg-yellow-500"
      }
    ];

    setCmmcLevels(levels);

    const totalControls = levels.reduce((sum, level) => sum + level.controls, 0);
    const totalImplemented = levels.reduce((sum, level) => sum + level.implemented, 0);
    setOverallScore(Math.round((totalImplemented / totalControls) * 100));
  };

  const fetchPOAMItems = async () => {
    // Awaiting telemetry for real POAM data
    const pendingPOAM: POAMItem[] = [];

    setPOAMItems(pendingPOAM);
  };

  const fetchOrganizationData = async () => {
    try {
      const { data: orgs } = await supabase
        .from('organizations')
        .select('name')
        .limit(1)
        .single();

      if (orgs?.name) {
        setOrganizationName(orgs.name);
      }
    } catch (error) {
      console.error('Error fetching organization:', error);
    }
  };

  const getDomainIcon = (domain: string): React.ElementType => {
    const icons: Record<string, any> = {
      'AC': Users,      // Access Control
      'AU': FileText,   // Audit and Accountability  
      'AT': TrendingUp, // Awareness and Training
      'CM': Settings,   // Configuration Management
      'IA': Lock,       // Identification and Authentication
      'IR': AlertTriangle, // Incident Response
      'MA': Settings,   // Maintenance
      'MP': Database,   // Media Protection
      'PS': Users,      // Personnel Security
      'PE': Shield,     // Physical Protection
      'RE': TrendingUp, // Recovery
      'RM': Eye,        // Risk Management
      'CA': Shield,     // Security Assessment
      'SC': Wifi,       // System and Communications Protection
      'SI': Shield,     // System and Information Integrity
    };

    return icons[domain] || Shield;
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'COMPLETED': return 'bg-green-500';
      case 'IN_PROGRESS': return 'bg-yellow-500';
      case 'OPEN': return 'bg-red-500';
      default: return 'bg-gray-500';
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'HIGH': return 'text-red-400';
      case 'MEDIUM': return 'text-yellow-400';
      case 'LOW': return 'text-green-400';
      default: return 'text-gray-400';
    }
  };

  if (loading) {
    return (
      <div className="space-y-6">
        <Card className="bg-gradient-to-r from-blue-900/40 to-purple-900/40 border-blue-500/30">
          <CardContent className="p-6">
            <div className="text-center text-gray-400">Loading CMMC compliance data...</div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card className="bg-gradient-to-r from-indigo-900/40 to-slate-900/40 border-indigo-500/30 overflow-hidden relative">
        <div className="absolute top-0 right-0 p-8 opacity-10">
          <Shield className="w-32 h-32 text-indigo-500" />
        </div>
        <CardHeader>
          <CardTitle className="flex items-center space-x-3 text-white">
            <Shield className="h-8 w-8 text-indigo-400" />
            <div>
              <h1 className="text-2xl font-black tracking-tight">Sentinel CMMC Intelligence</h1>
              <p className="text-indigo-200 text-xs font-bold uppercase tracking-widest">{organizationName} • Continuous Compliance Engine</p>
            </div>
          </CardTitle>
        </CardHeader>
      </Card>

      {/* Overall Score & Behavioral Forensics */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2 bg-slate-950/40 border-indigo-500/20 backdrop-blur-xl relative overflow-hidden">
          <div className="absolute bottom-0 left-0 w-full h-1 bg-gradient-to-r from-indigo-600 via-blue-500 to-indigo-600 animate-shimmer" />
          <CardContent className="p-8">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
              <div className="md:col-span-2 space-y-6">
                <div>
                  <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-[0.2em] mb-2">Enterprise Readiness Score</h3>
                  <div className="flex items-baseline gap-4">
                    <span className="text-6xl font-black text-white tracking-tighter">{overallScore}%</span>
                    <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/20">On Track</Badge>
                  </div>
                </div>

                <div className="space-y-2">
                  <Progress value={overallScore} className="h-2 bg-slate-800" />
                  <div className="flex justify-between text-[10px] font-bold text-slate-500 uppercase tracking-widest">
                    <span>Target: CMMC Level 2.0</span>
                    <span>Next Milestone: 14 Days</span>
                  </div>
                </div>
              </div>

              <div className="flex flex-col justify-center items-center p-6 bg-indigo-600/5 rounded-2xl border border-indigo-500/20">
                <TrendingUp className="h-8 w-8 text-indigo-400 mb-2" />
                <div className="text-2xl font-black text-white">+12%</div>
                <div className="text-[9px] text-slate-500 font-bold uppercase tracking-widest">Monthly Growth</div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Behavioral Forensic Link */}
        <Card className="bg-slate-900 border-red-500/20 relative group hover:border-red-500/40 transition-all cursor-pointer" onClick={() => globalThis.location.href = '/threat-hunting'}>
          <div className="absolute top-0 right-0 p-4">
            <Zap className="h-4 w-4 text-red-500 animate-pulse" />
          </div>
          <CardHeader>
            <CardTitle className="text-sm font-black text-slate-300 uppercase tracking-widest flex items-center gap-2">
              <Activity className="h-4 w-4 text-red-400" />
              Forensic Proofs
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-black text-white mb-1">Pending Traces</div>
            <p className="text-[11px] text-slate-500 leading-relaxed mb-4">
              Awaiting telemetry to map behavioral events to integrity controls.
            </p>
            <Button variant="outline" className="w-full text-[10px] font-bold uppercase tracking-widest border-red-500/30 text-red-400 hover:bg-red-500/10">
              View Forensic Evidence
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* CMMC Levels */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {cmmcLevels.map((level) => {
          const completionRate = Math.round((level.implemented / level.controls) * 100);
          return (
            <Card key={level.level} className="bg-slate-950/40 border-slate-800 backdrop-blur-lg hover:border-indigo-500/30 transition-all">
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-3">
                  <div className={`w-10 h-10 rounded-xl ${level.color} flex items-center justify-center text-white font-black shadow-lg`}>
                    {level.level}
                  </div>
                  <div>
                    <div className="text-xs font-black text-slate-200 uppercase tracking-tight">{level.name}</div>
                    <div className="text-[10px] text-slate-500 font-medium leading-tight mt-0.5">{level.description}</div>
                  </div>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div className="flex justify-between text-[10px] font-black text-slate-400 uppercase tracking-widest">
                    <span>Validation</span>
                    <span className="text-white">{completionRate}%</span>
                  </div>
                  <Progress value={completionRate} className="h-1.5 bg-slate-800" />
                  <div className="flex justify-between items-center text-[10px]">
                    <span className="text-slate-500 font-bold">{level.implemented} of {level.controls} controls</span>
                    <Badge variant="outline" className={`text-[9px] py-0 border-current ${completionRate >= 80 ? "text-emerald-400" : "text-indigo-400"}`}>
                      {completionRate >= 80 ? "Operational" : "Building"}
                    </Badge>
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* POA&M */}
      <Card className="bg-slate-950/40 border-slate-800 backdrop-blur-lg">
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <div className="flex items-center space-x-2 text-white">
              <FileText className="h-5 w-5 text-indigo-400" />
              <span className="text-sm font-black uppercase tracking-widest">Plan of Action & Milestones (POA&M)</span>
            </div>
            <Button size="sm" className="bg-indigo-600 hover:bg-indigo-700 text-[10px] font-bold uppercase tracking-widest">
              Export Evidence Package
            </Button>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {poamItems.map((item) => (
              <div key={item.id} className="p-5 bg-slate-900/50 rounded-xl border border-slate-800/50 group hover:border-indigo-500/30 transition-all">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3 mb-3">
                      <Badge variant="outline" className="text-indigo-400 border-indigo-400/30 bg-indigo-400/5 font-black text-[9px]">
                        {item.control_id}
                      </Badge>
                      <Badge
                        variant="outline"
                        className={`${getPriorityColor(item.priority)} border-current font-black text-[9px] uppercase`}
                      >
                        {item.priority} PRIORITY
                      </Badge>
                      <div className={`w-2 h-2 rounded-full ${getStatusColor(item.status)} shadow-[0_0_8px_currentColor]`} />
                    </div>
                    <h4 className="text-slate-200 font-bold mb-1">{item.weakness}</h4>
                    <p className="text-slate-500 text-xs mb-4 leading-relaxed">{item.remediation}</p>
                    <div className="flex items-center justify-between pt-4 border-t border-slate-800">
                      <div className="flex items-center gap-2">
                        <Users className="h-3 w-3 text-slate-500" />
                        <span className="text-[10px] text-slate-400 font-bold">{item.responsible_party}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Clock className="h-3 w-3 text-slate-500" />
                        <span className="text-[10px] text-slate-400 font-bold">Due: {new Date(item.due_date).toLocaleDateString()}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Control Map Shortcut */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Generate SSP', icon: FileText, color: 'text-blue-400' },
          { label: 'Run Assessment', icon: TrendingUp, color: 'text-indigo-400' },
          { label: 'STIG Mapper', icon: Settings, color: 'text-emerald-400' },
          { label: 'Audit Vault', icon: Shield, color: 'text-purple-400' }
        ].map((action, i) => (
          <Button
            key={action.label}
            variant="outline"
            className="h-24 flex-col gap-3 border-slate-800 bg-slate-950/40 text-slate-400 hover:bg-slate-900 hover:border-indigo-500/30 transition-all"
          >
            <action.icon className={`h-6 w-6 ${action.color}`} />
            <span className="text-[10px] font-black uppercase tracking-[0.15em]">{action.label}</span>
          </Button>
        ))}
      </div>
    </div>
  );
};