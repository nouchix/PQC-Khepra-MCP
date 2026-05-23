

import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Shield, Zap, Eye, Search, Cloud, Lock, Network, Database } from "lucide-react";
import { useContextMenu } from '@/components/ui/context-menu-system';
import { useWorkflowAnalytics } from '@/hooks/useWorkflowAnalytics';

interface ModuleGridProps {
  onModuleClick?: (moduleKey: string) => void;
}

export const ModuleGrid = ({ onModuleClick }: ModuleGridProps) => {
  const { showContextMenu, ContextMenuComponent } = useContextMenu();
  const { trackEvent } = useWorkflowAnalytics();
  const modules = [
    {
      title: "STIG-Codex",
      description: "Advanced STIG-first compliance intelligence platform",
      icon: Shield,
      status: "ready",
      color: "cyan",
      moduleKey: "stig-codex",
      placeholder: "Launch STIG-Codex"
    },
    {
      title: "M-XDR Core",
      description: "Extended Detection & Response Platform",
      icon: Shield,
      status: "ready",
      color: "cyan",
      moduleKey: "security",
      placeholder: "Configure XDR"
    },
    {
      title: "SOAR Platform", 
      description: "Security Orchestration & Automated Response",
      icon: Zap,
      status: "ready",
      color: "yellow",
      moduleKey: "automation",
      placeholder: "Setup Automation"
    },
    {
      title: "IPS Engine",
      description: "Intrusion Prevention System - IN DEVELOPMENT", 
      icon: Eye,
      status: "development",
      color: "green",
      moduleKey: "security",
      placeholder: "Configure IPS"
    },
    {
      title: "SIEM Analytics",
      description: "Security Information & Event Management",
      icon: Search,
      status: "ready", 
      color: "blue",
      moduleKey: "integrations",
      placeholder: "Setup SIEM"
    },
    {
      title: "Cloud Security",
      description: "Multi-cloud Protection - IN DEVELOPMENT",
      icon: Cloud,
      status: "development",
      color: "purple", 
      moduleKey: "security",
      placeholder: "Connect Cloud"
    },
    {
      title: "Zero Trust",
      description: "Identity & Access Management - IN DEVELOPMENT",
      icon: Lock,
      status: "development",
      color: "orange",
      moduleKey: "users",
      placeholder: "Setup IAM"
    },
    {
      title: "Network Monitor", 
      description: "Real-time Traffic Analysis",
      icon: Network,
      status: "ready",
      color: "teal",
      moduleKey: "analytics",
      placeholder: "Monitor Network"
    },
    {
      title: "Threat Intel",
      description: "Intelligence Aggregation", 
      icon: Database,
      status: "ready",
      color: "red",
      moduleKey: "threat-feeds",
      placeholder: "Configure Feeds"
    }
  ];

  const getStatusColor = (status: string) => {
    switch (status) {
      case "ready": return "bg-green-400";
      case "development": return "bg-yellow-400";
      default: return "bg-gray-400";
    }
  };

  const getColorClasses = (color: string) => {
    const colors: { [key: string]: string } = {
      cyan: "border-cyan-500/30 bg-cyan-900/20 hover:bg-cyan-800/30",
      yellow: "border-yellow-500/30 bg-yellow-900/20 hover:bg-yellow-800/30", 
      green: "border-green-500/30 bg-green-900/20 hover:bg-green-800/30",
      blue: "border-blue-500/30 bg-blue-900/20 hover:bg-blue-800/30",
      purple: "border-purple-500/30 bg-purple-900/20 hover:bg-purple-800/30",
      orange: "border-orange-500/30 bg-orange-900/20 hover:bg-orange-800/30",
      teal: "border-teal-500/30 bg-teal-900/20 hover:bg-teal-800/30",
      red: "border-red-500/30 bg-red-900/20 hover:bg-red-800/30"
    };
    return colors[color] || "border-gray-500/30 bg-gray-900/20 hover:bg-gray-800/30";
  };

  const handleModuleClick = (module: any, event: React.MouseEvent) => {
    trackEvent('module-card', `click-${module.moduleKey}`, { x: event.clientX, y: event.clientY });
    
    if (onModuleClick) {
      onModuleClick(module.moduleKey);
    }
  };

  return (
    <Card className="bg-black/40 border-slate-500/30 backdrop-blur-lg">
      <CardHeader>
        <CardTitle className="text-slate-200">Security Modules</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {modules.map((module) => {
            const IconComponent = module.icon;
            return (
              <div
                key={module.title}
                onClick={(e) => handleModuleClick(module, e)}
                onContextMenu={(e) => showContextMenu(e, [
                  {
                    id: 'configure',
                    label: `Configure ${module.title}`,
                    icon: module.icon,
                    variant: 'primary',
                    action: () => {
                      trackEvent('context-menu', `configure-${module.moduleKey}`, { x: 0, y: 0 });
                      if (onModuleClick) onModuleClick(module.moduleKey);
                    }
                  },
                  {
                    id: 'monitor',
                    label: 'Add to Dashboard',
                    icon: Eye,
                    action: () => {
                      trackEvent('context-menu', `monitor-${module.moduleKey}`, { x: 0, y: 0 });
                    }
                  }
                ])}
                className={`p-4 rounded-lg ${getColorClasses(module.color)} backdrop-blur-sm transition-all duration-300 hover:scale-105 cursor-pointer relative group`}
              >
                <div className="flex items-start justify-between mb-3">
                  <IconComponent className="h-6 w-6 text-white group-hover:animate-pulse" />
                  <div className={`w-2 h-2 rounded-full ${getStatusColor(module.status)} animate-pulse`}></div>
                </div>
                
                <h3 className="font-semibold text-white mb-1">{module.title}</h3>
                <p className="text-xs text-gray-300 mb-3">{module.description}</p>
                
                {module.status === "ready" && (
                  <div className="mb-2">
                    <span className="inline-block px-2 py-1 text-xs bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 rounded">
                      BETA
                    </span>
                  </div>
                )}
                
                <div className="text-center py-2">
                  <span className="text-sm text-gray-400 group-hover:text-white transition-colors">{module.placeholder}</span>
                  <div className="text-xs text-blue-400 mt-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    Right-click for options
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </CardContent>
      
      {/* Context Menu Component */}
      <ContextMenuComponent />
    </Card>
  );
};
