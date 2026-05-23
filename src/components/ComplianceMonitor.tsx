
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, CheckCircle, AlertCircle, Lock } from "lucide-react";

export const ComplianceMonitor = () => {
  const frameworks = [
    { name: "NIST 800-53", status: "planned", score: 0, controls: "0/330", target: "Q2 2025" },
    { name: "IEC 62443", status: "planned", score: 0, controls: "0/92", target: "Q3 2025" },
    { name: "CMMC Level 2", status: "in-progress", score: 35, controls: "38/110", target: "Q3 2025" },
    { name: "FedRAMP High", status: "planned", score: 0, controls: "0/325", target: "Q4 2025" },
    { name: "DISA STIG", status: "in-progress", score: 25, controls: "62/247", target: "Q2 2025" }
  ];

  const securityFeatures = [
    { name: "AWS GovCloud Deployment", status: "planned", description: "Q2 2025 - CUI-ready infrastructure", color: "blue" },
    { name: "NIST 800-171 Controls", status: "in-progress", description: "Core controls under development", color: "yellow" },
    { name: "Audit Logging (AU)", status: "in-progress", description: "CloudTrail integration planned", color: "yellow" },
    { name: "Configuration Management (CM)", status: "planned", description: "DISA STIG baselines Q2 2025", color: "blue" }
  ];

  return (
    <Card className="bg-black/40 border-red-500/30 backdrop-blur-lg">
      <CardHeader>
        <CardTitle className="flex items-center space-x-2 text-red-400">
          <Shield className="h-5 w-5" />
          <span>Compliance & Security</span>
          <Badge variant="outline" className="ml-2 text-xs bg-yellow-500/10 text-yellow-400 border-yellow-500/30">
            IN DEVELOPMENT
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div>
          <h4 className="text-sm font-semibold text-red-400 mb-2">Compliance Framework Roadmap</h4>
          {frameworks.map((framework) => (
            <div key={framework.name} className="flex items-center justify-between p-2 bg-slate-800/40 rounded border border-slate-600/30 mb-2">
              <div className="flex items-center space-x-2">
                {framework.status === 'in-progress' ? 
                  <AlertCircle className="h-3 w-3 text-yellow-400" /> : 
                  <CheckCircle className="h-3 w-3 text-blue-400 opacity-50" />
                }
                <span className="text-xs font-medium text-white">{framework.name}</span>
              </div>
              <div className="text-right">
                <div className="text-xs text-cyan-400">{framework.score}%</div>
                <div className="text-xs text-gray-400">{framework.controls}</div>
                <div className="text-xs text-blue-400">{framework.target}</div>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-4">
          <h4 className="text-sm font-semibold text-red-400 mb-2">Security Controls Development</h4>
          {securityFeatures.map((feature) => (
            <div key={feature.name} className="p-2 bg-slate-800/40 rounded border border-slate-600/30 mb-2">
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center space-x-2">
                  <Lock className={`h-3 w-3 ${feature.color === 'yellow' ? 'text-yellow-400' : 'text-blue-400'}`} />
                  <span className="text-xs font-medium text-white">{feature.name}</span>
                </div>
                <span className={`text-xs uppercase ${feature.status === 'in-progress' ? 'text-yellow-400' : 'text-blue-400'}`}>
                  {feature.status}
                </span>
              </div>
              <p className="text-xs text-gray-400 ml-5">{feature.description}</p>
            </div>
          ))}
        </div>
        
        <div className="mt-4 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded">
          <p className="text-xs text-yellow-300">
            <strong>Development Status:</strong> Compliance controls are under active development. 
            Production CUI workloads require AWS GovCloud deployment (Q2 2025).
          </p>
        </div>
      </CardContent>
    </Card>
  );
};
