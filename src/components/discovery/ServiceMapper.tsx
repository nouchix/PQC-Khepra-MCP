import { useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Server, Shield, AlertTriangle, CheckCircle, Network, Database } from 'lucide-react';

interface DiscoveredService {
  port: number;
  protocol: string;
  service: string;
  version?: string;
  state: string;
  product?: string;
  extrainfo?: string;
  cpe?: string[];
  scripts?: any[];
  vulnerabilities?: string[];
  stig_mappings?: string[];
  compliance_status?: 'compliant' | 'non_compliant' | 'needs_review' | 'unknown';
  risk_score?: number;
}

interface ServicedAsset {
  id: string;
  identifier: string;
  hostname?: string;
  ip_address: string;
  asset_type: string;
  platform?: string;
  operating_system?: string;
  services: DiscoveredService[];
  overall_risk_score: number;
  compliance_percentage: number;
  last_scan: string;
}

interface ServiceMapperProps {
  assets: ServicedAsset[];
  onServiceSelect?: (assetId: string, service: DiscoveredService) => void;
  showCompliance?: boolean;
}

export const ServiceMapper: React.FC<ServiceMapperProps> = ({
  assets,
  onServiceSelect,
  showCompliance = true
}) => {
  const getServiceIcon = (service: string) => {
    const serviceIconMap: { [key: string]: React.ReactNode } = {
      'ssh': <Shield className="h-4 w-4" />,
      'http': <Network className="h-4 w-4" />,
      'https': <Shield className="h-4 w-4" />,
      'ftp': <Database className="h-4 w-4" />,
      'smtp': <Network className="h-4 w-4" />,
      'dns': <Network className="h-4 w-4" />,
      'mysql': <Database className="h-4 w-4" />,
      'postgresql': <Database className="h-4 w-4" />,
      'redis': <Database className="h-4 w-4" />,
      'mongodb': <Database className="h-4 w-4" />
    };

    return serviceIconMap[service.toLowerCase()] || <Server className="h-4 w-4" />;
  };

  const getRiskColor = (score: number) => {
    if (score >= 80) return 'text-red-400 bg-red-500/20 border-red-500/30';
    if (score >= 60) return 'text-orange-400 bg-orange-500/20 border-orange-500/30';
    if (score >= 40) return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30';
    return 'text-green-400 bg-green-500/20 border-green-500/30';
  };

  const getComplianceIcon = (status: string) => {
    switch (status) {
      case 'compliant':
        return <CheckCircle className="h-4 w-4 text-green-400" />;
      case 'non_compliant':
        return <AlertTriangle className="h-4 w-4 text-red-400" />;
      case 'needs_review':
        return <AlertTriangle className="h-4 w-4 text-yellow-400" />;
      default:
        return <Shield className="h-4 w-4 text-slate-400" />;
    }
  };

  const formatServiceDescription = (service: DiscoveredService) => {
    const parts = [service.service];
    if (service.product) parts.push(service.product);
    if (service.version) parts.push(`v${service.version}`);
    return parts.join(' ');
  };

  const getVulnerabilityCount = (service: DiscoveredService) => {
    return service.vulnerabilities?.length || 0;
  };

  const getSTIGMappingCount = (service: DiscoveredService) => {
    return service.stig_mappings?.length || 0;
  };

  if (!assets || assets.length === 0) {
    return (
      <Card className="border-slate-700">
        <CardContent className="py-8">
          <div className="text-center text-slate-400">
            <Server className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>No assets with mapped services found</p>
            <p className="text-sm mt-2">Run a discovery scan to populate service mappings</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {assets.map((asset) => (
          <Card key={asset.id} className="border-slate-700 hover:border-primary/30 transition-colors">
            <CardHeader className="pb-3">
              <div className="flex items-start justify-between">
                <div>
                  <CardTitle className="text-lg flex items-center gap-2">
                    <Server className="h-5 w-5 text-primary" />
                    {asset.hostname || asset.identifier}
                  </CardTitle>
                  <p className="text-sm text-slate-400 mt-1">
                    {asset.ip_address} • {asset.platform || asset.asset_type}
                  </p>
                </div>
                <Badge variant="outline" className={getRiskColor(asset.overall_risk_score)}>
                  Risk: {asset.overall_risk_score}/100
                </Badge>
              </div>
              
              {showCompliance && (
                <div className="flex items-center justify-between mt-3">
                  <span className="text-sm text-slate-400">STIG Compliance</span>
                  <div className="flex items-center gap-2">
                    <Progress value={asset.compliance_percentage} className="w-20 h-2" />
                    <span className="text-sm font-medium">{asset.compliance_percentage}%</span>
                  </div>
                </div>
              )}
            </CardHeader>
            
            <CardContent>
              <div className="space-y-3">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-slate-400">Services Detected</span>
                  <Badge variant="outline">{asset.services.length}</Badge>
                </div>
                
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {asset.services.map((service, idx) => (
                    <div
                      key={`${service.port}-${service.protocol}`}
                      className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-primary/30 transition-colors cursor-pointer"
                      onClick={() => onServiceSelect?.(asset.id, service)}
                    >
                      <div className="flex items-center gap-3">
                        {getServiceIcon(service.service)}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="font-medium text-sm">{service.port}/{service.protocol}</span>
                            <Badge
                              variant={service.state === 'open' ? 'default' : 'secondary'}
                              className="text-xs"
                            >
                              {service.state}
                            </Badge>
                          </div>
                          <p className="text-xs text-slate-400 truncate">
                            {formatServiceDescription(service)}
                          </p>
                        </div>
                      </div>
                      
                      <div className="flex items-center gap-2">
                        {showCompliance && service.compliance_status && (
                          <div className="flex items-center gap-1">
                            {getComplianceIcon(service.compliance_status)}
                          </div>
                        )}
                        
                        {getVulnerabilityCount(service) > 0 && (
                          <Badge variant="destructive" className="text-xs">
                            {getVulnerabilityCount(service)} CVEs
                          </Badge>
                        )}
                        
                        {getSTIGMappingCount(service) > 0 && (
                          <Badge variant="outline" className="text-xs">
                            {getSTIGMappingCount(service)} STIGs
                          </Badge>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
                
                <div className="pt-2 border-t border-slate-700">
                  <div className="flex justify-between text-xs text-slate-400">
                    <span>Last Scan</span>
                    <span>{new Date(asset.last_scan).toLocaleDateString()}</span>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
};