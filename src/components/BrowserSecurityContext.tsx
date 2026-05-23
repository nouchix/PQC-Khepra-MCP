import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Globe, Shield, AlertTriangle, Clock, Network, Eye } from 'lucide-react';
import { useKhepraProtection } from '@/hooks/useKhepraProtection';

interface BrowserSecurityContextProps {
  vulnerabilities: number;
  warningCount: number;
  criticalCount: number;
  lastScanTime: string;
  networkType: 'Private' | 'Public WiFi';
}

export const BrowserSecurityContext: React.FC<BrowserSecurityContextProps> = ({
  vulnerabilities = 1,
  warningCount = 0,
  criticalCount = 0,
  lastScanTime = '10:37:47',
  networkType = 'Private'
}) => {
  const { protectionState, enableKhepraProtection } = useKhepraProtection();

  const getStatusColor = () => {
    if (protectionState.isEnabled) return 'bg-emerald-500';
    if (criticalCount > 0) return 'bg-red-500';
    if (vulnerabilities > 0) return 'bg-amber-500';
    return 'bg-gray-500';
  };

  const getStatusText = () => {
    if (protectionState.isEnabled) return 'Protected';
    if (protectionState.deploymentStatus === 'deploying') return 'Activating Protection...';
    if (vulnerabilities > 0) return `${vulnerabilities} vulnerabilities`;
    return 'Monitoring';
  };

  return (
    <Card className="border-primary/20 bg-card/95 backdrop-blur-sm">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-lg">
          <Globe className="h-5 w-5 text-primary" />
          Browser Security Context
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Status Overview */}
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <span className="text-muted-foreground">Type:</span>
            <span className="ml-2 font-medium">application</span>
          </div>
          <div>
            <span className="text-muted-foreground">Status:</span>
            <Badge 
              variant={protectionState.isEnabled ? "default" : "destructive"}
              className={`ml-2 ${getStatusColor()}`}
            >
              {getStatusText()}
            </Badge>
          </div>
        </div>

        {/* Security Metrics */}
        <div className="grid grid-cols-3 gap-4 text-center">
          <div className="space-y-1">
            <div className="flex items-center justify-center gap-1">
              <Shield className="h-4 w-4 text-emerald-500" />
              <span className="text-xs text-muted-foreground">Protected</span>
            </div>
            <div className="text-lg font-bold text-emerald-500">
              {protectionState.protectedAssets}
            </div>
          </div>
          <div className="space-y-1">
            <div className="flex items-center justify-center gap-1">
              <AlertTriangle className="h-4 w-4 text-amber-500" />
              <span className="text-xs text-muted-foreground">Warning</span>
            </div>
            <div className="text-lg font-bold text-amber-500">{warningCount}</div>
          </div>
          <div className="space-y-1">
            <div className="flex items-center justify-center gap-1">
              <AlertTriangle className="h-4 w-4 text-red-500" />
              <span className="text-xs text-muted-foreground">Critical</span>
            </div>
            <div className="text-lg font-bold text-red-500">{criticalCount}</div>
          </div>
        </div>

        {/* Environment Details */}
        <div className="space-y-2 text-sm">
          <div className="flex justify-between">
            <span className="text-muted-foreground">Agents:</span>
            <span className="font-medium">Active</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Network:</span>
            <span className="font-medium">{networkType}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Last Scan:</span>
            <span className="font-medium">{lastScanTime}</span>
          </div>
        </div>

        {/* Vulnerability Status */}
        {vulnerabilities > 0 && !protectionState.isEnabled && (
          <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg">
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle className="h-4 w-4 text-amber-500" />
              <span className="text-sm font-medium text-amber-600">Vulnerabilities</span>
              <Badge variant="destructive" className="bg-red-500">
                {vulnerabilities} found
              </Badge>
            </div>
            <div className="text-xs text-muted-foreground">
              Last Scanned: {lastScanTime}
            </div>
          </div>
        )}

        {/* KHEPRA Protection Status */}
        {protectionState.isEnabled && (
          <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg">
            <div className="flex items-center gap-2 mb-2">
              <Shield className="h-4 w-4 text-emerald-500" />
              <span className="text-sm font-medium text-emerald-600">KHEPRA Active</span>
              <Badge variant="default" className="bg-emerald-500">
                Protected
              </Badge>
            </div>
            <div className="text-xs text-muted-foreground">
              Environment: {protectionState.environment.toUpperCase()} • 
              Security Level: {protectionState.securityLevel}
            </div>
            {protectionState.lastActivated && (
              <div className="text-xs text-muted-foreground mt-1">
                Activated: {protectionState.lastActivated.toLocaleTimeString()}
              </div>
            )}
          </div>
        )}

        {/* Enable KHEPRA Protection Button */}
        {!protectionState.isEnabled && (
          <Button
            onClick={enableKhepraProtection}
            disabled={protectionState.isLoading}
            className="w-full bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-600 hover:to-blue-600 text-white border-0"
            size="lg"
          >
            <Shield className="h-4 w-4 mr-2" />
            {protectionState.isLoading ? 'Activating Protection...' : 'Enable KHEPRA Protection'}
          </Button>
        )}

        {/* Protection Progress */}
        {protectionState.deploymentStatus === 'deploying' && (
          <div className="space-y-2">
            <div className="flex justify-between text-xs">
              <span>Deployment Progress</span>
              <span>Initializing...</span>
            </div>
            <Progress value={33} className="h-2" />
            <div className="text-xs text-muted-foreground">
              Activating cultural cryptographic framework...
            </div>
          </div>
        )}

        {/* DOD Classification Banner */}
        <div className="mt-4 p-2 bg-amber-500/20 border border-amber-500/30 rounded text-center">
          <div className="text-xs font-bold text-amber-600">
            DoD CLASSIFIED
          </div>
          <div className="text-xs text-muted-foreground">
            Security Level: {protectionState.securityLevel}
          </div>
        </div>
      </CardContent>
    </Card>
  );
};