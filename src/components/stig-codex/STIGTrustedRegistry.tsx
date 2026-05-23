/**
 * STIG Trusted Registry Component
 * Manages DISA-approved STIG configurations and AI verification
 */

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Separator } from '@/components/ui/separator';
import { Shield, CheckCircle, AlertTriangle, Search, Bot, FileText, Settings } from 'lucide-react';
import { useSTIGCodex } from '@/hooks/useSTIGCodex';
import { useOrganization } from '@/hooks/useOrganization';

export const STIGTrustedRegistry = () => {
  const { currentOrganization } = useOrganization();
  const {
    trustedConfigurations,
    aiVerifications,
    loading,
    getTrustedConfigurations,
    verifyWithAI,
    searchConfigurations
  } = useSTIGCodex(currentOrganization?.id || '');

  const [searchFilters, setSearchFilters] = useState({
    platform: '',
    stigCategory: '',
    implementationStatus: ''
  });

  const [selectedConfig, setSelectedConfig] = useState<any>(null);

  useEffect(() => {
    if (currentOrganization?.id) {
      handleSearch();
    }
  }, [currentOrganization]);

  const handleSearch = async () => {
    if (!currentOrganization?.id) return;
    
    await searchConfigurations({
      platform: searchFilters.platform,
      stig_category: searchFilters.stigCategory,
      implementation_status: searchFilters.implementationStatus,
      organization_id: currentOrganization.id
    });
  };

  const handleAIVerification = async (configId: string) => {
    if (!currentOrganization?.id) return;
    
    await verifyWithAI(configId, {
      environment_type: 'production',
      platform_version: '2022',
      security_requirements: ['high_assurance'],
      compliance_level: 'strict'
    });
  };

  const getVerificationBadge = (config: any) => {
    const verification = aiVerifications.find(v => v.configuration_id === config.id);
    if (!verification) return null;

    const variant = verification.verification_status === 'verified' ? 'default' : 
                   verification.verification_status === 'warning' ? 'secondary' : 'destructive';

    return (
      <Badge variant={variant} className="ml-2">
        <Bot className="w-3 h-3 mr-1" />
        AI {verification.verification_status}
      </Badge>
    );
  };

  return (
    <div className="space-y-6">
      {/* Search and Filters */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="w-5 h-5" />
            STIG Trusted Registry
          </CardTitle>
          <CardDescription>
            Search and manage DISA-approved STIG configurations with AI verification
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
            <Select
              value={searchFilters.platform}
              onValueChange={(value) => setSearchFilters(prev => ({ ...prev, platform: value }))}
            >
              <SelectTrigger>
                <SelectValue placeholder="Platform" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="">All Platforms</SelectItem>
                <SelectItem value="windows_server">Windows Server</SelectItem>
                <SelectItem value="linux_server">Linux Server</SelectItem>
                <SelectItem value="network_device">Network Device</SelectItem>
                <SelectItem value="database">Database</SelectItem>
              </SelectContent>
            </Select>

            <Select
              value={searchFilters.stigCategory}
              onValueChange={(value) => setSearchFilters(prev => ({ ...prev, stigCategory: value }))}
            >
              <SelectTrigger>
                <SelectValue placeholder="STIG Category" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="">All Categories</SelectItem>
                <SelectItem value="access_control">Access Control</SelectItem>
                <SelectItem value="audit_logging">Audit & Logging</SelectItem>
                <SelectItem value="network_security">Network Security</SelectItem>
                <SelectItem value="system_hardening">System Hardening</SelectItem>
              </SelectContent>
            </Select>

            <Select
              value={searchFilters.implementationStatus}
              onValueChange={(value) => setSearchFilters(prev => ({ ...prev, implementationStatus: value }))}
            >
              <SelectTrigger>
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="">All Status</SelectItem>
                <SelectItem value="approved">DISA Approved</SelectItem>
                <SelectItem value="verified">AI Verified</SelectItem>
                <SelectItem value="pending">Pending Review</SelectItem>
              </SelectContent>
            </Select>

            <Button onClick={handleSearch} disabled={loading}>
              <Search className="w-4 h-4 mr-2" />
              Search
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Results */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Configuration List */}
        <Card>
          <CardHeader>
            <CardTitle>Trusted Configurations</CardTitle>
            <CardDescription>
              {trustedConfigurations.length} configurations found
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3 max-h-96 overflow-y-auto">
              {trustedConfigurations.map((config) => (
                <div
                  key={config.id}
                  className={`p-3 border rounded-lg cursor-pointer transition-colors ${
                    selectedConfig?.id === config.id ? 'border-primary bg-primary/5' : 'hover:bg-muted/50'
                  }`}
                  onClick={() => setSelectedConfig(config)}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="font-medium">{config.stig_id}</div>
                      <div className="text-sm text-muted-foreground">{config.platform_type}</div>
                      <div className="flex items-center gap-2 mt-2">
                        {config.disa_approved && (
                          <Badge variant="default">
                            <CheckCircle className="w-3 h-3 mr-1" />
                            DISA Approved
                          </Badge>
                        )}
                        {getVerificationBadge(config)}
                      </div>
                    </div>
                    <div className="text-sm text-muted-foreground">
                      {Math.round(config.confidence_score * 100)}% confidence
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Configuration Details */}
        <Card>
          <CardHeader>
            <CardTitle>Configuration Details</CardTitle>
            {selectedConfig && (
              <CardDescription>
                {selectedConfig.stig_id} - {selectedConfig.platform_type}
              </CardDescription>
            )}
          </CardHeader>
          <CardContent>
            {selectedConfig ? (
              <Tabs defaultValue="details" className="w-full">
                <TabsList className="grid w-full grid-cols-3">
                  <TabsTrigger value="details">Details</TabsTrigger>
                  <TabsTrigger value="implementation">Implementation</TabsTrigger>
                  <TabsTrigger value="verification">AI Verification</TabsTrigger>
                </TabsList>

                <TabsContent value="details" className="space-y-4">
                  <div>
                    <h4 className="font-medium mb-2">Configuration Template</h4>
                    <div className="p-3 bg-muted rounded-lg">
                      <pre className="text-sm overflow-x-auto">
                        {JSON.stringify(selectedConfig.configuration_template, null, 2)}
                      </pre>
                    </div>
                  </div>
                  
                  <div>
                    <h4 className="font-medium mb-2">Validation Rules</h4>
                    <div className="space-y-2">
                      {selectedConfig.validation_rules?.map((rule: any, index: number) => (
                        <div key={index} className="p-2 bg-muted rounded text-sm">
                          {typeof rule === 'string' ? rule : JSON.stringify(rule)}
                        </div>
                      ))}
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="implementation" className="space-y-4">
                  <div>
                    <h4 className="font-medium mb-2">Implementation Guidance</h4>
                    <p className="text-sm text-muted-foreground">
                      {selectedConfig.implementation_guidance || 'No guidance available'}
                    </p>
                  </div>
                  
                  {selectedConfig.vendor_specific_notes && (
                    <div>
                      <h4 className="font-medium mb-2">Vendor-Specific Notes</h4>
                      <p className="text-sm text-muted-foreground">
                        {selectedConfig.vendor_specific_notes}
                      </p>
                    </div>
                  )}
                </TabsContent>

                <TabsContent value="verification" className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h4 className="font-medium">AI Verification</h4>
                    <Button
                      size="sm"
                      onClick={() => handleAIVerification(selectedConfig.id)}
                      disabled={loading}
                    >
                      <Bot className="w-4 h-4 mr-2" />
                      Verify with AI
                    </Button>
                  </div>

                  {aiVerifications
                    .filter(v => v.configuration_id === selectedConfig.id)
                    .map((verification) => (
                      <div key={verification.id} className="p-3 border rounded-lg">
                        <div className="flex items-center justify-between mb-2">
                          <Badge
                            variant={verification.verification_status === 'verified' ? 'default' :
                                   verification.verification_status === 'warning' ? 'secondary' : 'destructive'}
                          >
                            {verification.verification_status}
                          </Badge>
                          <span className="text-sm text-muted-foreground">
                            {Math.round(verification.confidence_score * 100)}% confidence
                          </span>
                        </div>
                        
                        <p className="text-sm mb-2">
                          {typeof verification.verification_details === 'string' 
                            ? verification.verification_details 
                            : JSON.stringify(verification.verification_details)
                          }
                        </p>
                        
                        {verification.recommendations?.length > 0 && (
                          <div>
                            <h5 className="font-medium mb-1">Recommendations:</h5>
                            <ul className="text-sm list-disc list-inside space-y-1">
                              {verification.recommendations.map((rec: string, index: number) => (
                                <li key={index}>{rec}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    ))}
                </TabsContent>
              </Tabs>
            ) : (
              <div className="text-center text-muted-foreground py-8">
                Select a configuration to view details
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
};