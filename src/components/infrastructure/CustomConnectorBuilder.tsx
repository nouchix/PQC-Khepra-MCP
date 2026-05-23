import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { 
  Code, Plus, TestTube, Download, Upload, Settings, 
  Zap, Cpu, Database, Cloud, Network, Shield
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface ConnectorTemplate {
  id: string;
  name: string;
  type: 'REST' | 'GraphQL' | 'WebSocket' | 'Database' | 'File' | 'Custom';
  description: string;
  code: string;
  status: 'draft' | 'testing' | 'deployed' | 'deprecated';
  dataTypes: string[];
  createdAt: string;
  author: string;
}

interface ConnectorField {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';
  required: boolean;
  description: string;
}

export const CustomConnectorBuilder = () => {
  const [templates, setTemplates] = useState<ConnectorTemplate[]>([]);
  const [selectedTemplate, setSelectedTemplate] = useState<ConnectorTemplate | null>(null);
  const [isBuilding, setIsBuilding] = useState(false);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const { toast } = useToast();

  // Form state for creating new connector
  const [connectorConfig, setConnectorConfig] = useState({
    name: '',
    type: '',
    description: '',
    endpoint: '',
    method: 'GET',
    headers: '',
    dataMapping: '',
    schedule: 'hourly'
  });

  // Initialize with sample connector templates
  useState(() => {
    const sampleTemplates: ConnectorTemplate[] = [
      {
        id: '1',
        name: 'Generic REST API Connector',
        type: 'REST',
        description: 'Universal REST API connector with OAuth 2.0 support',
        code: `// REST API Connector Template
class RestApiConnector {
  constructor(config) {
    this.endpoint = config.endpoint;
    this.apiKey = config.apiKey;
    this.headers = config.headers || {};
  }

  async fetchData() {
    const response = await fetch(this.endpoint, {
      headers: {
        'Authorization': \`Bearer \${this.apiKey}\`,
        'Content-Type': 'application/json',
        ...this.headers
      }
    });
    
    if (!response.ok) {
      throw new Error(\`HTTP \${response.status}: \${response.statusText}\`);
    }
    
    return await response.json();
  }

  async testConnection() {
    try {
      await this.fetchData();
      return { success: true, message: 'Connection successful' };
    } catch (error) {
      return { success: false, message: error.message };
    }
  }
}`,
        status: 'deployed',
        dataTypes: ['json', 'xml', 'csv'],
        createdAt: '2024-01-10T10:00:00Z',
        author: 'System'
      },
      {
        id: '2', 
        name: 'Syslog TCP Collector',
        type: 'Custom',
        description: 'Real-time syslog data collector via TCP socket',
        code: `// Syslog TCP Collector
const net = require('net');

class SyslogCollector {
  constructor(config) {
    this.port = config.port || 514;
    this.host = config.host || '0.0.0.0';
    this.server = null;
  }

  start() {
    this.server = net.createServer((socket) => {
      socket.on('data', (data) => {
        const syslogMessage = this.parseSyslog(data.toString());
        this.processMessage(syslogMessage);
      });
    });

    this.server.listen(this.port, this.host, () => {
      console.log(\`Syslog collector listening on \${this.host}:\${this.port}\`);
    });
  }

  parseSyslog(message) {
    // RFC3164 syslog parsing
    const regex = /<(\\d+)>(\\w{3}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2})\\s+(\\S+)\\s+(.*)/;
    const match = message.match(regex);
    
    if (match) {
      return {
        priority: Number.parseInt(match[1]),
        timestamp: match[2],
        hostname: match[3],
        message: match[4]
      };
    }
    
    return { raw: message };
  }

  processMessage(message) {
    // Send to data lake or processing pipeline
    console.log('Processed syslog:', message);
  }
}`,
        status: 'testing',
        dataTypes: ['syslog', 'events'],
        createdAt: '2024-01-12T14:30:00Z',
        author: 'DevOps Team'
      }
    ];
    
    setTemplates(sampleTemplates);
  });

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'REST': return <Network className="h-4 w-4" />;
      case 'GraphQL': return <Code className="h-4 w-4" />;
      case 'WebSocket': return <Zap className="h-4 w-4" />;
      case 'Database': return <Database className="h-4 w-4" />;
      case 'File': return <Upload className="h-4 w-4" />;
      case 'Custom': return <Cpu className="h-4 w-4" />;
      default: return <Code className="h-4 w-4" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'deployed': return 'bg-success text-success-foreground';
      case 'testing': return 'bg-warning text-warning-foreground';
      case 'draft': return 'bg-muted text-muted-foreground';
      case 'deprecated': return 'bg-destructive text-destructive-foreground';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const createConnector = async () => {
    setIsBuilding(true);
    
    // Simulate connector creation process
    setTimeout(() => {
      const newConnector: ConnectorTemplate = {
        id: Date.now().toString(),
        name: connectorConfig.name,
        type: connectorConfig.type as any,
        description: connectorConfig.description,
        code: generateConnectorCode(connectorConfig),
        status: 'draft',
        dataTypes: ['json', 'events'],
        createdAt: new Date().toISOString(),
        author: 'Current User'
      };
      
      setTemplates(prev => [newConnector, ...prev]);
      setIsBuilding(false);
      setShowCreateDialog(false);
      
      // Reset form
      setConnectorConfig({
        name: '',
        type: '',
        description: '',
        endpoint: '',
        method: 'GET',
        headers: '',
        dataMapping: '',
        schedule: 'hourly'
      });
      
      toast({
        title: "Connector Created",
        description: `${newConnector.name} has been created and is ready for testing`,
        variant: "default"
      });
    }, 3000);
  };

  const generateConnectorCode = (config: any) => {
    return `// Auto-generated ${config.type} Connector: ${config.name}
class ${config.name.replace(/\s+/g, '')}Connector {
  constructor(config) {
    this.endpoint = '${config.endpoint}';
    this.method = '${config.method}';
    this.headers = ${config.headers || '{}'};
    this.schedule = '${config.schedule}';
  }

  async fetchData() {
    try {
      const response = await fetch(this.endpoint, {
        method: this.method,
        headers: this.headers
      });
      
      if (!response.ok) {
        throw new Error(\`HTTP \${response.status}: \${response.statusText}\`);
      }
      
      const data = await response.json();
      return this.transformData(data);
    } catch (error) {
      console.error('Connector error:', error);
      throw error;
    }
  }

  transformData(data) {
    // Apply data mapping transformations
    ${config.dataMapping || '// No transformations defined'}
    return data;
  }

  async testConnection() {
    try {
      await this.fetchData();
      return { success: true, message: 'Connection successful' };
    } catch (error) {
      return { success: false, message: error.message };
    }
  }
}`;
  };

  const testConnector = async (connector: ConnectorTemplate) => {
    toast({
      title: "Testing Connector",
      description: `Running tests for ${connector.name}...`,
      variant: "default"
    });
    
    // Simulate test
    setTimeout(() => {
      toast({
        title: "Test Complete",
        description: `${connector.name} passed all tests`,
        variant: "default"
      });
    }, 2000);
  };

  const deployConnector = async (connector: ConnectorTemplate) => {
    setTemplates(prev => 
      prev.map(t => 
        t.id === connector.id 
          ? { ...t, status: 'deployed' }
          : t
      )
    );
    
    toast({
      title: "Connector Deployed",
      description: `${connector.name} is now live and collecting data`,
      variant: "default"
    });
  };

  return (
    <div className="space-y-6">
      {/* Builder Header */}
      <Card className="card-cyber">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center space-x-2">
                <Code className="h-5 w-5 text-primary" />
                <span>Custom Connector Builder</span>
              </CardTitle>
              <CardDescription>
                Create and manage custom data connectors for third-party integrations
              </CardDescription>
            </div>
            <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
              <DialogTrigger asChild>
                <Button variant="cyber">
                  <Plus className="h-4 w-4 mr-2" />
                  New Connector
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl card-cyber">
                <DialogHeader>
                  <DialogTitle>Create Custom Connector</DialogTitle>
                  <DialogDescription>
                    Build a new data connector using our visual interface
                  </DialogDescription>
                </DialogHeader>
                
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="connector-name">Connector Name</Label>
                      <Input
                        id="connector-name"
                        value={connectorConfig.name}
                        onChange={(e) => setConnectorConfig(prev => ({ ...prev, name: e.target.value }))}
                        placeholder="My Custom Connector"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="connector-type">Type</Label>
                      <Select value={connectorConfig.type} onValueChange={(value) => setConnectorConfig(prev => ({ ...prev, type: value }))}>
                        <SelectTrigger>
                          <SelectValue placeholder="Select type" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="REST">REST API</SelectItem>
                          <SelectItem value="GraphQL">GraphQL</SelectItem>
                          <SelectItem value="WebSocket">WebSocket</SelectItem>
                          <SelectItem value="Database">Database</SelectItem>
                          <SelectItem value="File">File/FTP</SelectItem>
                          <SelectItem value="Custom">Custom Protocol</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <Label htmlFor="connector-description">Description</Label>
                    <Textarea
                      id="connector-description"
                      value={connectorConfig.description}
                      onChange={(e) => setConnectorConfig(prev => ({ ...prev, description: e.target.value }))}
                      placeholder="Describe what this connector does..."
                    />
                  </div>
                  
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="connector-endpoint">Endpoint URL</Label>
                      <Input
                        id="connector-endpoint"
                        value={connectorConfig.endpoint}
                        onChange={(e) => setConnectorConfig(prev => ({ ...prev, endpoint: e.target.value }))}
                        placeholder="https://api.example.com/data"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="connector-method">HTTP Method</Label>
                      <Select value={connectorConfig.method} onValueChange={(value) => setConnectorConfig(prev => ({ ...prev, method: value }))}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="GET">GET</SelectItem>
                          <SelectItem value="POST">POST</SelectItem>
                          <SelectItem value="PUT">PUT</SelectItem>
                          <SelectItem value="DELETE">DELETE</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-end space-x-2 pt-4">
                    <Button
                      variant="outline"
                      onClick={() => setShowCreateDialog(false)}
                    >
                      Cancel
                    </Button>
                    <Button
                      variant="cyber"
                      onClick={createConnector}
                      disabled={isBuilding || !connectorConfig.name || !connectorConfig.type}
                    >
                      {isBuilding ? 'Creating...' : 'Create Connector'}
                    </Button>
                  </div>
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </CardHeader>
      </Card>

      {/* Connector Templates */}
      <Tabs defaultValue="templates" className="space-y-4">
        <TabsList className="bg-card border border-border">
          <TabsTrigger value="templates">Templates</TabsTrigger>
          <TabsTrigger value="deployed">Deployed</TabsTrigger>
        </TabsList>

        <TabsContent value="templates" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {templates.map((template) => (
              <Card key={template.id} className="card-cyber">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      {getTypeIcon(template.type)}
                      <div>
                        <CardTitle className="text-base">{template.name}</CardTitle>
                        <CardDescription className="text-sm">
                          {template.description}
                        </CardDescription>
                      </div>
                    </div>
                    <Badge className={getStatusColor(template.status)}>
                      {template.status.toUpperCase()}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div className="text-xs text-muted-foreground">
                      <p>Data Types: {template.dataTypes.join(', ')}</p>
                      <p>Author: {template.author}</p>
                    </div>
                    
                    <div className="flex items-center space-x-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setSelectedTemplate(template)}
                      >
                        <Code className="h-3 w-3 mr-1" />
                        View Code
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => testConnector(template)}
                      >
                        <TestTube className="h-3 w-3 mr-1" />
                        Test
                      </Button>
                      {template.status !== 'deployed' && (
                        <Button
                          variant="cyber"
                          size="sm"
                          onClick={() => deployConnector(template)}
                        >
                          <Upload className="h-3 w-3 mr-1" />
                          Deploy
                        </Button>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="deployed" className="space-y-4">
          <div className="grid grid-cols-1 gap-4">
            {templates.filter(t => t.status === 'deployed').map((template) => (
              <Card key={template.id} className="card-cyber">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      {getTypeIcon(template.type)}
                      <div>
                        <h4 className="font-medium text-foreground">{template.name}</h4>
                        <p className="text-sm text-muted-foreground">{template.description}</p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Badge className="bg-success text-success-foreground">
                        <Shield className="h-3 w-3 mr-1" />
                        ACTIVE
                      </Badge>
                      <Button variant="outline" size="sm">
                        <Settings className="h-3 w-3 mr-1" />
                        Manage
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>

      {/* Code Viewer Dialog */}
      {selectedTemplate && (
        <Dialog open={!!selectedTemplate} onOpenChange={() => setSelectedTemplate(null)}>
          <DialogContent className="max-w-4xl card-cyber">
            <DialogHeader>
              <DialogTitle className="flex items-center space-x-2">
                {getTypeIcon(selectedTemplate.type)}
                <span>{selectedTemplate.name}</span>
              </DialogTitle>
              <DialogDescription>
                {selectedTemplate.description}
              </DialogDescription>
            </DialogHeader>
            
            <div className="space-y-4">
              <pre className="bg-muted/50 p-4 rounded-lg text-sm overflow-auto max-h-96">
                <code>{selectedTemplate.code}</code>
              </pre>
              
              <div className="flex items-center justify-end space-x-2">
                <Button variant="outline" onClick={() => setSelectedTemplate(null)}>
                  Close
                </Button>
                <Button variant="cyber">
                  <Download className="h-4 w-4 mr-2" />
                  Download
                </Button>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      )}
    </div>
  );
};