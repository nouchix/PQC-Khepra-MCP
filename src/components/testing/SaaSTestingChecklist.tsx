import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Checkbox } from '@/components/ui/checkbox';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { 
  Shield, 
  Settings, 
  Globe, 
  Database, 
  Zap, 
  Users, 
  Lock, 
  RefreshCw,
  ChevronDown,
  ChevronRight,
  CheckCircle2,
  AlertTriangle,
  Info
} from 'lucide-react';

interface TestItem {
  id: string;
  title: string;
  description: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  completed: boolean;
  category: string;
}

interface TestCategory {
  id: string;
  title: string;
  description: string;
  icon: React.ReactNode;
  items: TestItem[];
  expanded: boolean;
}

const SaaSTestingChecklist = () => {
  const [categories, setCategories] = useState<TestCategory[]>([
    {
      id: 'pre-testing',
      title: 'Pre-Testing Preparations',
      description: 'Essential setup before beginning testing',
      icon: <Settings className="h-5 w-5" />,
      expanded: true,
      items: [
        {
          id: 'env-setup',
          title: 'Set Up Test Environment',
          description: 'Secure stable, replicable environment separate from production',
          priority: 'critical',
          completed: false,
          category: 'pre-testing'
        },
        {
          id: 'tool-identification',
          title: 'Identify Test Tools and Resources',
          description: 'Select SaaS-specific testing tools and allocate necessary resources',
          priority: 'high',
          completed: false,
          category: 'pre-testing'
        },
        {
          id: 'test-objectives',
          title: 'Finalize Test Objectives',
          description: 'Define scope, set measurable objectives, prioritize critical areas',
          priority: 'high',
          completed: false,
          category: 'pre-testing'
        }
      ]
    },
    {
      id: 'functional',
      title: 'Functional Testing',
      description: 'Core functionality validation',
      icon: <Zap className="h-5 w-5" />,
      expanded: false,
      items: [
        {
          id: 'core-functions',
          title: 'Test Core Functionalities',
          description: 'User registration, login, data processing, UI-server-database communications',
          priority: 'critical',
          completed: false,
          category: 'functional'
        },
        {
          id: 'interface-testing',
          title: 'Interface Testing',
          description: 'Buttons, links, menus, forms, responsiveness, modal windows',
          priority: 'high',
          completed: false,
          category: 'functional'
        },
        {
          id: 'user-experience',
          title: 'User Experience & Accessibility',
          description: 'Navigation, performance, accessibility features, notifications',
          priority: 'high',
          completed: false,
          category: 'functional'
        },
        {
          id: 'network-conditions',
          title: 'Network Condition Testing',
          description: 'Test under high latency, low bandwidth, interrupted connections',
          priority: 'medium',
          completed: false,
          category: 'functional'
        }
      ]
    },
    {
      id: 'security',
      title: 'Security Testing',
      description: 'Comprehensive security validation',
      icon: <Shield className="h-5 w-5" />,
      expanded: false,
      items: [
        {
          id: 'vulnerability-assessment',
          title: 'Vulnerability Assessment',
          description: 'Check for outdated libraries, unprotected services, default credentials',
          priority: 'critical',
          completed: false,
          category: 'security'
        },
        {
          id: 'penetration-testing',
          title: 'Penetration Testing',
          description: 'Bypass authentication, simulate breaches, probe server vulnerabilities',
          priority: 'critical',
          completed: false,
          category: 'security'
        },
        {
          id: 'data-encryption',
          title: 'Data Encryption Checks',
          description: 'Validate encryption at rest and in transit using industry standards',
          priority: 'critical',
          completed: false,
          category: 'security'
        },
        {
          id: 'session-management',
          title: 'Session Management',
          description: 'Test session timeouts, token security, session termination',
          priority: 'high',
          completed: false,
          category: 'security'
        }
      ]
    },
    {
      id: 'compatibility',
      title: 'Compatibility Testing',
      description: 'Cross-platform compatibility validation',
      icon: <Globe className="h-5 w-5" />,
      expanded: false,
      items: [
        {
          id: 'browser-testing',
          title: 'Browser Compatibility',
          description: 'Test on Chrome, Firefox, Safari, Edge, mobile browsers',
          priority: 'high',
          completed: false,
          category: 'compatibility'
        },
        {
          id: 'os-testing',
          title: 'Operating System Testing',
          description: 'Validate on Windows, macOS, Linux, Android, iOS',
          priority: 'high',
          completed: false,
          category: 'compatibility'
        },
        {
          id: 'device-testing',
          title: 'Device & Screen Testing',
          description: 'Test on various devices, screen sizes, and resolutions',
          priority: 'medium',
          completed: false,
          category: 'compatibility'
        }
      ]
    },
    {
      id: 'integration',
      title: 'Integration Testing',
      description: 'Third-party and system integration validation',
      icon: <RefreshCw className="h-5 w-5" />,
      expanded: false,
      items: [
        {
          id: 'api-testing',
          title: 'API & Endpoint Validation',
          description: 'Test all endpoints, error handling, authentication, data consistency',
          priority: 'critical',
          completed: false,
          category: 'integration'
        },
        {
          id: 'third-party',
          title: 'Third-Party Integrations',
          description: 'Validate CRM, ERP integrations, data flow, error handling',
          priority: 'high',
          completed: false,
          category: 'integration'
        },
        {
          id: 'database-integration',
          title: 'Database Integration',
          description: 'Data integrity, SQL injection protection, backup/restore',
          priority: 'critical',
          completed: false,
          category: 'integration'
        },
        {
          id: 'payment-integration',
          title: 'Payment Integration',
          description: 'Payment gateways, transaction security, error handling',
          priority: 'critical',
          completed: false,
          category: 'integration'
        }
      ]
    },
    {
      id: 'backup-recovery',
      title: 'Backup & Recovery Testing',
      description: 'Data protection and recovery validation',
      icon: <Database className="h-5 w-5" />,
      expanded: false,
      items: [
        {
          id: 'backup-protocols',
          title: 'Data Backup Protocols',
          description: 'Validate backup schedules, integrity, encryption, versioning',
          priority: 'critical',
          completed: false,
          category: 'backup-recovery'
        },
        {
          id: 'recovery-processes',
          title: 'Recovery Processes',
          description: 'Full system recovery, specific data restoration, varied scenarios',
          priority: 'critical',
          completed: false,
          category: 'backup-recovery'
        },
        {
          id: 'backup-storage',
          title: 'Backup Storage',
          description: 'Compression, redundancy, off-site solutions, access controls',
          priority: 'high',
          completed: false,
          category: 'backup-recovery'
        }
      ]
    },
    {
      id: 'localization',
      title: 'Localization & Globalization',
      description: 'Multi-language and regional testing',
      icon: <Users className="h-5 w-5" />,
      expanded: false,
      items: [
        {
          id: 'language-testing',
          title: 'Language & Text Elements',
          description: 'Translation accuracy, text display, special characters',
          priority: 'medium',
          completed: false,
          category: 'localization'
        },
        {
          id: 'regional-formats',
          title: 'Regional Formats',
          description: 'Date, time, currency formats, regional standards',
          priority: 'medium',
          completed: false,
          category: 'localization'
        },
        {
          id: 'cultural-testing',
          title: 'Cultural Nuances',
          description: 'Cultural appropriateness, color meanings, content relevance',
          priority: 'low',
          completed: false,
          category: 'localization'
        }
      ]
    },
    {
      id: 'maintenance',
      title: 'Maintenance Testing',
      description: 'Post-launch and update testing',
      icon: <Lock className="h-5 w-5" />,
      expanded: false,
      items: [
        {
          id: 'post-update-testing',
          title: 'Post-Update Functionality',
          description: 'Test primary features after updates, check for new bugs',
          priority: 'high',
          completed: false,
          category: 'maintenance'
        },
        {
          id: 'performance-monitoring',
          title: 'Performance & Scalability',
          description: 'Monitor speed, user loads, server stability',
          priority: 'high',
          completed: false,
          category: 'maintenance'
        },
        {
          id: 'security-patches',
          title: 'Security Patch Testing',
          description: 'Test vulnerabilities after patches, verify fixes',
          priority: 'critical',
          completed: false,
          category: 'maintenance'
        }
      ]
    }
  ]);

  const priorityColors = {
    critical: 'bg-destructive/30 text-destructive-foreground border-destructive/50',
    high: 'bg-destructive/20 text-destructive-foreground border-destructive/30',
    medium: 'bg-accent/20 text-accent-foreground border-accent/30',
    low: 'bg-primary/20 text-primary border-primary/30'
  };

  const toggleCategory = (categoryId: string) => {
    setCategories(prev => prev.map(cat => 
      cat.id === categoryId ? { ...cat, expanded: !cat.expanded } : cat
    ));
  };

  const toggleItem = (categoryId: string, itemId: string) => {
    setCategories(prev => prev.map(cat => 
      cat.id === categoryId 
        ? {
            ...cat,
            items: cat.items.map(item => 
              item.id === itemId ? { ...item, completed: !item.completed } : item
            )
          }
        : cat
    ));
  };

  const getTotalProgress = () => {
    const totalItems = categories.reduce((sum, cat) => sum + cat.items.length, 0);
    const completedItems = categories.reduce((sum, cat) => 
      sum + cat.items.filter(item => item.completed).length, 0
    );
    return totalItems > 0 ? (completedItems / totalItems) * 100 : 0;
  };

  const getCategoryProgress = (category: TestCategory) => {
    const total = category.items.length;
    const completed = category.items.filter(item => item.completed).length;
    return total > 0 ? (completed / total) * 100 : 0;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-2xl font-bold">SaaS Testing Checklist</CardTitle>
              <p className="text-muted-foreground mt-2">
                Comprehensive testing framework for SaaS applications
              </p>
            </div>
            <Badge variant="outline" className="bg-primary/20 text-primary border-primary/30">
              Professional Grade
            </Badge>
          </div>
          
          {/* Overall Progress */}
          <div className="mt-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium">Overall Progress</span>
              <span className="text-sm text-muted-foreground">
                {Math.round(getTotalProgress())}% Complete
              </span>
            </div>
            <Progress value={getTotalProgress()} className="h-2" />
          </div>
        </CardHeader>
      </Card>

      {/* Categories */}
      <div className="space-y-4">
        {categories.map((category) => (
          <Card key={category.id}>
            <Collapsible open={category.expanded} onOpenChange={() => toggleCategory(category.id)}>
              <CollapsibleTrigger asChild>
                <CardHeader className="cursor-pointer hover:bg-muted/50 transition-colors">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-primary/10">
                        {category.icon}
                      </div>
                      <div>
                        <CardTitle className="text-lg">{category.title}</CardTitle>
                        <p className="text-sm text-muted-foreground">{category.description}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="text-right">
                        <div className="text-sm font-medium">
                          {category.items.filter(item => item.completed).length}/{category.items.length}
                        </div>
                        <div className="text-xs text-muted-foreground">
                          {Math.round(getCategoryProgress(category))}% done
                        </div>
                      </div>
                      {category.expanded ? (
                        <ChevronDown className="h-4 w-4" />
                      ) : (
                        <ChevronRight className="h-4 w-4" />
                      )}
                    </div>
                  </div>
                  
                  {/* Category Progress */}
                  <Progress value={getCategoryProgress(category)} className="h-1 mt-2" />
                </CardHeader>
              </CollapsibleTrigger>
              
              <CollapsibleContent>
                <CardContent className="pt-0">
                  <div className="space-y-3">
                    {category.items.map((item) => (
                      <div 
                        key={item.id}
                        className={`p-4 rounded-lg border transition-all ${
                          item.completed 
                            ? 'bg-muted/50 border-muted' 
                            : 'bg-card border-border hover:border-primary/30'
                        }`}
                      >
                        <div className="flex items-start gap-3">
                          <Checkbox
                            checked={item.completed}
                            onCheckedChange={() => toggleItem(category.id, item.id)}
                            className="mt-1"
                          />
                          
                          <div className="flex-1 space-y-2 min-w-0">
                            <div className="flex items-start justify-between gap-3">
                              <div className="space-y-1 min-w-0 flex-1">
                                <h4 className={`font-medium text-sm leading-tight ${
                                  item.completed ? 'line-through text-muted-foreground' : ''
                                }`}>
                                  {item.title}
                                </h4>
                                <p className="text-xs text-muted-foreground leading-relaxed">
                                  {item.description}
                                </p>
                              </div>
                              
                              <Badge 
                                variant="outline" 
                                className={`text-xs whitespace-nowrap flex-shrink-0 ${priorityColors[item.priority]}`}
                              >
                                {item.priority}
                              </Badge>
                            </div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </CollapsibleContent>
            </Collapsible>
          </Card>
        ))}
      </div>

      {/* Summary */}
      <Card>
        <CardContent className="pt-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">
                {categories.reduce((sum, cat) => sum + cat.items.filter(item => item.completed).length, 0)}
              </div>
              <div className="text-sm text-muted-foreground">Tests Completed</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-accent">
                {categories.reduce((sum, cat) => sum + cat.items.filter(item => !item.completed).length, 0)}
              </div>
              <div className="text-sm text-muted-foreground">Tests Remaining</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-secondary">
                {categories.reduce((sum, cat) => sum + cat.items.filter(item => item.priority === 'critical').length, 0)}
              </div>
              <div className="text-sm text-muted-foreground">Critical Tests</div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default SaaSTestingChecklist;