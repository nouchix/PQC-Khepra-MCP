import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { CheckCircle, Circle, AlertTriangle, DollarSign, Shield, Cloud, Zap, Lock, Users, Database, Globe, Monitor } from 'lucide-react';

export const AWSDeploymentGuide: React.FC = () => {
  const [checkedItems, setCheckedItems] = useState<Set<string>>(new Set());
  
  const toggleCheck = (item: string) => {
    const newChecked = new Set(checkedItems);
    if (newChecked.has(item)) {
      newChecked.delete(item);
    } else {
      newChecked.add(item);
    }
    setCheckedItems(newChecked);
  };

  return (
    <div className="container mx-auto p-6 max-w-6xl">
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold text-foreground mb-4">
            AWS Deployment Guide - SouHimBou AI Security Platform
          </h1>
          <p className="text-muted-foreground text-lg">
            Comprehensive security-focused deployment strategy for the complete SouHimBou AI Security Platform on AWS, 
            including KHEPRA Protocol, threat intelligence, compliance automation, and all integrated security services.
            Designed for DoD contractors, critical infrastructure operators, and enterprise AI environments.
          </p>
        </div>

        {/* Architecture Overview */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Cloud className="h-5 w-5" />
              Platform Architecture Overview
            </CardTitle>
            <CardDescription>
              Complete SouHimBou AI Security Platform deployment on AWS with enterprise-grade security
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="text-center p-4 border rounded-lg">
                <Database className="h-8 w-8 mx-auto mb-2 text-primary" />
                <h3 className="font-semibold">Data Layer</h3>
                <p className="text-sm text-muted-foreground">RDS PostgreSQL Multi-AZ, ElastiCache Redis, S3 Encrypted Storage</p>
              </div>
              <div className="text-center p-4 border rounded-lg">
                <Zap className="h-8 w-8 mx-auto mb-2 text-primary" />
                <h3 className="font-semibold">Application Layer</h3>
                <p className="text-sm text-muted-foreground">ECS Fargate, Lambda Functions, API Gateway, Supabase Backend</p>
              </div>
              <div className="text-center p-4 border rounded-lg">
                <Globe className="h-8 w-8 mx-auto mb-2 text-primary" />
                <h3 className="font-semibold">Frontend Layer</h3>
                <p className="text-sm text-muted-foreground">React App, CloudFront CDN, ALB, SSL/TLS</p>
              </div>
              <div className="text-center p-4 border rounded-lg">
                <Shield className="h-8 w-8 mx-auto mb-2 text-primary" />
                <h3 className="font-semibold">Security Layer</h3>
                <p className="text-sm text-muted-foreground">WAF, GuardDuty, Security Hub, KMS, IAM</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Tabs defaultValue="phases" className="w-full">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="phases">Deployment Phases</TabsTrigger>
            <TabsTrigger value="costs">Cost Analysis</TabsTrigger>
            <TabsTrigger value="compliance">Compliance</TabsTrigger>
            <TabsTrigger value="security">Security Features</TabsTrigger>
          </TabsList>

          <TabsContent value="phases" className="space-y-6">
            <div className="grid gap-6">
              {[
                {
                  phase: "Phase 1: Infrastructure Foundation",
                  duration: "Weeks 1-2",
                  icon: <Cloud className="h-5 w-5" />,
                  color: "bg-blue-500",
                  items: [
                    "Set up AWS GovCloud account for FedRAMP compliance",
                    "Deploy multi-AZ VPC with private/public subnet isolation",
                    "Configure network security groups with least-privilege access",
                    "Implement AWS WAF with custom rules for security protection",
                    "Set up AWS Secrets Manager for secure credential storage",
                    "Enable AWS Security Hub, GuardDuty, and Config for compliance monitoring"
                  ]
                },
                {
                  phase: "Phase 2: Database & Backend Services",
                  duration: "Weeks 2-3",
                  icon: <Database className="h-5 w-5" />,
                  color: "bg-green-500",
                  items: [
                    "Deploy RDS PostgreSQL Multi-AZ with encryption at rest",
                    "Configure automated backups with 30-day retention",
                    "Set up ElastiCache Redis for session management and caching",
                    "Deploy Supabase backend services on ECS Fargate with auto-scaling",
                    "Convert and deploy edge functions as AWS Lambda functions",
                    "Configure API Gateway with throttling and authentication"
                  ]
                },
                {
                  phase: "Phase 3: Frontend & CDN",
                  duration: "Week 3",
                  icon: <Globe className="h-5 w-5" />,
                  color: "bg-purple-500",
                  items: [
                    "Build optimized React production bundle with security headers",
                    "Deploy frontend application to ECS Fargate behind ALB",
                    "Configure CloudFront CDN with AWS Shield Advanced",
                    "Implement SSL/TLS certificates with automatic renewal",
                    "Set up custom domain routing for souhimbou.ai",
                    "Configure WAF rules for application-layer protection"
                  ]
                },
                {
                  phase: "Phase 4: Security Hardening",
                  duration: "Weeks 3-4",
                  icon: <Shield className="h-5 w-5" />,
                  color: "bg-red-500",
                  items: [
                    "Enable CloudTrail for comprehensive audit logging",
                    "Configure AWS Inspector for vulnerability assessments",
                    "Set up AWS Backup for automated disaster recovery",
                    "Implement KMS encryption keys for all services",
                    "Configure SNS alerts for security events and incidents",
                    "Deploy custom CloudWatch dashboards for monitoring"
                  ]
                },
                {
                  phase: "Phase 5: CI/CD & Automation",
                  duration: "Week 4-5",
                  icon: <Zap className="h-5 w-5" />,
                  color: "bg-yellow-500",
                  items: [
                    "Set up CodePipeline with security scanning gates",
                    "Configure CodeBuild for container image scanning",
                    "Implement blue-green deployment strategy",
                    "Set up automated security testing with OWASP ZAP",
                    "Configure dependency vulnerability scanning",
                    "Create infrastructure as code templates (Terraform/CloudFormation)"
                  ]
                },
                {
                  phase: "Phase 6: Compliance & Testing",
                  duration: "Weeks 5-6",
                  icon: <Users className="h-5 w-5" />,
                  color: "bg-indigo-500",
                  items: [
                    "Run comprehensive penetration testing",
                    "Validate FedRAMP compliance requirements",
                    "Generate SOC 2 Type II compliance reports",
                    "Test disaster recovery procedures",
                    "Validate backup and restore processes",
                    "Conduct security incident response drills"
                  ]
                }
              ].map((phase, index) => (
                <Card key={index}>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      {phase.icon}
                      {phase.phase}
                      <Badge variant="secondary">{phase.duration}</Badge>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {phase.items.map((item, itemIndex) => (
                        <div
                          key={itemIndex}
                          className="flex items-center gap-2 cursor-pointer"
                          onClick={() => toggleCheck(`${index}-${itemIndex}`)}
                        >
                          {checkedItems.has(`${index}-${itemIndex}`) ? (
                            <CheckCircle className="h-4 w-4 text-green-500" />
                          ) : (
                            <Circle className="h-4 w-4 text-muted-foreground" />
                          )}
                          <span className={checkedItems.has(`${index}-${itemIndex}`) ? 'line-through text-muted-foreground' : ''}>
                            {item}
                          </span>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </TabsContent>

          <TabsContent value="costs" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <DollarSign className="h-5 w-5" />
                  Monthly Cost Breakdown
                </CardTitle>
                <CardDescription>
                  Estimated monthly costs for production SouHimBou AI deployment
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {[
                    { service: "ECS Fargate (Application Hosting)", cost: "$800-1,200", percentage: 45 },
                    { service: "RDS Multi-AZ PostgreSQL", cost: "$400-600", percentage: 25 },
                    { service: "ElastiCache Redis", cost: "$150-250", percentage: 10 },
                    { service: "CloudFront + ALB", cost: "$50-100", percentage: 5 },
                    { service: "AWS WAF + Shield", cost: "$50-100", percentage: 5 },
                    { service: "GuardDuty + Security Hub", cost: "$30-80", percentage: 3 },
                    { service: "CloudTrail + CloudWatch", cost: "$20-50", percentage: 3 },
                    { service: "Secrets Manager + KMS", cost: "$10-25", percentage: 2 },
                    { service: "Backup Storage (S3)", cost: "$50-150", percentage: 2 }
                  ].map((item, index) => (
                    <div key={index} className="space-y-2">
                      <div className="flex justify-between items-center">
                        <span className="font-medium">{item.service}</span>
                        <span className="text-primary font-semibold">{item.cost}/month</span>
                      </div>
                      <Progress value={item.percentage} className="h-2" />
                    </div>
                  ))}
                  <div className="pt-4 border-t">
                    <div className="flex justify-between items-center text-lg font-bold">
                      <span>Total Estimated Monthly Cost:</span>
                      <span className="text-primary">$1,560-2,555/month</span>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Cost Optimization Strategies</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4">
                  {[
                    "Use Reserved Instances for stable workloads (30-50% savings)",
                    "Implement auto-scaling for variable workloads",
                    "Use Spot Instances for non-critical batch processing",
                    "Configure lifecycle policies for log retention",
                    "Use S3 Intelligent Tiering for backup storage",
                    "Optimize Lambda function memory allocation",
                    "Implement CloudWatch cost monitoring and alerts"
                  ].map((strategy, index) => (
                    <div key={index} className="flex items-center gap-2">
                      <CheckCircle className="h-4 w-4 text-green-500" />
                      <span>{strategy}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="compliance" className="space-y-6">
            <div className="grid gap-6 md:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Shield className="h-5 w-5" />
                    FedRAMP Compliance Requirements
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {[
                      "Encryption at rest and in transit",
                      "Multi-factor authentication",
                      "Role-based access control",
                      "Continuous monitoring",
                      "Incident response procedures",
                      "Audit logging and retention",
                      "Vulnerability management",
                      "Configuration management",
                      "Risk assessment and authorization",
                      "Supply chain risk management"
                    ].map((req, index) => (
                      <div key={index} className="flex items-center gap-2">
                        <CheckCircle className="h-4 w-4 text-green-500" />
                        <span>{req}</span>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Lock className="h-5 w-5" />
                    SOC 2 Type II Controls
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {[
                      "Security controls implementation",
                      "Availability monitoring and alerting",
                      "Processing integrity validation",
                      "Confidentiality through encryption",
                      "Privacy controls for PII handling",
                      "Access management and review",
                      "Change management procedures",
                      "System monitoring and logging",
                      "Vendor and third-party management",
                      "Business continuity planning"
                    ].map((control, index) => (
                      <div key={index} className="flex items-center gap-2">
                        <CheckCircle className="h-4 w-4 text-green-500" />
                        <span>{control}</span>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>

            <Card>
              <CardHeader>
                <CardTitle>Additional Compliance Frameworks</CardTitle>
                <CardDescription>
                  SouHimBou AI supports multiple compliance standards
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 md:grid-cols-3">
                  <div className="text-center p-4 border rounded-lg">
                    <Badge variant="outline" className="mb-2">DoD CMMC</Badge>
                    <p className="text-sm">Level 2 & 3 compliance for defense contractors</p>
                  </div>
                  <div className="text-center p-4 border rounded-lg">
                    <Badge variant="outline" className="mb-2">NIST CSF</Badge>
                    <p className="text-sm">Cybersecurity Framework implementation</p>
                  </div>
                  <div className="text-center p-4 border rounded-lg">
                    <Badge variant="outline" className="mb-2">ISO 27001</Badge>
                    <p className="text-sm">Information security management</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="security" className="space-y-6">
            {/* Infrastructure as Code Section */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Cloud className="h-5 w-5" />
                  Infrastructure as Code Templates
                </CardTitle>
                <CardDescription>
                  Complete CloudFormation/Terraform templates for secure deployment
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="p-4 border rounded-lg bg-muted/30">
                    <h4 className="font-semibold mb-2">Network Foundation</h4>
                    <ul className="text-sm space-y-1">
                      <li>• Multi-AZ VPC with private/public subnet isolation</li>
                      <li>• Network ACLs with least-privilege access</li>
                      <li>• VPC Flow Logs for all traffic analysis</li>
                      <li>• VPC Endpoints for AWS services</li>
                    </ul>
                  </div>
                  <div className="p-4 border rounded-lg bg-muted/30">
                    <h4 className="font-semibold mb-2">Security Groups</h4>
                    <ul className="text-sm space-y-1">
                      <li>• Web Tier: Port 443 from ALB only</li>
                      <li>• App Tier: Port 8080 from Web Tier only</li>
                      <li>• Data Tier: Port 5432 from App Tier only</li>
                      <li>• Default deny outbound rules</li>
                    </ul>
                  </div>
                  <div className="p-4 border rounded-lg bg-muted/30">
                    <h4 className="font-semibold mb-2">ECS Fargate</h4>
                    <ul className="text-sm space-y-1">
                      <li>• Frontend: React App (512 CPU, 1024 Memory)</li>
                      <li>• Backend: Supabase (2048 CPU, 4096 Memory)</li>
                      <li>• Health checks and auto-scaling</li>
                      <li>• Container image vulnerability scanning</li>
                    </ul>
                  </div>
                  <div className="p-4 border rounded-lg bg-muted/30">
                    <h4 className="font-semibold mb-2">RDS Security</h4>
                    <ul className="text-sm space-y-1">
                      <li>• PostgreSQL 15.4 with Multi-AZ</li>
                      <li>• Encryption at rest with KMS</li>
                      <li>• 30-day backup retention</li>
                      <li>• Performance Insights enabled</li>
                    </ul>
                  </div>
                </div>
              </CardContent>
            </Card>

            <div className="grid gap-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Shield className="h-5 w-5" />
                    WAF & Application Security
                  </CardTitle>
                  <CardDescription>
                    Advanced threat protection and application security controls
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid gap-6 md:grid-cols-2">
                    <div>
                      <h4 className="font-semibold mb-3">WAF Rules</h4>
                      <div className="space-y-2">
                        {[
                          "VPC with private/public subnet isolation",
                          "AWS WAF with OWASP Top 10 protection",
                          "DDoS protection with AWS Shield Advanced",
                          "Network ACLs and Security Groups",
                          "VPC Flow Logs for network monitoring"
                        ].map((item, index) => (
                          <div key={index} className="flex items-center gap-2">
                            <CheckCircle className="h-4 w-4 text-green-500" />
                            <span className="text-sm">{item}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                    
                    <div>
                      <h4 className="font-semibold mb-3">Data Protection</h4>
                      <div className="space-y-2">
                        {[
                          "Encryption at rest with AWS KMS",
                          "TLS 1.3 encryption in transit",
                          "Database encryption with customer-managed keys",
                          "Secrets management with rotation",
                          "PII data masking and tokenization"
                        ].map((item, index) => (
                          <div key={index} className="flex items-center gap-2">
                            <CheckCircle className="h-4 w-4 text-green-500" />
                            <span className="text-sm">{item}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                    
                    <div>
                      <h4 className="font-semibold mb-3">Access Control</h4>
                      <div className="space-y-2">
                        {[
                          "IAM roles with least-privilege access",
                          "Multi-factor authentication (MFA)",
                          "Single Sign-On (SSO) integration",
                          "Role-based access control (RBAC)",
                          "Regular access reviews and audits"
                        ].map((item, index) => (
                          <div key={index} className="flex items-center gap-2">
                            <CheckCircle className="h-4 w-4 text-green-500" />
                            <span className="text-sm">{item}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                    
                    <div>
                      <h4 className="font-semibold mb-3">Monitoring & Response</h4>
                      <div className="space-y-2">
                        {[
                          "24/7 security monitoring with GuardDuty",
                          "Real-time threat detection and alerts",
                          "Automated incident response playbooks",
                          "Comprehensive audit logging",
                          "Security metrics and dashboards"
                        ].map((item, index) => (
                          <div key={index} className="flex items-center gap-2">
                            <CheckCircle className="h-4 w-4 text-green-500" />
                            <span className="text-sm">{item}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Security Services Integration</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid gap-4 md:grid-cols-3">
                    <div className="text-center p-4 border rounded-lg">
                      <Monitor className="h-8 w-8 mx-auto mb-2 text-primary" />
                      <h4 className="font-semibold">KHEPRA Protocol</h4>
                      <p className="text-sm text-muted-foreground">Advanced AI threat detection and cultural intelligence</p>
                    </div>
                    <div className="text-center p-4 border rounded-lg">
                      <Users className="h-8 w-8 mx-auto mb-2 text-primary" />
                      <h4 className="font-semibold">Compliance Engine</h4>
                      <p className="text-sm text-muted-foreground">Automated compliance monitoring and reporting</p>
                    </div>
                    <div className="text-center p-4 border rounded-lg">
                      <Zap className="h-8 w-8 mx-auto mb-2 text-primary" />
                      <h4 className="font-semibold">Integration Hub</h4>
                      <p className="text-sm text-muted-foreground">Secure connections to 200+ security tools</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>

        <Card>
          <CardHeader>
            <CardTitle>Deployment Summary</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-3">
              <div className="text-center p-4 border rounded-lg">
                <Badge variant="outline" className="mb-2">Timeline</Badge>
                <p className="text-2xl font-bold text-primary">6 Weeks</p>
                <p className="text-sm text-muted-foreground">Full production deployment</p>
              </div>
              <div className="text-center p-4 border rounded-lg">
                <Badge variant="outline" className="mb-2">Cost</Badge>
                <p className="text-2xl font-bold text-primary">$1,560-2,555</p>
                <p className="text-sm text-muted-foreground">Monthly operational cost</p>
              </div>
              <div className="text-center p-4 border rounded-lg">
                <Badge variant="outline" className="mb-2">Compliance</Badge>
                <p className="text-2xl font-bold text-primary">FedRAMP</p>
                <p className="text-sm text-muted-foreground">SOC 2, CMMC ready</p>
              </div>
            </div>
            
            <div className="mt-6 p-4 bg-muted rounded-lg">
              <div className="flex items-start gap-2">
                <AlertTriangle className="h-5 w-5 text-yellow-500 mt-0.5" />
                <div>
                  <h4 className="font-semibold">Key Benefits</h4>
                  <ul className="text-sm text-muted-foreground mt-2 space-y-1">
                    <li>• Enterprise-scale security architecture</li>
                    <li>• FedRAMP and SOC 2 Type II compliance ready</li>
                    <li>• High availability with 99.9% uptime SLA</li>
                    <li>• Automated disaster recovery and backup</li>
                    <li>• Comprehensive threat detection and response</li>
                    <li>• Integration with existing security infrastructure</li>
                  </ul>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};