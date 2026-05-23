export type IndustryType = 'banking' | 'enterprise' | 'smb' | 'government' | 'healthcare';

export type AutomationLevel = 'monitor_only' | 'guided' | 'semi_automated' | 'fully_automated';

export interface DeploymentProfile {
  id: string;
  name: string;
  industry: IndustryType;
  description: string;
  automationLevel: AutomationLevel;
  riskTolerance: 'ultra_conservative' | 'conservative' | 'moderate' | 'aggressive';
  approvalRequired: {
    critical: boolean;
    high: boolean;
    medium: boolean;
    low: boolean;
  };
  monitoringLevel: 'basic' | 'enhanced' | 'comprehensive';
  auditCompliance: boolean;
  allowedActions: string[];
  restrictedSystems: string[];
  trustThresholds: {
    minimum: number;
    promotion: number;
    autonomous: number;
  };
}

export interface OrganizationDeploymentSettings {
  id: string;
  organizationId: string;
  activeProfile: DeploymentProfile;
  customSettings?: Partial<DeploymentProfile>;
  confidenceLevel: number;
  deploymentHistory: DeploymentHistoryEntry[];
  graduationCriteria: GraduationCriteria;
  createdAt: string;
  updatedAt: string;
}

export interface DeploymentHistoryEntry {
  timestamp: string;
  action: string;
  success: boolean;
  riskLevel: string;
  automated: boolean;
  approvedBy?: string;
  notes?: string;
}

export interface GraduationCriteria {
  successRate: number;
  minimumActions: number;
  timeFrameDays: number;
  riskLevelsHandled: string[];
}

export const INDUSTRY_DEPLOYMENT_TEMPLATES: Record<IndustryType, DeploymentProfile> = {
  banking: {
    id: 'banking-template',
    name: 'Banking & Financial Services',
    industry: 'banking',
    description: 'Ultra-conservative deployment with comprehensive monitoring and approval workflows',
    automationLevel: 'monitor_only',
    riskTolerance: 'ultra_conservative',
    approvalRequired: {
      critical: true,
      high: true,
      medium: true,
      low: true
    },
    monitoringLevel: 'comprehensive',
    auditCompliance: true,
    allowedActions: ['monitor', 'alert', 'recommend'],
    restrictedSystems: ['core_banking', 'payment_processing', 'customer_data'],
    trustThresholds: {
      minimum: 95,
      promotion: 98,
      autonomous: 99
    }
  },
  enterprise: {
    id: 'enterprise-template',
    name: 'Enterprise Corporation',
    industry: 'enterprise',
    description: 'Balanced approach with graduated automation based on system criticality',
    automationLevel: 'guided',
    riskTolerance: 'conservative',
    approvalRequired: {
      critical: true,
      high: true,
      medium: false,
      low: false
    },
    monitoringLevel: 'enhanced',
    auditCompliance: true,
    allowedActions: ['monitor', 'alert', 'recommend', 'auto_remediate_low', 'guided_remediate_medium'],
    restrictedSystems: ['hr_systems', 'financial_reporting'],
    trustThresholds: {
      minimum: 75,
      promotion: 85,
      autonomous: 95
    }
  },
  smb: {
    id: 'smb-template',
    name: 'Small to Medium Business',
    industry: 'smb',
    description: 'High automation with basic oversight for resource efficiency',
    automationLevel: 'semi_automated',
    riskTolerance: 'moderate',
    approvalRequired: {
      critical: true,
      high: false,
      medium: false,
      low: false
    },
    monitoringLevel: 'basic',
    auditCompliance: false,
    allowedActions: ['monitor', 'alert', 'recommend', 'auto_remediate_low', 'auto_remediate_medium'],
    restrictedSystems: ['backup_systems'],
    trustThresholds: {
      minimum: 60,
      promotion: 75,
      autonomous: 85
    }
  },
  government: {
    id: 'government-template',
    name: 'Government & Defense',
    industry: 'government',
    description: 'Maximum security with comprehensive audit trails and approval workflows',
    automationLevel: 'guided',
    riskTolerance: 'ultra_conservative',
    approvalRequired: {
      critical: true,
      high: true,
      medium: true,
      low: true
    },
    monitoringLevel: 'comprehensive',
    auditCompliance: true,
    allowedActions: ['monitor', 'alert', 'recommend'],
    restrictedSystems: ['classified_systems', 'command_control', 'intelligence'],
    trustThresholds: {
      minimum: 98,
      promotion: 99,
      autonomous: 100
    }
  },
  healthcare: {
    id: 'healthcare-template',
    name: 'Healthcare & Medical',
    industry: 'healthcare',
    description: 'HIPAA-compliant deployment with patient data protection focus',
    automationLevel: 'guided',
    riskTolerance: 'conservative',
    approvalRequired: {
      critical: true,
      high: true,
      medium: true,
      low: false
    },
    monitoringLevel: 'comprehensive',
    auditCompliance: true,
    allowedActions: ['monitor', 'alert', 'recommend', 'guided_remediate_low'],
    restrictedSystems: ['patient_records', 'medical_devices', 'phi_systems'],
    trustThresholds: {
      minimum: 85,
      promotion: 92,
      autonomous: 97
    }
  }
};