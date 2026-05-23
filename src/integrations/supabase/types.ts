export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "13.0.4"
  }
  graphql_public: {
    Tables: {
      [_ in never]: never
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      graphql: {
        Args: {
          extensions?: Json
          operationName?: string
          query?: string
          variables?: Json
        }
        Returns: Json
      }
    }
    Enums: {
      [_ in never]: never
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
  public: {
    Tables: {
      admin_roles: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      agent_actions: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      agent_workflows: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      ai_agent_chats: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      ai_agents: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      ai_compliance_agents: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      alert_rules: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      alerts: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      api_integrations: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      asset_configuration_snapshots: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      beta_enrollments: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      billing_periods: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      cloud_connections: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      cmmc_control_mappings: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      cmmc_stig_mappings: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      compliance_assessments: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      compliance_drift_events: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      compliance_evidence: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      compliance_implementations: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      compliance_reports: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      compliance_validation_results: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      connector_api_licenses: {
        Row: {
          id: string
          organization_id: string
          api_key_hash: string
          tier: 'community' | 'professional' | 'enterprise' | 'partner'
          rate_limit_rpm: number
          rate_limit_daily: number
          allowed_actions: string[]
          pqc_public_key: string | null
          issued_at: string
          expires_at: string | null
          revoked: boolean
          revoked_at: string | null
          metadata: Json
        }
        Insert: {
          id?: string
          organization_id: string
          api_key_hash: string
          tier?: 'community' | 'professional' | 'enterprise' | 'partner'
          rate_limit_rpm?: number
          rate_limit_daily?: number
          allowed_actions?: string[]
          pqc_public_key?: string | null
          issued_at?: string
          expires_at?: string | null
          revoked?: boolean
          revoked_at?: string | null
          metadata?: Json
        }
        Update: {
          id?: string
          organization_id?: string
          api_key_hash?: string
          tier?: 'community' | 'professional' | 'enterprise' | 'partner'
          rate_limit_rpm?: number
          rate_limit_daily?: number
          allowed_actions?: string[]
          pqc_public_key?: string | null
          issued_at?: string
          expires_at?: string | null
          revoked?: boolean
          revoked_at?: string | null
          metadata?: Json
        }
        Relationships: []
      }
      connector_dag_nodes: {
        Row: {
          id: string
          node_hash: string
          parent_hashes: string[]
          action: string
          symbol: string
          actor_id: string | null
          organization_id: string
          connector_id: string | null
          pqc_metadata: Json
          hmac_signature: string | null
          ml_dsa_signature: string | null
          created_at: string
        }
        Insert: {
          id?: string
          node_hash: string
          parent_hashes?: string[]
          action: string
          symbol: string
          actor_id?: string | null
          organization_id: string
          connector_id?: string | null
          pqc_metadata?: Json
          hmac_signature?: string | null
          ml_dsa_signature?: string | null
          created_at?: string
        }
        Update: {
          id?: string
          node_hash?: string
          parent_hashes?: string[]
          action?: string
          symbol?: string
          actor_id?: string | null
          organization_id?: string
          connector_id?: string | null
          pqc_metadata?: Json
          hmac_signature?: string | null
          ml_dsa_signature?: string | null
          created_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "connector_dag_nodes_actor_id_fkey"
            columns: ["actor_id"]
            referencedRelation: "users"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "connector_dag_nodes_connector_id_fkey"
            columns: ["connector_id"]
            referencedRelation: "compliance_connectors"
            referencedColumns: ["id"]
          }
        ]
      }
      connector_failure_log: {
        Row: {
          id: string
          organization_id: string
          connector_id: string | null
          provider: string
          error_code: string | null
          error_body: Json
          http_status: number | null
          attempted_at: string
          dag_node_hash: string | null
          pattern_generated: boolean
          pattern_id: string | null
        }
        Insert: {
          id?: string
          organization_id: string
          connector_id?: string | null
          provider: string
          error_code?: string | null
          error_body?: Json
          http_status?: number | null
          attempted_at?: string
          dag_node_hash?: string | null
          pattern_generated?: boolean
          pattern_id?: string | null
        }
        Update: {
          id?: string
          organization_id?: string
          connector_id?: string | null
          provider?: string
          error_code?: string | null
          error_body?: Json
          http_status?: number | null
          attempted_at?: string
          dag_node_hash?: string | null
          pattern_generated?: boolean
          pattern_id?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "connector_failure_log_connector_id_fkey"
            columns: ["connector_id"]
            referencedRelation: "compliance_connectors"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "connector_failure_log_dag_node_hash_fkey"
            columns: ["dag_node_hash"]
            referencedRelation: "connector_dag_nodes"
            referencedColumns: ["node_hash"]
          }
        ]
      }
      connector_usage_events: {
        Row: {
          id: string
          organization_id: string
          license_id: string | null
          session_id: string | null
          dag_node_hash: string | null
          action: string
          provider: string | null
          billable: boolean
          cost_units: number
          occurred_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          license_id?: string | null
          session_id?: string | null
          dag_node_hash?: string | null
          action: string
          provider?: string | null
          billable?: boolean
          cost_units?: number
          occurred_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          license_id?: string | null
          session_id?: string | null
          dag_node_hash?: string | null
          action?: string
          provider?: string | null
          billable?: boolean
          cost_units?: number
          occurred_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "connector_usage_events_license_id_fkey"
            columns: ["license_id"]
            referencedRelation: "connector_api_licenses"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "connector_usage_events_session_id_fkey"
            columns: ["session_id"]
            referencedRelation: "pqc_oauth_sessions"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "connector_usage_events_dag_node_hash_fkey"
            columns: ["dag_node_hash"]
            referencedRelation: "connector_dag_nodes"
            referencedColumns: ["node_hash"]
          }
        ]
      }
      pqc_oauth_sessions: {
        Row: {
          id: string
          user_id: string
          organization_id: string
          license_id: string | null
          tier: string
          threat_level: 'green' | 'yellow' | 'orange' | 'red'
          allowed_scopes: string[]
          token_hash: string
          ml_dsa_signature: string | null
          issued_at: string
          expires_at: string
          last_used_at: string | null
          revoked: boolean
        }
        Insert: {
          id?: string
          user_id: string
          organization_id: string
          license_id?: string | null
          tier?: string
          threat_level?: 'green' | 'yellow' | 'orange' | 'red'
          allowed_scopes?: string[]
          token_hash: string
          ml_dsa_signature?: string | null
          issued_at?: string
          expires_at?: string
          last_used_at?: string | null
          revoked?: boolean
        }
        Update: {
          id?: string
          user_id?: string
          organization_id?: string
          license_id?: string | null
          tier?: string
          threat_level?: 'green' | 'yellow' | 'orange' | 'red'
          allowed_scopes?: string[]
          token_hash?: string
          ml_dsa_signature?: string | null
          issued_at?: string
          expires_at?: string
          last_used_at?: string | null
          revoked?: boolean
        }
        Relationships: [
          {
            foreignKeyName: "pqc_oauth_sessions_user_id_fkey"
            columns: ["user_id"]
            referencedRelation: "users"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "pqc_oauth_sessions_license_id_fkey"
            columns: ["license_id"]
            referencedRelation: "connector_api_licenses"
            referencedColumns: ["id"]
          }
        ]
      }
      data_source_configurations: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      deployments: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      disa_stigs_api_cache: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      discovered_assets: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      discovery_audit_trail: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      discovery_credentials: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      discovery_executions: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      discovery_jobs: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      encryption_keys: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      enhanced_open_controls_integrations: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      enterprise_performance_analytics: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      environment_assets: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      event_sources: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      infrastructure_assets: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      infrastructure_audit: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      integration_tickets: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      integrations_library: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      live_api_gateway_requests: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      ml_training_datasets: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      monday_integration_config: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      monday_sync_history: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      nist_controls: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      open_controls_performance_metrics: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      organization_integrations: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      organization_settings: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      performance_metrics: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      referrals: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      remediation_activities: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      resource_usage: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      secure_discovery_credentials: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      security_audit_enhanced: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      security_devices: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      session_security_events: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      stig_analytics_metrics: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      stig_applicability_rules: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      stig_assessment_results: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      stig_baselines: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      stig_compliance_policies: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      stig_compliance_reports: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      stig_monitoring_agents: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      stig_remediation_executions: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      stig_remediation_workflows: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      stig_rule_implementations: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      stig_rules: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      stig_trusted_registry: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      subscriptions: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      threat_intelligence: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      threat_investigations: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      trusted_devices: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      usage_costs_summary: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      usage_quotas: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      user_agreements: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      user_integrations: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      user_roles: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      webhook_activity: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      zero_trust_device_assessments: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      zero_trust_network_segments: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      zero_trust_policies: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }
      zero_trust_risk_assessments: {
        Row: any
        Insert: any
        Update: any
        Relationships: []
      }

      adinkra_symbols: {
        Row: {
          adjacency_matrix: Json
          category: Database["public"]["Enums"]["adinkra_category"]
          created_at: string | null
          cultural_weight: number
          id: string
          meaning: string
          name: string
          transformation_rules: Json
          trust_implications: Json
          unicode_symbol: string
          updated_at: string | null
        }
        Insert: {
          adjacency_matrix: Json
          category: Database["public"]["Enums"]["adinkra_category"]
          created_at?: string | null
          cultural_weight?: number
          id?: string
          meaning: string
          name: string
          transformation_rules?: Json
          trust_implications?: Json
          unicode_symbol: string
          updated_at?: string | null
        }
        Update: {
          adjacency_matrix?: Json
          category?: Database["public"]["Enums"]["adinkra_category"]
          created_at?: string | null
          cultural_weight?: number
          id?: string
          meaning?: string
          name?: string
          transformation_rules?: Json
          trust_implications?: Json
          unicode_symbol?: string
          updated_at?: string | null
        }
        Relationships: []
      }
      compliance_connectors: {
        Row: {
          capabilities: Json | null
          config: Json | null
          created_at: string
          id: string
          last_sync: string | null
          name: string
          organization_id: string
          status: string
          type: string
          updated_at: string
        }
        Insert: {
          capabilities?: Json | null
          config?: Json | null
          created_at?: string
          id?: string
          last_sync?: string | null
          name: string
          organization_id: string
          status?: string
          type: string
          updated_at?: string
        }
        Update: {
          capabilities?: Json | null
          config?: Json | null
          created_at?: string
          id?: string
          last_sync?: string | null
          name?: string
          organization_id?: string
          status?: string
          type?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "compliance_connectors_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      compliance_control_gaps: {
        Row: {
          assigned_to: string | null
          control_id: string
          created_at: string
          description: string | null
          due_date: string | null
          id: string
          organization_id: string
          remediation_plan: string | null
          severity: string
          status: string
          title: string
          updated_at: string
        }
        Insert: {
          assigned_to?: string | null
          control_id: string
          created_at?: string
          description?: string | null
          due_date?: string | null
          id?: string
          organization_id: string
          remediation_plan?: string | null
          severity: string
          status?: string
          title: string
          updated_at?: string
        }
        Update: {
          assigned_to?: string | null
          control_id?: string
          created_at?: string
          description?: string | null
          due_date?: string | null
          id?: string
          organization_id?: string
          remediation_plan?: string | null
          severity?: string
          status?: string
          title?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "compliance_control_gaps_control_id_fkey"
            columns: ["control_id"]
            isOneToOne: false
            referencedRelation: "compliance_controls"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "compliance_control_gaps_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      compliance_controls: {
        Row: {
          automation_possible: boolean | null
          control_family: string
          control_id: string | null
          control_identifier: string
          created_at: string
          description: string | null
          framework_id: string
          id: string
          title: string
          updated_at: string
        }
        Insert: {
          automation_possible?: boolean | null
          control_family: string
          control_id?: string | null
          control_identifier: string
          created_at?: string
          description?: string | null
          framework_id: string
          id?: string
          title: string
          updated_at?: string
        }
        Update: {
          automation_possible?: boolean | null
          control_family?: string
          control_id?: string | null
          control_identifier?: string
          created_at?: string
          description?: string | null
          framework_id?: string
          id?: string
          title?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "compliance_controls_framework_id_fkey"
            columns: ["framework_id"]
            isOneToOne: false
            referencedRelation: "compliance_frameworks"
            referencedColumns: ["id"]
          },
        ]
      }
      compliance_frameworks: {
        Row: {
          authority: string | null
          category: string | null
          created_at: string
          description: string | null
          enabled: boolean | null
          id: string
          metadata: Json | null
          name: string
          organization_id: string
          updated_at: string
          version: string
        }
        Insert: {
          authority?: string | null
          category?: string | null
          created_at?: string
          description?: string | null
          enabled?: boolean | null
          id?: string
          metadata?: Json | null
          name: string
          organization_id: string
          updated_at?: string
          version: string
        }
        Update: {
          authority?: string | null
          category?: string | null
          created_at?: string
          description?: string | null
          enabled?: boolean | null
          id?: string
          metadata?: Json | null
          name?: string
          organization_id?: string
          updated_at?: string
          version?: string
        }
        Relationships: [
          {
            foreignKeyName: "compliance_frameworks_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      remediation_executions: {
        Row: {
          created_at: string
          end_time: string | null
          failed_targets: number | null
          id: string
          logs: Json | null
          organization_id: string
          playbook_id: string
          start_time: string
          status: string
          successful_targets: number | null
          target_count: number | null
          triggered_by: string | null
          updated_at: string
        }
        Insert: {
          created_at?: string
          end_time?: string | null
          failed_targets?: number | null
          id?: string
          logs?: Json | null
          organization_id: string
          playbook_id: string
          start_time?: string
          status?: string
          successful_targets?: number | null
          target_count?: number | null
          triggered_by?: string | null
          updated_at?: string
        }
        Update: {
          created_at?: string
          end_time?: string | null
          failed_targets?: number | null
          id?: string
          logs?: Json | null
          organization_id?: string
          playbook_id?: string
          start_time?: string
          status?: string
          successful_targets?: number | null
          target_count?: number | null
          triggered_by?: string | null
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "remediation_executions_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "remediation_executions_playbook_id_fkey"
            columns: ["playbook_id"]
            isOneToOne: false
            referencedRelation: "remediation_playbooks"
            referencedColumns: ["id"]
          },
        ]
      }
      remediation_playbooks: {
        Row: {
          author: string | null
          created_at: string
          created_by: string | null
          description: string | null
          id: string
          last_executed: string | null
          name: string
          organization_id: string
          requires_approval: boolean | null
          rollback_steps: Json | null
          status: string
          steps: Json | null
          success_rate: number | null
          tags: Json | null
          target_type: string
          type: string
          updated_at: string
        }
        Insert: {
          author?: string | null
          created_at?: string
          created_by?: string | null
          description?: string | null
          id?: string
          last_executed?: string | null
          name: string
          organization_id: string
          requires_approval?: boolean | null
          rollback_steps?: Json | null
          status?: string
          steps?: Json | null
          success_rate?: number | null
          tags?: Json | null
          target_type: string
          type: string
          updated_at?: string
        }
        Update: {
          author?: string | null
          created_at?: string
          created_by?: string | null
          description?: string | null
          id?: string
          last_executed?: string | null
          name?: string
          organization_id?: string
          requires_approval?: boolean | null
          rollback_steps?: Json | null
          status?: string
          steps?: Json | null
          success_rate?: number | null
          tags?: Json | null
          target_type?: string
          type?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "remediation_playbooks_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      agent_registry: {
        Row: {
          adinkra_signature: string
          agent_name: string
          assigned_symbol_id: string | null
          behavioral_pattern: Json | null
          created_at: string
          cultural_fingerprint: Json | null
          environment_id: string | null
          id: string
          is_active: boolean
          last_seen: string | null
          last_verification: string | null
          metadata: Json | null
          pubkey: string
          trust_matrix: Json | null
          trust_score: number
          updated_at: string
        }
        Insert: {
          adinkra_signature: string
          agent_name: string
          assigned_symbol_id?: string | null
          behavioral_pattern?: Json | null
          created_at?: string
          cultural_fingerprint?: Json | null
          environment_id?: string | null
          id?: string
          is_active?: boolean
          last_seen?: string | null
          last_verification?: string | null
          metadata?: Json | null
          pubkey: string
          trust_matrix?: Json | null
          trust_score?: number
          updated_at?: string
        }
        Update: {
          adinkra_signature?: string
          agent_name?: string
          assigned_symbol_id?: string | null
          behavioral_pattern?: Json | null
          created_at?: string
          cultural_fingerprint?: Json | null
          environment_id?: string | null
          id?: string
          is_active?: boolean
          last_seen?: string | null
          last_verification?: string | null
          metadata?: Json | null
          pubkey?: string
          trust_matrix?: Json | null
          trust_score?: number
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "agent_registry_assigned_symbol_id_fkey"
            columns: ["assigned_symbol_id"]
            isOneToOne: false
            referencedRelation: "adinkra_symbols"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "agent_registry_environment_id_fkey"
            columns: ["environment_id"]
            isOneToOne: false
            referencedRelation: "secured_environments"
            referencedColumns: ["id"]
          },
        ]
      }
      asset_intel: {
        Row: {
          asset_metadata: Json
          asset_name: string
          asset_type: Database["public"]["Enums"]["asset_type"]
          discovered_at: string
          discovered_by: string | null
          id: string
          is_monitored: boolean
          last_assessed: string
          risk_score: number
          threat_indicators: Json | null
        }
        Insert: {
          asset_metadata?: Json
          asset_name: string
          asset_type: Database["public"]["Enums"]["asset_type"]
          discovered_at?: string
          discovered_by?: string | null
          id?: string
          is_monitored?: boolean
          last_assessed?: string
          risk_score?: number
          threat_indicators?: Json | null
        }
        Update: {
          asset_metadata?: Json
          asset_name?: string
          asset_type?: Database["public"]["Enums"]["asset_type"]
          discovered_at?: string
          discovered_by?: string | null
          id?: string
          is_monitored?: boolean
          last_assessed?: string
          risk_score?: number
          threat_indicators?: Json | null
        }
        Relationships: [
          {
            foreignKeyName: "asset_intel_discovered_by_fkey"
            columns: ["discovered_by"]
            isOneToOne: false
            referencedRelation: "agent_registry"
            referencedColumns: ["id"]
          },
        ]
      }
      audit_log: {
        Row: {
          action: string
          actor: string
          actor_ip: string | null
          created_at: string | null
          id: string
          new_value: Json | null
          old_value: Json | null
          resource_id: string | null
          resource_type: string
        }
        Insert: {
          action: string
          actor: string
          actor_ip?: string | null
          created_at?: string | null
          id?: string
          new_value?: Json | null
          old_value?: Json | null
          resource_id?: string | null
          resource_type: string
        }
        Update: {
          action?: string
          actor?: string
          actor_ip?: string | null
          created_at?: string | null
          id?: string
          new_value?: Json | null
          old_value?: Json | null
          resource_id?: string | null
          resource_type?: string
        }
        Relationships: []
      }
      audit_logs: {
        Row: {
          action: string
          created_at: string | null
          details: Json | null
          id: string
          ip_address: string | null
          resource_type: string | null
          user_agent: string | null
          user_id: string | null
        }
        Insert: {
          action: string
          created_at?: string | null
          details?: Json | null
          id?: string
          ip_address?: string | null
          resource_type?: string | null
          user_agent?: string | null
          user_id?: string | null
        }
        Update: {
          action?: string
          created_at?: string | null
          details?: Json | null
          id?: string
          ip_address?: string | null
          resource_type?: string | null
          user_agent?: string | null
          user_id?: string | null
        }
        Relationships: []
      }
      community_leads: {
        Row: {
          company_name: string
          company_size: string | null
          created_at: string | null
          email: string
          email_sequence_started: boolean | null
          first_name: string
          id: string
          industry: string | null
          newsletter: boolean | null
        }
        Insert: {
          company_name: string
          company_size?: string | null
          created_at?: string | null
          email: string
          email_sequence_started?: boolean | null
          first_name: string
          id?: string
          industry?: string | null
          newsletter?: boolean | null
        }
        Update: {
          company_name?: string
          company_size?: string | null
          created_at?: string | null
          email?: string
          email_sequence_started?: boolean | null
          first_name?: string
          id?: string
          industry?: string | null
          newsletter?: boolean | null
        }
        Relationships: []
      }
      compliance_tasks: {
        Row: {
          assigned_to: string | null
          automation_data: Json | null
          created_at: string
          description: string | null
          due_date: string | null
          id: string
          priority: number
          related_asset_id: string | null
          related_policy_id: string | null
          resolved_at: string | null
          resolved_by: string | null
          status: Database["public"]["Enums"]["task_status"]
          task_type: string
          title: string
          updated_at: string
        }
        Insert: {
          assigned_to?: string | null
          automation_data?: Json | null
          created_at?: string
          description?: string | null
          due_date?: string | null
          id?: string
          priority?: number
          related_asset_id?: string | null
          related_policy_id?: string | null
          resolved_at?: string | null
          resolved_by?: string | null
          status?: Database["public"]["Enums"]["task_status"]
          task_type: string
          title: string
          updated_at?: string
        }
        Update: {
          assigned_to?: string | null
          automation_data?: Json | null
          created_at?: string
          description?: string | null
          due_date?: string | null
          id?: string
          priority?: number
          related_asset_id?: string | null
          related_policy_id?: string | null
          resolved_at?: string | null
          resolved_by?: string | null
          status?: Database["public"]["Enums"]["task_status"]
          task_type?: string
          title?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "compliance_tasks_related_asset_id_fkey"
            columns: ["related_asset_id"]
            isOneToOne: false
            referencedRelation: "asset_intel"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "compliance_tasks_related_policy_id_fkey"
            columns: ["related_policy_id"]
            isOneToOne: false
            referencedRelation: "policy_vault"
            referencedColumns: ["id"]
          },
        ]
      }
      consulting_access: {
        Row: {
          advisory_approved: boolean
          advisory_approved_at: string | null
          advisory_approved_by: string | null
          advisory_requested: boolean
          advisory_requested_at: string | null
          created_at: string
          diagnostic_paid: boolean
          diagnostic_paid_at: string | null
          id: string
          stripe_customer_id: string | null
          subscription_id: string | null
          subscription_status: string | null
          subscription_updated_at: string | null
          updated_at: string
          user_id: string
        }
        Insert: {
          advisory_approved?: boolean
          advisory_approved_at?: string | null
          advisory_approved_by?: string | null
          advisory_requested?: boolean
          advisory_requested_at?: string | null
          created_at?: string
          diagnostic_paid?: boolean
          diagnostic_paid_at?: string | null
          id?: string
          stripe_customer_id?: string | null
          subscription_id?: string | null
          subscription_status?: string | null
          subscription_updated_at?: string | null
          updated_at?: string
          user_id: string
        }
        Update: {
          advisory_approved?: boolean
          advisory_approved_at?: string | null
          advisory_approved_by?: string | null
          advisory_requested?: boolean
          advisory_requested_at?: string | null
          created_at?: string
          diagnostic_paid?: boolean
          diagnostic_paid_at?: string | null
          id?: string
          stripe_customer_id?: string | null
          subscription_id?: string | null
          subscription_status?: string | null
          subscription_updated_at?: string | null
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      crypto_inventory: {
        Row: {
          agent_version: string | null
          compliance_score: number | null
          created_at: string | null
          des_count: number | null
          device_hash: string
          dilithium3_count: number | null
          dilithium5_count: number | null
          ecc_p256_count: number | null
          ecc_p384_count: number | null
          ecc_p521_count: number | null
          hostname: string | null
          id: string
          kyber1024_count: number | null
          kyber512_count: number | null
          kyber768_count: number | null
          last_scan_at: string | null
          md5_count: number | null
          organization_id: string | null
          platform: string | null
          pqc_readiness_score: number | null
          quantum_exposure_score: number | null
          rsa_1024_count: number | null
          rsa_2048_count: number | null
          rsa_3072_count: number | null
          rsa_4096_count: number | null
          sha1_count: number | null
          sphincs_count: number | null
          tls_config: Json | null
          triple_des_count: number | null
        }
        Insert: {
          agent_version?: string | null
          compliance_score?: number | null
          created_at?: string | null
          des_count?: number | null
          device_hash: string
          dilithium3_count?: number | null
          dilithium5_count?: number | null
          ecc_p256_count?: number | null
          ecc_p384_count?: number | null
          ecc_p521_count?: number | null
          hostname?: string | null
          id?: string
          kyber1024_count?: number | null
          kyber512_count?: number | null
          kyber768_count?: number | null
          last_scan_at?: string | null
          md5_count?: number | null
          organization_id?: string | null
          platform?: string | null
          pqc_readiness_score?: number | null
          quantum_exposure_score?: number | null
          rsa_1024_count?: number | null
          rsa_2048_count?: number | null
          rsa_3072_count?: number | null
          rsa_4096_count?: number | null
          sha1_count?: number | null
          sphincs_count?: number | null
          tls_config?: Json | null
          triple_des_count?: number | null
        }
        Update: {
          agent_version?: string | null
          compliance_score?: number | null
          created_at?: string | null
          des_count?: number | null
          device_hash?: string
          dilithium3_count?: number | null
          dilithium5_count?: number | null
          ecc_p256_count?: number | null
          ecc_p384_count?: number | null
          ecc_p521_count?: number | null
          hostname?: string | null
          id?: string
          kyber1024_count?: number | null
          kyber512_count?: number | null
          kyber768_count?: number | null
          last_scan_at?: string | null
          md5_count?: number | null
          organization_id?: string | null
          platform?: string | null
          pqc_readiness_score?: number | null
          quantum_exposure_score?: number | null
          rsa_1024_count?: number | null
          rsa_2048_count?: number | null
          rsa_3072_count?: number | null
          rsa_4096_count?: number | null
          sha1_count?: number | null
          sphincs_count?: number | null
          tls_config?: Json | null
          triple_des_count?: number | null
        }
        Relationships: [
          {
            foreignKeyName: "crypto_inventory_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      cultural_policies: {
        Row: {
          applicable_environments: string[] | null
          created_at: string | null
          created_by: string | null
          cultural_context: string
          enforcement_matrix: Json
          id: string
          is_active: boolean
          policy_name: string
          symbolic_logic: Json
          trust_requirements: Json
          updated_at: string | null
          version: number
          violation_consequences: Json
        }
        Insert: {
          applicable_environments?: string[] | null
          created_at?: string | null
          created_by?: string | null
          cultural_context: string
          enforcement_matrix: Json
          id?: string
          is_active?: boolean
          policy_name: string
          symbolic_logic: Json
          trust_requirements?: Json
          updated_at?: string | null
          version?: number
          violation_consequences?: Json
        }
        Update: {
          applicable_environments?: string[] | null
          created_at?: string | null
          created_by?: string | null
          cultural_context?: string
          enforcement_matrix?: Json
          id?: string
          is_active?: boolean
          policy_name?: string
          symbolic_logic?: Json
          trust_requirements?: Json
          updated_at?: string | null
          version?: number
          violation_consequences?: Json
        }
        Relationships: []
      }
      dark_crypto_moat: {
        Row: {
          affected_device_count: number | null
          affected_org_count: number | null
          aggregate_exposure_value: number | null
          algorithm_name: string
          algorithm_type: string
          cve_references: string[] | null
          deprecation_status: string | null
          id: string
          key_size: number | null
          migration_priority: string | null
          nist_reference: string | null
          quantum_threat_level: string
          recommended_replacement: string | null
          total_key_count: number | null
          updated_at: string | null
          vulnerability_score: number
        }
        Insert: {
          affected_device_count?: number | null
          affected_org_count?: number | null
          aggregate_exposure_value?: number | null
          algorithm_name: string
          algorithm_type: string
          cve_references?: string[] | null
          deprecation_status?: string | null
          id?: string
          key_size?: number | null
          migration_priority?: string | null
          nist_reference?: string | null
          quantum_threat_level: string
          recommended_replacement?: string | null
          total_key_count?: number | null
          updated_at?: string | null
          vulnerability_score: number
        }
        Update: {
          affected_device_count?: number | null
          affected_org_count?: number | null
          aggregate_exposure_value?: number | null
          algorithm_name?: string
          algorithm_type?: string
          cve_references?: string[] | null
          deprecation_status?: string | null
          id?: string
          key_size?: number | null
          migration_priority?: string | null
          nist_reference?: string | null
          quantum_threat_level?: string
          recommended_replacement?: string | null
          total_key_count?: number | null
          updated_at?: string | null
          vulnerability_score?: number
        }
        Relationships: []
      }
      environment_discoveries: {
        Row: {
          cloud_provider: string | null
          created_at: string
          discovery_id: string
          endpoints: Json
          id: string
          organization_id: string
          profile: string | null
          summary: Json | null
        }
        Insert: {
          cloud_provider?: string | null
          created_at?: string
          discovery_id: string
          endpoints?: Json
          id?: string
          organization_id: string
          profile?: string | null
          summary?: Json | null
        }
        Update: {
          cloud_provider?: string | null
          created_at?: string
          discovery_id?: string
          endpoints?: Json
          id?: string
          organization_id?: string
          profile?: string | null
          summary?: Json | null
        }
        Relationships: []
      }
      investigation_sessions: {
        Row: {
          created_at: string
          description: string | null
          id: string
          metadata: Json | null
          name: string
          status: string
          targets: string[] | null
          updated_at: string
          user_id: string | null
        }
        Insert: {
          created_at?: string
          description?: string | null
          id?: string
          metadata?: Json | null
          name: string
          status?: string
          targets?: string[] | null
          updated_at?: string
          user_id?: string | null
        }
        Update: {
          created_at?: string
          description?: string | null
          id?: string
          metadata?: Json | null
          name?: string
          status?: string
          targets?: string[] | null
          updated_at?: string
          user_id?: string | null
        }
        Relationships: []
      }
      khepra_admin_users: {
        Row: {
          activated_at: string | null
          admin_level: string
          created_at: string
          created_by: string | null
          cultural_fingerprint: string | null
          id: string
          is_active: boolean
          permissions: Json
          trust_score: number
          user_id: string
        }
        Insert: {
          activated_at?: string | null
          admin_level?: string
          created_at?: string
          created_by?: string | null
          cultural_fingerprint?: string | null
          id?: string
          is_active?: boolean
          permissions?: Json
          trust_score?: number
          user_id: string
        }
        Update: {
          activated_at?: string | null
          admin_level?: string
          created_at?: string
          created_by?: string | null
          cultural_fingerprint?: string | null
          id?: string
          is_active?: boolean
          permissions?: Json
          trust_score?: number
          user_id?: string
        }
        Relationships: []
      }
      khepra_secret_keys: {
        Row: {
          created_at: string
          created_by: string | null
          cultural_context: Json | null
          expires_at: string | null
          id: string
          is_active: boolean
          key_hash: string
          key_name: string
          key_type: string
          last_used_at: string | null
          security_level: number
          usage_count: number
        }
        Insert: {
          created_at?: string
          created_by?: string | null
          cultural_context?: Json | null
          expires_at?: string | null
          id?: string
          is_active?: boolean
          key_hash: string
          key_name: string
          key_type: string
          last_used_at?: string | null
          security_level?: number
          usage_count?: number
        }
        Update: {
          created_at?: string
          created_by?: string | null
          cultural_context?: Json | null
          expires_at?: string | null
          id?: string
          is_active?: boolean
          key_hash?: string
          key_name?: string
          key_type?: string
          last_used_at?: string | null
          security_level?: number
          usage_count?: number
        }
        Relationships: []
      }
      license_telemetry: {
        Row: {
          compliance_status: string | null
          created_at: string | null
          enrollment_token: string | null
          expires_at: string | null
          features: Json | null
          features_used: Json | null
          heartbeat_count: number | null
          id: string
          issued_at: string
          last_heartbeat_at: string | null
          last_validation_at: string | null
          license_tier: string
          machine_id: string
          organization_id: string | null
          pilot_id: string | null
          stripe_customer_id: string | null
          updated_at: string | null
          validation_count: number | null
          violation_reason: string | null
        }
        Insert: {
          compliance_status?: string | null
          created_at?: string | null
          enrollment_token?: string | null
          expires_at?: string | null
          features?: Json | null
          features_used?: Json | null
          heartbeat_count?: number | null
          id?: string
          issued_at: string
          last_heartbeat_at?: string | null
          last_validation_at?: string | null
          license_tier: string
          machine_id: string
          organization_id?: string | null
          pilot_id?: string | null
          stripe_customer_id?: string | null
          updated_at?: string | null
          validation_count?: number | null
          violation_reason?: string | null
        }
        Update: {
          compliance_status?: string | null
          created_at?: string | null
          enrollment_token?: string | null
          expires_at?: string | null
          features?: Json | null
          features_used?: Json | null
          heartbeat_count?: number | null
          id?: string
          issued_at?: string
          last_heartbeat_at?: string | null
          last_validation_at?: string | null
          license_tier?: string
          machine_id?: string
          organization_id?: string | null
          pilot_id?: string | null
          stripe_customer_id?: string | null
          updated_at?: string | null
          validation_count?: number | null
          violation_reason?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "license_telemetry_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      matrix_operations_log: {
        Row: {
          cultural_context: string | null
          environment_id: string | null
          execution_time_ms: number
          id: string
          input_matrix: Json
          operation_type: Database["public"]["Enums"]["matrix_operation"]
          output_matrix: Json
          source_agent_id: string | null
          symbol_used_id: string | null
          target_agent_id: string | null
          timestamp: string | null
          transformation_applied: Json
          verification_result: boolean
        }
        Insert: {
          cultural_context?: string | null
          environment_id?: string | null
          execution_time_ms: number
          id?: string
          input_matrix: Json
          operation_type: Database["public"]["Enums"]["matrix_operation"]
          output_matrix: Json
          source_agent_id?: string | null
          symbol_used_id?: string | null
          target_agent_id?: string | null
          timestamp?: string | null
          transformation_applied: Json
          verification_result: boolean
        }
        Update: {
          cultural_context?: string | null
          environment_id?: string | null
          execution_time_ms?: number
          id?: string
          input_matrix?: Json
          operation_type?: Database["public"]["Enums"]["matrix_operation"]
          output_matrix?: Json
          source_agent_id?: string | null
          symbol_used_id?: string | null
          target_agent_id?: string | null
          timestamp?: string | null
          transformation_applied?: Json
          verification_result?: boolean
        }
        Relationships: [
          {
            foreignKeyName: "matrix_operations_log_environment_id_fkey"
            columns: ["environment_id"]
            isOneToOne: false
            referencedRelation: "secured_environments"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "matrix_operations_log_symbol_used_id_fkey"
            columns: ["symbol_used_id"]
            isOneToOne: false
            referencedRelation: "adinkra_symbols"
            referencedColumns: ["id"]
          },
        ]
      }
      organization_onboarding: {
        Row: {
          assessment_data: Json | null
          completed_at: string | null
          created_at: string
          current_phase: string | null
          discovery_data: Json | null
          discovery_results: Json | null
          id: string
          intake_data: Json | null
          integration_config: Json | null
          organization_id: string | null
          step: string
          updated_at: string
          user_id: string
        }
        Insert: {
          assessment_data?: Json | null
          completed_at?: string | null
          created_at?: string
          current_phase?: string | null
          discovery_data?: Json | null
          discovery_results?: Json | null
          id?: string
          intake_data?: Json | null
          integration_config?: Json | null
          organization_id?: string | null
          step?: string
          updated_at?: string
          user_id: string
        }
        Update: {
          assessment_data?: Json | null
          completed_at?: string | null
          created_at?: string
          current_phase?: string | null
          discovery_data?: Json | null
          discovery_results?: Json | null
          id?: string
          intake_data?: Json | null
          integration_config?: Json | null
          organization_id?: string | null
          step?: string
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      organizations: {
        Row: {
          cage_code: string | null
          contract_number: string | null
          created_at: string | null
          current_device_count: number | null
          duns_number: string | null
          fedramp_authorized: boolean | null
          id: string
          license_expires_at: string | null
          license_tier: string
          logo_url: string | null
          max_devices: number | null
          name: string
          pqc_transition_complete: boolean | null
          primary_contact_email: string
          settings: Json | null
          slug: string
          stig_compliant: boolean | null
          updated_at: string | null
        }
        Insert: {
          cage_code?: string | null
          contract_number?: string | null
          created_at?: string | null
          current_device_count?: number | null
          duns_number?: string | null
          fedramp_authorized?: boolean | null
          id?: string
          license_expires_at?: string | null
          license_tier?: string
          logo_url?: string | null
          max_devices?: number | null
          name: string
          pqc_transition_complete?: boolean | null
          primary_contact_email: string
          settings?: Json | null
          slug: string
          stig_compliant?: boolean | null
          updated_at?: string | null
        }
        Update: {
          cage_code?: string | null
          contract_number?: string | null
          created_at?: string | null
          current_device_count?: number | null
          duns_number?: string | null
          fedramp_authorized?: boolean | null
          id?: string
          license_expires_at?: string | null
          license_tier?: string
          logo_url?: string | null
          max_devices?: number | null
          name?: string
          pqc_transition_complete?: boolean | null
          primary_contact_email?: string
          settings?: Json | null
          slug?: string
          stig_compliant?: boolean | null
          updated_at?: string | null
        }
        Relationships: []
      }
      osint_investigations: {
        Row: {
          created_at: string
          error_message: string | null
          execution_time_ms: number | null
          id: string
          parameters: Json | null
          results: Json | null
          status: string
          target: string
          tool_id: string
          updated_at: string
          user_id: string | null
        }
        Insert: {
          created_at?: string
          error_message?: string | null
          execution_time_ms?: number | null
          id?: string
          parameters?: Json | null
          results?: Json | null
          status?: string
          target: string
          tool_id: string
          updated_at?: string
          user_id?: string | null
        }
        Update: {
          created_at?: string
          error_message?: string | null
          execution_time_ms?: number | null
          id?: string
          parameters?: Json | null
          results?: Json | null
          status?: string
          target?: string
          tool_id?: string
          updated_at?: string
          user_id?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "osint_investigations_tool_id_fkey"
            columns: ["tool_id"]
            isOneToOne: false
            referencedRelation: "osint_tools"
            referencedColumns: ["id"]
          },
        ]
      }
      osint_tools: {
        Row: {
          category: string
          created_at: string
          description: string | null
          docker_image: string | null
          github_repo: string
          id: string
          input_format: Json
          is_active: boolean
          language: string | null
          last_updated: string | null
          name: string
          output_format: Json
          stars: number | null
          topics: string[] | null
          updated_at: string
        }
        Insert: {
          category: string
          created_at?: string
          description?: string | null
          docker_image?: string | null
          github_repo: string
          id?: string
          input_format?: Json
          is_active?: boolean
          language?: string | null
          last_updated?: string | null
          name: string
          output_format?: Json
          stars?: number | null
          topics?: string[] | null
          updated_at?: string
        }
        Update: {
          category?: string
          created_at?: string
          description?: string | null
          docker_image?: string | null
          github_repo?: string
          id?: string
          input_format?: Json
          is_active?: boolean
          language?: string | null
          last_updated?: string | null
          name?: string
          output_format?: Json
          stars?: number | null
          topics?: string[] | null
          updated_at?: string
        }
        Relationships: []
      }
      password_reset_otps: {
        Row: {
          created_at: string | null
          email: string
          expires_at: string
          id: string
          otp_code: string
          used: boolean | null
          used_at: string | null
          user_id: string
        }
        Insert: {
          created_at?: string | null
          email: string
          expires_at: string
          id?: string
          otp_code: string
          used?: boolean | null
          used_at?: string | null
          user_id: string
        }
        Update: {
          created_at?: string | null
          email?: string
          expires_at?: string
          id?: string
          otp_code?: string
          used?: boolean | null
          used_at?: string | null
          user_id?: string
        }
        Relationships: []
      }
      policy_vault: {
        Row: {
          category: Database["public"]["Enums"]["policy_category"]
          created_at: string
          created_by: string | null
          encrypted_content: string
          id: string
          is_active: boolean
          policy_name: string
          updated_at: string
          version: number
        }
        Insert: {
          category: Database["public"]["Enums"]["policy_category"]
          created_at?: string
          created_by?: string | null
          encrypted_content: string
          id?: string
          is_active?: boolean
          policy_name: string
          updated_at?: string
          version?: number
        }
        Update: {
          category?: Database["public"]["Enums"]["policy_category"]
          created_at?: string
          created_by?: string | null
          encrypted_content?: string
          id?: string
          is_active?: boolean
          policy_name?: string
          updated_at?: string
          version?: number
        }
        Relationships: []
      }
      processed_stripe_events: {
        Row: {
          event_id: string
          metadata: Json | null
          processed_at: string
          stripe_event_type: string
        }
        Insert: {
          event_id: string
          metadata?: Json | null
          processed_at?: string
          stripe_event_type: string
        }
        Update: {
          event_id?: string
          metadata?: Json | null
          processed_at?: string
          stripe_event_type?: string
        }
        Relationships: []
      }
      profiles: {
        Row: {
          created_at: string
          data_classification: string | null
          department: string | null
          emergency_access_codes: string[] | null
          full_name: string | null
          id: string
          is_trial_active: boolean | null
          master_admin: boolean | null
          mfa_backup_codes: string[] | null
          mfa_enabled: boolean | null
          plan_type: string | null
          role: string | null
          security_clearance: string | null
          trial_ends_at: string | null
          trial_starts_at: string | null
          trusted_devices: Json | null
          updated_at: string
          user_id: string
          username: string | null
        }
        Insert: {
          created_at?: string
          data_classification?: string | null
          department?: string | null
          emergency_access_codes?: string[] | null
          full_name?: string | null
          id?: string
          is_trial_active?: boolean | null
          master_admin?: boolean | null
          mfa_backup_codes?: string[] | null
          mfa_enabled?: boolean | null
          plan_type?: string | null
          role?: string | null
          security_clearance?: string | null
          trial_ends_at?: string | null
          trial_starts_at?: string | null
          trusted_devices?: Json | null
          updated_at?: string
          user_id: string
          username?: string | null
        }
        Update: {
          created_at?: string
          data_classification?: string | null
          department?: string | null
          emergency_access_codes?: string[] | null
          full_name?: string | null
          id?: string
          is_trial_active?: boolean | null
          master_admin?: boolean | null
          mfa_backup_codes?: string[] | null
          mfa_enabled?: boolean | null
          plan_type?: string | null
          role?: string | null
          security_clearance?: string | null
          trial_ends_at?: string | null
          trial_starts_at?: string | null
          trusted_devices?: Json | null
          updated_at?: string
          user_id?: string
          username?: string | null
        }
        Relationships: []
      }
      secured_environments: {
        Row: {
          agent_count: number
          created_at: string | null
          environment_name: string
          environment_type: string
          id: string
          last_matrix_operation: string | null
          metadata: Json
          primary_symbol_id: string | null
          protection_matrix: Json
          state: Database["public"]["Enums"]["environment_state"]
          trust_matrix: Json
          updated_at: string | null
        }
        Insert: {
          agent_count?: number
          created_at?: string | null
          environment_name: string
          environment_type: string
          id?: string
          last_matrix_operation?: string | null
          metadata?: Json
          primary_symbol_id?: string | null
          protection_matrix?: Json
          state?: Database["public"]["Enums"]["environment_state"]
          trust_matrix?: Json
          updated_at?: string | null
        }
        Update: {
          agent_count?: number
          created_at?: string | null
          environment_name?: string
          environment_type?: string
          id?: string
          last_matrix_operation?: string | null
          metadata?: Json
          primary_symbol_id?: string | null
          protection_matrix?: Json
          state?: Database["public"]["Enums"]["environment_state"]
          trust_matrix?: Json
          updated_at?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "secured_environments_primary_symbol_id_fkey"
            columns: ["primary_symbol_id"]
            isOneToOne: false
            referencedRelation: "adinkra_symbols"
            referencedColumns: ["id"]
          },
        ]
      }
      security_events: {
        Row: {
          acknowledged_at: string | null
          acknowledged_by: string | null
          archived: boolean | null
          created_at: string | null
          description: string | null
          details: Json | null
          event_type: string
          id: string
          organization_id: string | null
          resolution_notes: string | null
          resolved: boolean | null
          resolved_at: string | null
          resolved_by: string | null
          severity: string
          source_country: string | null
          source_device_id: string | null
          source_ip: string | null
          source_system: string | null
          title: string
        }
        Insert: {
          acknowledged_at?: string | null
          acknowledged_by?: string | null
          archived?: boolean | null
          created_at?: string | null
          description?: string | null
          details?: Json | null
          event_type: string
          id?: string
          organization_id?: string | null
          resolution_notes?: string | null
          resolved?: boolean | null
          resolved_at?: string | null
          resolved_by?: string | null
          severity: string
          source_country?: string | null
          source_device_id?: string | null
          source_ip?: string | null
          source_system?: string | null
          title: string
        }
        Update: {
          acknowledged_at?: string | null
          acknowledged_by?: string | null
          archived?: boolean | null
          created_at?: string | null
          description?: string | null
          details?: Json | null
          event_type?: string
          id?: string
          organization_id?: string | null
          resolution_notes?: string | null
          resolved?: boolean | null
          resolved_at?: string | null
          resolved_by?: string | null
          severity?: string
          source_country?: string | null
          source_device_id?: string | null
          source_ip?: string | null
          source_system?: string | null
          title?: string
        }
        Relationships: [
          {
            foreignKeyName: "security_events_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      session_investigations: {
        Row: {
          investigation_id: string
          session_id: string
        }
        Insert: {
          investigation_id: string
          session_id: string
        }
        Update: {
          investigation_id?: string
          session_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "session_investigations_investigation_id_fkey"
            columns: ["investigation_id"]
            isOneToOne: false
            referencedRelation: "osint_investigations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "session_investigations_session_id_fkey"
            columns: ["session_id"]
            isOneToOne: false
            referencedRelation: "investigation_sessions"
            referencedColumns: ["id"]
          },
        ]
      }
      symbolic_threats: {
        Row: {
          affected_environments: string[] | null
          created_at: string | null
          cultural_implications: Json
          detection_rules: Json
          first_detected: string | null
          id: string
          is_active: boolean
          last_seen: string | null
          metadata: Json
          mitigation_symbol_id: string | null
          severity_score: number
          symbolic_signature: Json
          threat_category: string
          threat_name: string
        }
        Insert: {
          affected_environments?: string[] | null
          created_at?: string | null
          cultural_implications?: Json
          detection_rules?: Json
          first_detected?: string | null
          id?: string
          is_active?: boolean
          last_seen?: string | null
          metadata?: Json
          mitigation_symbol_id?: string | null
          severity_score: number
          symbolic_signature: Json
          threat_category: string
          threat_name: string
        }
        Update: {
          affected_environments?: string[] | null
          created_at?: string | null
          cultural_implications?: Json
          detection_rules?: Json
          first_detected?: string | null
          id?: string
          is_active?: boolean
          last_seen?: string | null
          metadata?: Json
          mitigation_symbol_id?: string | null
          severity_score?: number
          symbolic_signature?: Json
          threat_category?: string
          threat_name?: string
        }
        Relationships: [
          {
            foreignKeyName: "symbolic_threats_mitigation_symbol_id_fkey"
            columns: ["mitigation_symbol_id"]
            isOneToOne: false
            referencedRelation: "adinkra_symbols"
            referencedColumns: ["id"]
          },
        ]
      }
      telemetry_logs: {
        Row: {
          agent_id: string | null
          correlation_id: string | null
          event_data: Json
          event_type: string
          id: string
          severity: Database["public"]["Enums"]["event_severity"]
          source_ip: unknown
          timestamp: string
          user_agent: string | null
        }
        Insert: {
          agent_id?: string | null
          correlation_id?: string | null
          event_data?: Json
          event_type: string
          id?: string
          severity?: Database["public"]["Enums"]["event_severity"]
          source_ip?: unknown
          timestamp?: string
          user_agent?: string | null
        }
        Update: {
          agent_id?: string | null
          correlation_id?: string | null
          event_data?: Json
          event_type?: string
          id?: string
          severity?: Database["public"]["Enums"]["event_severity"]
          source_ip?: unknown
          timestamp?: string
          user_agent?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "telemetry_logs_agent_id_fkey"
            columns: ["agent_id"]
            isOneToOne: false
            referencedRelation: "agent_registry"
            referencedColumns: ["id"]
          },
        ]
      }
      user_organizations: {
        Row: {
          created_at: string
          id: string
          organization_id: string
          role: string
          user_id: string
        }
        Insert: {
          created_at?: string
          id?: string
          organization_id: string
          role?: string
          user_id: string
        }
        Update: {
          created_at?: string
          id?: string
          organization_id?: string
          role?: string
          user_id?: string
        }
        Relationships: []
      }
      user_profiles: {
        Row: {
          avatar_url: string | null
          created_at: string
          culture_fingerprint: string | null
          display_name: string | null
          id: string
          last_login: string | null
          org_id: string | null
          permissions: Json | null
          preferences: Json | null
          role: Database["public"]["Enums"]["user_role"]
          updated_at: string
          user_id: string
        }
        Insert: {
          avatar_url?: string | null
          created_at?: string
          culture_fingerprint?: string | null
          display_name?: string | null
          id?: string
          last_login?: string | null
          org_id?: string | null
          permissions?: Json | null
          preferences?: Json | null
          role?: Database["public"]["Enums"]["user_role"]
          updated_at?: string
          user_id: string
        }
        Update: {
          avatar_url?: string | null
          created_at?: string
          culture_fingerprint?: string | null
          display_name?: string | null
          id?: string
          last_login?: string | null
          org_id?: string | null
          permissions?: Json | null
          preferences?: Json | null
          role?: Database["public"]["Enums"]["user_role"]
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
    }
    Views: {
      v_license_health: {
        Row: {
          compliance_status: string | null
          health_status: string | null
          last_activity: string | null
          license_count: number | null
          license_tier: string | null
          organization_name: string | null
          total_validations: number | null
        }
        Relationships: []
      }
      v_pqc_transition_dashboard: {
        Row: {
          avg_exposure: number | null
          avg_pqc_readiness: number | null
          device_count: number | null
          license_tier: string | null
          organization_name: string | null
          total_classical_keys: number | null
          total_pqc_keys: number | null
        }
        Relationships: []
      }
      v_security_summary: {
        Row: {
          event_count: number | null
          event_date: string | null
          event_type: string | null
          resolved_count: number | null
          severity: string | null
        }
        Relationships: []
      }
    }
    Functions: {
      calculate_pqc_readiness: {
        Args: { inv: Database["public"]["Tables"]["crypto_inventory"]["Row"] }
        Returns: number
      }
      check_auth_rate_limit: {
        Args: { user_identifier: string }
        Returns: boolean
      }
      check_auth_rate_limit_enhanced: {
        Args: { user_identifier: string }
        Returns: boolean
      }
      cleanup_expired_otps: { Args: never; Returns: undefined }
      get_current_user_role: { Args: never; Returns: string }
      get_document_template_by_id: {
        Args: { template_id: string }
        Returns: {
          created_at: string
          description: string
          document_type: string
          fields_schema: Json
          id: string
          is_active: boolean
          jurisdiction: string
          name: string
          price_cents: number
          template_content: string
          updated_at: string
        }[]
      }
      get_document_templates: {
        Args: { filters_json?: Json }
        Returns: {
          created_at: string
          description: string
          document_type: string
          fields_schema: Json
          id: string
          is_active: boolean
          jurisdiction: string
          name: string
          price_cents: number
          template_content: string
          updated_at: string
        }[]
      }
      get_template_document_types: { Args: never; Returns: string[] }
      get_template_jurisdictions: { Args: never; Returns: string[] }
      is_master_admin: { Args: never; Returns: boolean }
      sanitize_user_input: { Args: { input_text: string }; Returns: string }
      update_crypto_moat_stats: { Args: never; Returns: undefined }
      validate_admin_permissions: {
        Args: { permissions_json: Json }
        Returns: boolean
      }
      validate_cultural_input: {
        Args: { input_text: string }
        Returns: boolean
      }
      validate_key_metadata: {
        Args: { key_name: string; key_type: string }
        Returns: boolean
      }
      validate_osint_parameters: { Args: { params: Json }; Returns: boolean }
      validate_sensitive_input: {
        Args: { input_text: string }
        Returns: boolean
      }
      correlate_security_alerts: { Args: Record<string, never> | { [key: string]: Json }; Returns: Json }
      check_security_policy_compliance: { Args: Record<string, never> | { [key: string]: Json }; Returns: Json }
      is_account_locked: { Args: { [key: string]: Json } | Record<string, never>; Returns: boolean }
      is_sunsum_diminished: { Args: Record<string, never> | { [key: string]: Json }; Returns: boolean }
      log_security_event: { Args: { [key: string]: Json } | Record<string, never>; Returns: Json }
      log_third_party_security_event: { Args: { [key: string]: Json } | Record<string, never>; Returns: Json }
      log_user_action: { Args: { [key: string]: Json } | Record<string, never>; Returns: Json }
      record_failed_login: { Args: { [key: string]: Json } | Record<string, never>; Returns: Json }
      record_ritual_lapse: { Args: Record<string, never> | { [key: string]: Json }; Returns: Json }
      validate_password_strength: { Args: { [key: string]: Json } | Record<string, never>; Returns: Json }
      has_accepted_all_agreements: { Args: Record<string, never> | { [key: string]: Json }; Returns: boolean }
      log_clearance_access: { Args: { [key: string]: Json } | Record<string, never>; Returns: Json }
      log_session_security_event: { Args: { [key: string]: Json } | Record<string, never>; Returns: Json }
      log_system_audit: { Args: { [key: string]: Json } | Record<string, never>; Returns: Json }
      track_resource_usage: { Args: { [key: string]: Json } | Record<string, never>; Returns: Json }
      decrypt_credential_data: { Args: { [key: string]: Json } | Record<string, never>; Returns: Json }
      encrypt_credential_data: { Args: { [key: string]: Json } | Record<string, never>; Returns: Json }
    }
    Enums: {
      adinkra_category:
      | "trust"
      | "protection"
      | "wisdom"
      | "strength"
      | "unity"
      | "justice"
      | "leadership"
      | "transformation"
      agent_trust_level:
      | "untrusted"
      | "provisional"
      | "verified"
      | "trusted"
      | "sentinel"
      asset_type: "data" | "model" | "api" | "infrastructure" | "agent"
      environment_state:
      | "initializing"
      | "secured"
      | "monitoring"
      | "threat_detected"
      | "compromised"
      | "recovering"
      event_severity: "low" | "medium" | "high" | "critical"
      matrix_operation:
      | "identity"
      | "transformation"
      | "verification"
      | "propagation"
      | "validation"
      | "enforcement"
      policy_category: "cultural" | "compliance" | "security" | "operational"
      task_status:
      | "pending"
      | "in_progress"
      | "completed"
      | "failed"
      | "overdue"
      user_role: "admin" | "operator" | "analyst" | "viewer"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
  | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
  | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
  ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
    DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
  : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
    DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
  ? R
  : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
    DefaultSchema["Views"])
  ? (DefaultSchema["Tables"] &
    DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
      Row: infer R
    }
  ? R
  : never
  : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
  | keyof DefaultSchema["Tables"]
  | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
  ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
  : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
    Insert: infer I
  }
  ? I
  : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
  ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
    Insert: infer I
  }
  ? I
  : never
  : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
  | keyof DefaultSchema["Tables"]
  | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
  ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
  : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
    Update: infer U
  }
  ? U
  : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
  ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
    Update: infer U
  }
  ? U
  : never
  : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
  | keyof DefaultSchema["Enums"]
  | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
  ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
  : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
  ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
  : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
  | keyof DefaultSchema["CompositeTypes"]
  | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
  ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
  : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
  ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
  : never

export const Constants = {
  graphql_public: {
    Enums: {},
  },
  public: {
    Enums: {
      adinkra_category: [
        "trust",
        "protection",
        "wisdom",
        "strength",
        "unity",
        "justice",
        "leadership",
        "transformation",
      ],
      agent_trust_level: [
        "untrusted",
        "provisional",
        "verified",
        "trusted",
        "sentinel",
      ],
      asset_type: ["data", "model", "api", "infrastructure", "agent"],
      environment_state: [
        "initializing",
        "secured",
        "monitoring",
        "threat_detected",
        "compromised",
        "recovering",
      ],
      event_severity: ["low", "medium", "high", "critical"],
      matrix_operation: [
        "identity",
        "transformation",
        "verification",
        "propagation",
        "validation",
        "enforcement",
      ],
      policy_category: ["cultural", "compliance", "security", "operational"],
      task_status: ["pending", "in_progress", "completed", "failed", "overdue"],
      user_role: ["admin", "operator", "analyst", "viewer"],
    },
  },
} as const
