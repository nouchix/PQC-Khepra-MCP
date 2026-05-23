import { useState, useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';
import { Database } from '@/integrations/supabase/types';

type ComplianceFramework = Database['public']['Tables']['compliance_frameworks']['Row'];
type ComplianceControl = Database['public']['Tables']['compliance_controls']['Row'];
type ComplianceAssessment = Database['public']['Tables']['compliance_assessments']['Row'];

export const useComplianceFrameworks = () => {
  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([]);
  const [controls, setControls] = useState<ComplianceControl[]>([]);
  const [assessments, setAssessments] = useState<ComplianceAssessment[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { user } = useAuth();

  useEffect(() => {
    fetchComplianceData();
  }, []);

  const fetchComplianceData = async () => {
    try {
      setLoading(true);
      
      // Fetch frameworks
      const { data: frameworksData, error: frameworksError } = await supabase
        .from('compliance_frameworks')
        .select('*')
        .eq('enabled', true)
        .order('name');

      if (frameworksError) throw frameworksError;
      setFrameworks(frameworksData || []);

      // Fetch controls
      const { data: controlsData, error: controlsError } = await supabase
        .from('compliance_controls')
        .select('*')
        .order('control_id');

      if (controlsError) throw controlsError;
      setControls(controlsData || []);

      // Fetch assessments
      const { data: assessmentsData, error: assessmentsError } = await supabase
        .from('compliance_assessments')
        .select('*')
        .order('created_at', { ascending: false });

      if (assessmentsError) throw assessmentsError;
      setAssessments(assessmentsData || []);

    } catch (err: any) {
      console.error('Error fetching compliance data:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const createFramework = async (framework: Omit<ComplianceFramework, 'id' | 'created_at' | 'updated_at'>) => {
    if (!user) return { error: 'User not authenticated' };

    try {
      const { data, error } = await supabase
        .from('compliance_frameworks')
        .insert([framework])
        .select()
        .single();

      if (error) throw error;
      
      setFrameworks(prev => [...prev, data]);
      
      // Log the action
      await supabase.from('audit_logs').insert({
        user_id: user.id,
        action: 'compliance_framework_created',
        resource_type: 'compliance_framework',
        resource_id: data.id,
        details: { framework_name: framework.name }
      });

      return { data };
    } catch (err: any) {
      return { error: err.message };
    }
  };

  const createControl = async (control: Omit<ComplianceControl, 'id' | 'created_at' | 'updated_at'>) => {
    if (!user) return { error: 'User not authenticated' };

    try {
      const { data, error } = await supabase
        .from('compliance_controls')
        .insert([control])
        .select()
        .single();

      if (error) throw error;
      
      setControls(prev => [...prev, data]);
      
      // Log the action
      await supabase.from('audit_logs').insert({
        user_id: user.id,
        action: 'compliance_control_created',
        resource_type: 'compliance_control',
        resource_id: data.id,
        details: { control_id: control.control_id, title: control.title }
      });

      return { data };
    } catch (err: any) {
      return { error: err.message };
    }
  };

  const createAssessment = async (assessment: Omit<ComplianceAssessment, 'id' | 'created_at' | 'updated_at'>) => {
    if (!user) return { error: 'User not authenticated' };

    try {
      const { data, error } = await supabase
        .from('compliance_assessments')
        .insert([{ ...assessment, created_by: user.id }])
        .select()
        .single();

      if (error) throw error;
      
      setAssessments(prev => [data, ...prev]);
      
      // Log the action
      await supabase.from('audit_logs').insert({
        user_id: user.id,
        action: 'compliance_assessment_created',
        resource_type: 'compliance_assessment',
        resource_id: data.id,
        details: { assessment_name: assessment.name }
      });

      return { data };
    } catch (err: any) {
      return { error: err.message };
    }
  };

  const updateAssessmentStatus = async (assessmentId: string, status: string, findings?: string) => {
    if (!user) return { error: 'User not authenticated' };

    try {
      const { data, error } = await supabase
        .from('compliance_assessments')
        .update({ 
          status, 
          findings_summary: findings,
          updated_at: new Date().toISOString()
        })
        .eq('id', assessmentId)
        .select()
        .single();

      if (error) throw error;
      
      setAssessments(prev => prev.map(a => a.id === assessmentId ? data : a));
      
      // Log the action
      await supabase.from('audit_logs').insert({
        user_id: user.id,
        action: 'compliance_assessment_updated',
        resource_type: 'compliance_assessment',
        resource_id: assessmentId,
        details: { new_status: status, findings }
      });

      return { data };
    } catch (err: any) {
      return { error: err.message };
    }
  };

  const getFrameworkCompliance = (frameworkId: string) => {
    const frameworkControls = controls.filter(c => c.framework_id === frameworkId);
    const totalControls = frameworkControls.length;
    
    if (totalControls === 0) return { score: 0, implemented: 0, total: 0 };
    
    // This would need to be enhanced with actual control assessment data
    const implementedControls = frameworkControls.filter(c => c.automation_possible).length;
    const score = Math.round((implementedControls / totalControls) * 100);
    
    return { score, implemented: implementedControls, total: totalControls };
  };

  return {
    frameworks,
    controls,
    assessments,
    loading,
    error,
    createFramework,
    createControl,
    createAssessment,
    updateAssessmentStatus,
    getFrameworkCompliance,
    refetch: fetchComplianceData
  };
};