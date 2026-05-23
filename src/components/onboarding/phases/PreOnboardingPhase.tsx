import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { Button } from '@/components/ui/button';
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';
import { useOrganizationOnboarding } from '@/hooks/useOrganizationOnboarding';
import { Checkbox } from '@/components/ui/checkbox';

const intakeSchema = z.object({
  primary_contact_name: z.string().min(2).max(100),
  primary_contact_email: z.string().email().max(255),
  primary_contact_phone: z.string().min(10).max(20),
  organization_size: z.enum(['1-50', '51-200', '201-500', '501-1000', '1000+']),
  compliance_goals: z.array(z.string()).min(1),
  current_infrastructure: z.string().max(1000),
  cloud_platforms: z.array(z.string()),
  cmmc_level_target: z.enum(['1', '2', '3']),
  timeline_expectations: z.string().max(500),
  special_requirements: z.string().max(1000).optional(),
});

interface PreOnboardingPhaseProps {
  organizationId: string;
  onboardingId: string;
}

export function PreOnboardingPhase({ organizationId }: PreOnboardingPhaseProps) {
  const { saveIntakeData } = useOrganizationOnboarding(organizationId);
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);

  const form = useForm<z.infer<typeof intakeSchema>>({
    resolver: zodResolver(intakeSchema),
    defaultValues: {
      compliance_goals: [],
      cloud_platforms: [],
      cmmc_level_target: '1',
    },
  });

  const onSubmit = async (values: z.infer<typeof intakeSchema>) => {
    setLoading(true);
    try {
      await saveIntakeData(values);
      toast({
        title: 'Intake Complete',
        description: 'Pre-onboarding information saved successfully',
      });
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to save intake data',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  const complianceGoals = [
    { id: 'cmmc', label: 'CMMC Certification' },
    { id: 'fedramp', label: 'FedRAMP Authorization' },
    { id: 'ato', label: 'Authority to Operate (ATO)' },
    { id: 'continuous', label: 'Continuous Compliance' },
    { id: 'audit', label: 'Audit Readiness' },
  ];

  const cloudPlatforms = [
    { id: 'aws', label: 'Amazon Web Services (AWS)' },
    { id: 'azure', label: 'Microsoft Azure' },
    { id: 'gcp', label: 'Google Cloud Platform' },
    { id: 'on-premise', label: 'On-Premise' },
    { id: 'hybrid', label: 'Hybrid Cloud' },
  ];

  return (
    <div className="space-y-6">
      <div className="rounded-lg bg-primary/10 p-4 border border-primary/20">
        <h3 className="font-semibold mb-2">What to Expect</h3>
        <ul className="space-y-2 text-sm">
          <li>✓ Complete intake questionnaire (10 minutes)</li>
          <li>✓ Assign onboarding and technical leads</li>
          <li>✓ Clarify roles and establish milestones</li>
          <li>✓ Receive welcome kit and documentation access</li>
        </ul>
      </div>

      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <FormField
              control={form.control}
              name="primary_contact_name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Primary Contact Name *</FormLabel>
                  <FormControl>
                    <Input placeholder="John Doe" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="primary_contact_email"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Primary Contact Email *</FormLabel>
                  <FormControl>
                    <Input type="email" placeholder="john@company.com" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <FormField
              control={form.control}
              name="primary_contact_phone"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Phone Number *</FormLabel>
                  <FormControl>
                    <Input placeholder="+1 (555) 123-4567" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="organization_size"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Organization Size *</FormLabel>
                  <Select onValueChange={field.onChange} defaultValue={field.value}>
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder="Select size" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="1-50">1-50 employees</SelectItem>
                      <SelectItem value="51-200">51-200 employees</SelectItem>
                      <SelectItem value="201-500">201-500 employees</SelectItem>
                      <SelectItem value="501-1000">501-1000 employees</SelectItem>
                      <SelectItem value="1000+">1000+ employees</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>

          <FormField
            control={form.control}
            name="compliance_goals"
            render={() => (
              <FormItem>
                <FormLabel>Compliance Goals *</FormLabel>
                <FormDescription>Select all that apply</FormDescription>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-2">
                  {complianceGoals.map((goal) => (
                    <FormField
                      key={goal.id}
                      control={form.control}
                      name="compliance_goals"
                      render={({ field }) => (
                        <FormItem className="flex items-center space-x-3 space-y-0">
                          <FormControl>
                            <Checkbox
                              checked={field.value?.includes(goal.id)}
                              onCheckedChange={(checked) => {
                                const updated = checked
                                  ? [...field.value, goal.id]
                                  : field.value.filter((v) => v !== goal.id);
                                field.onChange(updated);
                              }}
                            />
                          </FormControl>
                          <FormLabel className="font-normal cursor-pointer">
                            {goal.label}
                          </FormLabel>
                        </FormItem>
                      )}
                    />
                  ))}
                </div>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="cloud_platforms"
            render={() => (
              <FormItem>
                <FormLabel>Cloud Platforms *</FormLabel>
                <FormDescription>Select all platforms in use</FormDescription>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-2">
                  {cloudPlatforms.map((platform) => (
                    <FormField
                      key={platform.id}
                      control={form.control}
                      name="cloud_platforms"
                      render={({ field }) => (
                        <FormItem className="flex items-center space-x-3 space-y-0">
                          <FormControl>
                            <Checkbox
                              checked={field.value?.includes(platform.id)}
                              onCheckedChange={(checked) => {
                                const updated = checked
                                  ? [...field.value, platform.id]
                                  : field.value.filter((v) => v !== platform.id);
                                field.onChange(updated);
                              }}
                            />
                          </FormControl>
                          <FormLabel className="font-normal cursor-pointer">
                            {platform.label}
                          </FormLabel>
                        </FormItem>
                      )}
                    />
                  ))}
                </div>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="cmmc_level_target"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Target CMMC Level *</FormLabel>
                <Select onValueChange={field.onChange} defaultValue={field.value}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    <SelectItem value="1">Level 1 - Foundational</SelectItem>
                    <SelectItem value="2">Level 2 - Advanced</SelectItem>
                    <SelectItem value="3">Level 3 - Expert</SelectItem>
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="current_infrastructure"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Current Infrastructure Overview *</FormLabel>
                <FormControl>
                  <Textarea
                    placeholder="Describe your current IT infrastructure, number of assets, network topology, etc."
                    className="min-h-[100px]"
                    {...field}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="timeline_expectations"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Timeline Expectations *</FormLabel>
                <FormControl>
                  <Textarea
                    placeholder="When do you need to achieve compliance? Any critical deadlines?"
                    {...field}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="special_requirements"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Special Requirements (Optional)</FormLabel>
                <FormControl>
                  <Textarea
                    placeholder="Any special requirements, concerns, or questions?"
                    {...field}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <Button type="submit" disabled={loading} className="w-full">
            {loading ? 'Saving...' : 'Save & Continue'}
          </Button>
        </form>
      </Form>
    </div>
  );
}
