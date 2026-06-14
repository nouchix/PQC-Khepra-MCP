import { supabase } from '@/integrations/supabase/client';

/**
 * Governed by NEXT_PUBLIC_ENABLE_TELEMETRY.
 * When false: UX analytics events and optional usage-tracking RPC calls are suppressed.
 * Security audit logs (threat events, auth events) are NOT governed by this flag —
 * those are mandatory compliance records and must always fire.
 */
export const TELEMETRY_ENABLED =
  process.env.NEXT_PUBLIC_ENABLE_TELEMETRY === 'true';

/**
 * Wraps supabase.rpc('log_user_action', ...) for OPTIONAL analytics events.
 * Returns silently when telemetry is disabled. Throws on RPC error when enabled.
 */
export async function logAnalyticsAction(
  action_type: string,
  resource_type: string,
  resource_id: string,
  details: Record<string, unknown>,
): Promise<void> {
  if (!TELEMETRY_ENABLED) return;

  const { error } = await supabase.rpc('log_user_action', {
    action_type,
    resource_type,
    resource_id,
    details,
  });

  if (error) {
    throw new Error(`Telemetry RPC failed [${action_type}]: ${error.message}`);
  }
}
