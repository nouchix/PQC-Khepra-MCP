import { NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';

/**
 * POST /api/compliance/send-report
 *
 * Triggers CMMC scorecard email delivery via the Supabase Edge Function
 * (compliance-report) which uses Autosend for email delivery.
 *
 * Body: { recipient_email, recipient_name?, attestation_id? }
 *
 * Flow:
 *   Vercel → Fly.io (get scorecard) → Supabase Edge Fn (send email via Autosend)
 */

const INTERNAL_API = process.env.ASAF_INTERNAL_API_URL || 'http://172.19.0.1:45444';
const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL || '';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { recipient_email, recipient_name, attestation_id } = body;

    if (!recipient_email) {
      return NextResponse.json({ error: 'recipient_email required' }, { status: 400 });
    }

    // 1. Fetch the live scorecard from the Go API
    const authHeader = request.headers.get('Authorization') || '';
    let scorecard = null;

    try {
      const scorecardRes = await fetch(`${INTERNAL_API}/api/v1/compliance/cmmc-scorecard`, {
        headers: { 'Authorization': authHeader },
        signal: AbortSignal.timeout(30000),
      });
      if (scorecardRes.ok) {
        scorecard = await scorecardRes.json();
      }
    } catch {
      // Scorecard unavailable — send evidence package email instead
    }

    // 2. Invoke the Supabase Edge Function for email delivery
    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

    if (scorecard) {
      // Send full scorecard report
      const { data, error } = await supabase.functions.invoke('compliance-report', {
        body: {
          action: 'send_scorecard',
          data: {
            recipient_email,
            recipient_name: recipient_name || 'Team',
            scorecard,
          },
        },
      });

      if (error) {
        return NextResponse.json({ error: error.message }, { status: 502 });
      }

      return NextResponse.json({
        success: true,
        type: 'scorecard',
        message_id: data?.message_id,
        sprs_score: scorecard.sprs_score,
      });
    }

    if (attestation_id) {
      // Send evidence package notification
      const { data, error } = await supabase.functions.invoke('compliance-report', {
        body: {
          action: 'send_evidence_package',
          data: {
            recipient_email,
            recipient_name: recipient_name || 'Team',
            attestation_id,
            verify_url: `https://adinkhepra.com/verify/${attestation_id}`,
          },
        },
      });

      if (error) {
        return NextResponse.json({ error: error.message }, { status: 502 });
      }

      return NextResponse.json({
        success: true,
        type: 'evidence_package',
        message_id: data?.message_id,
      });
    }

    return NextResponse.json(
      { error: 'No scorecard available and no attestation_id provided' },
      { status: 422 }
    );
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
