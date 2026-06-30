import { NextRequest, NextResponse } from 'next/server';

const STRIPE_API = 'https://api.stripe.com/v1';

/**
 * POST /api/checkout
 * Creates a Stripe Checkout Session for the ADINKHEPRA Certify plan ($99/mo).
 *
 * Required env vars:
 *   STRIPE_SECRET_KEY         — sk_live_... or sk_test_...
 *
 * Optional env vars:
 *   STRIPE_PRICE_ID           — A *recurring* price_... ID. If set AND the
 *                               price is recurring, it takes precedence.
 *                               IMPORTANT: must be a subscription price —
 *                               one-time prices will cause a Stripe error.
 *   NEXT_PUBLIC_APP_URL       — https://www.souhimbou.ai
 *
 * NOTE: We default to inline price_data (no pre-created price needed) so
 * checkout always works out of the box without Stripe dashboard setup.
 */
export async function POST(req: NextRequest) {
  const stripeKey = process.env.STRIPE_SECRET_KEY;
  const appUrl    = process.env.NEXT_PUBLIC_APP_URL || 'https://www.souhimbou.ai';

  if (!stripeKey) {
    return NextResponse.json(
      { error: 'Stripe is not configured. Please contact support@souhimbou.ai' },
      { status: 500 }
    );
  }

  const body  = await req.json().catch(() => ({}));
  const email = typeof body.email === 'string' ? body.email.trim() : undefined;

  // Build form-encoded body for Stripe API
  const params = new URLSearchParams({
    mode: 'subscription',
    'success_url': `${appUrl}/onboarding?certified=1&session_id={CHECKOUT_SESSION_ID}`,
    'cancel_url':  `${appUrl}/onboarding?cancelled=1`,
    'allow_promotion_codes':      'true',
    'billing_address_collection': 'auto',
  });

  // Inline price_data — always creates a $99/mo recurring subscription price
  params.set('line_items[0][price_data][currency]',                  'usd');
  params.set('line_items[0][price_data][product_data][name]',        'ADINKHEPRA Certification');
  params.set('line_items[0][price_data][product_data][description]', 'ML-DSA-65 signed certification badge · CMMC/STIG compliance evidence · Renews monthly. Cancel anytime.');
  params.set('line_items[0][price_data][unit_amount]',               '9900');
  params.set('line_items[0][price_data][recurring][interval]',       'month');
  params.set('line_items[0][quantity]',                              '1');

  if (email) {
    params.set('customer_email', email);
  }

  const response = await fetch(`${STRIPE_API}/checkout/sessions`, {
    method: 'POST',
    headers: {
      'Authorization': `Basic ${Buffer.from(`${stripeKey}:`).toString('base64')}`,
      'Content-Type':  'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });

  const responseData = await response.json().catch(() => ({}));

  if (!response.ok) {
    // Surface the exact Stripe error to the toast for immediate diagnosis
    const msg = (responseData as any)?.error?.message
      || `Stripe error ${response.status}`;
    return NextResponse.json({ error: msg }, { status: response.status });
  }

  return NextResponse.json({ url: (responseData as any).url });
}
