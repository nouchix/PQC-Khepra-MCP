import { NextRequest, NextResponse } from 'next/server';

const STRIPE_API = 'https://api.stripe.com/v1';

/**
 * POST /api/checkout
 * Creates a Stripe Checkout Session for the ASAF Certify plan ($99/mo).
 * Uses Stripe REST API directly — no SDK dependency required.
 *
 * Required env vars:
 *   STRIPE_SECRET_KEY     — sk_live_... or sk_test_...
 *
 * Optional env vars:
 *   STRIPE_PRICE_ID       — price_... (pre-created recurring subscription price)
 *                           If not set, uses inline price_data ($99/mo)
 *   NEXT_PUBLIC_APP_URL   — https://www.souhimbou.ai (used for redirect URLs)
 */
export async function POST(req: NextRequest) {
  const stripeKey = process.env.STRIPE_SECRET_KEY;
  const priceId   = process.env.STRIPE_PRICE_ID;
  const appUrl    = process.env.NEXT_PUBLIC_APP_URL || 'https://www.souhimbou.ai';

  if (!stripeKey) {
    return NextResponse.json(
      { error: 'Stripe is not configured on this server. Please contact support@souhimbou.ai' },
      { status: 500 }
    );
  }

  const body  = await req.json().catch(() => ({}));
  const email = body.email as string | undefined;

  // Build form-encoded body for Stripe API
  const params = new URLSearchParams({
    mode: 'subscription',
    'success_url': `${appUrl}/onboarding?certified=1&session_id={CHECKOUT_SESSION_ID}`,
    'cancel_url':  `${appUrl}/onboarding?cancelled=1`,
    'allow_promotion_codes':      'true',
    'billing_address_collection': 'auto',
  });

  if (priceId) {
    // Use pre-created price (preferred — set STRIPE_PRICE_ID in Vercel env)
    params.set('line_items[0][price]',    priceId);
    params.set('line_items[0][quantity]', '1');
  } else {
    // Inline price_data fallback — creates price on the fly, no pre-setup needed
    params.set('line_items[0][price_data][currency]',                  'usd');
    params.set('line_items[0][price_data][product_data][name]',        'ADINKHEPRA Certification');
    params.set('line_items[0][price_data][product_data][description]', 'ML-DSA-65 signed certification badge. Renews automatically. Cancel anytime.');
    params.set('line_items[0][price_data][unit_amount]',               '9900'); // $99.00
    params.set('line_items[0][price_data][recurring][interval]',       'month');
    params.set('line_items[0][quantity]',                              '1');
  }

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

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    return NextResponse.json(
      { error: err.error?.message || 'Failed to create checkout session' },
      { status: response.status }
    );
  }

  const session = await response.json();
  return NextResponse.json({ url: session.url });
}
