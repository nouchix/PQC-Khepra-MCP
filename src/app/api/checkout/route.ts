import { NextRequest, NextResponse } from 'next/server';

const STRIPE_API = 'https://api.stripe.com/v1';

/**
 * POST /api/checkout
 * Creates a Stripe Checkout Session for the ASAF Certify plan ($99/mo).
 * Uses Stripe REST API directly — no SDK dependency required.
 *
 * Required env vars:
 *   STRIPE_SECRET_KEY     — sk_live_... or sk_test_...
 *   STRIPE_PRICE_ID       — price_... (created in Stripe Dashboard)
 *   NEXT_PUBLIC_APP_URL   — https://app.nouchix.com (used for redirect URLs)
 */
export async function POST(req: NextRequest) {
  const stripeKey = process.env.STRIPE_SECRET_KEY;
  const priceId = process.env.STRIPE_PRICE_ID;
  const appUrl = process.env.NEXT_PUBLIC_APP_URL || 'https://app.nouchix.com';

  if (!stripeKey || !priceId) {
    return NextResponse.json(
      { error: 'Stripe is not configured. Set STRIPE_SECRET_KEY and STRIPE_PRICE_ID.' },
      { status: 500 }
    );
  }

  const body = await req.json().catch(() => ({}));
  const email = body.email as string | undefined;

  // Build form-encoded body for Stripe API
  const params = new URLSearchParams({
    mode: 'subscription',
    'line_items[0][price]': priceId,
    'line_items[0][quantity]': '1',
    'success_url': `${appUrl}/onboarding?stripe_session_id={CHECKOUT_SESSION_ID}&plan=certify`,
    'cancel_url': `${appUrl}/billing?cancelled=1`,
    'allow_promotion_codes': 'true',
    'billing_address_collection': 'auto',
  });

  if (email) {
    params.set('customer_email', email);
  }

  const response = await fetch(`${STRIPE_API}/checkout/sessions`, {
    method: 'POST',
    headers: {
      'Authorization': `Basic ${Buffer.from(`${stripeKey}:`).toString('base64')}`,
      'Content-Type': 'application/x-www-form-urlencoded',
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
