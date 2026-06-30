import { NextRequest, NextResponse } from 'next/server';

const STRIPE_API = 'https://api.stripe.com/v1';

/**
 * POST /api/checkout
 *
 * Plan-aware Stripe Checkout Session creator.
 * Accepts { plan, email } — routes to the correct price ID and mode.
 *
 * Canonical price IDs (SecRed Knowledge Inc. — souhimbou.ai):
 *   certify         → price_1TiVvxDqGyad2D3VlUm3ba6s  $99     one-time  (mode: payment)
 *   starter         → price_1TiVXPDqGyad2D3VSpr7L05X  $299/mo recurring (mode: subscription)
 *   professional    → price_1TiVXoDqGyad2D3V5AZQ0EiW  $999/mo recurring (mode: subscription)
 *   enterprise      → price_1TiVvyDqGyad2D3V4mszc5v5  $500/mo recurring (mode: subscription)
 *   sovereign       → price_1TiVXoDqGyad2D3Vr78bgbTI  $2999/mo recurring (mode: subscription)
 *   diagnostic      → price_1TiVXpDqGyad2D3VXMnYnrZP  $1500   one-time  (mode: payment)
 *   advisory        → price_1TiVXqDqGyad2D3VQizyv9o7  $5000   one-time  (mode: payment)
 *   deadline_sprint → price_1TiVw1DqGyad2D3VTs0ewSp0  $15000  one-time  (mode: payment)
 *
 * Required env vars (Vercel):
 *   STRIPE_SECRET_KEY
 *   STRIPE_PRICE_CERTIFY
 *   STRIPE_PRICE_STARTER
 *   STRIPE_PRICE_PROFESSIONAL
 *   STRIPE_PRICE_ENTERPRISE
 *   STRIPE_PRICE_SOVEREIGN
 *   STRIPE_PRICE_DIAGNOSTIC
 *   STRIPE_PRICE_ADVISORY
 *   STRIPE_PRICE_DEADLINE_SPRINT
 */

// Price catalog — maps plan slug → { priceId env var, mode, label }
type StripePlan = {
  envKey: string;
  fallbackPriceId: string;         // canonical ID — only used if env var not set
  mode: 'payment' | 'subscription';
  label: string;
  successPath: string;             // used when user was already logged in
  anonSuccessPath: string;         // used when user paid anonymously
};

const PLANS: Record<string, StripePlan> = {
  certify: {
    envKey: 'STRIPE_PRICE_CERTIFY',
    fallbackPriceId: 'price_1TiVvxDqGyad2D3VlUm3ba6s',
    mode: 'payment',
    label: 'ADINKHEPRA Certify',
    successPath:     '/onboarding?certified=1&session_id={CHECKOUT_SESSION_ID}',
    anonSuccessPath: '/auth?registered=1&plan=certify&session_id={CHECKOUT_SESSION_ID}',
  },
  starter: {
    envKey: 'STRIPE_PRICE_STARTER',
    fallbackPriceId: 'price_1TiVXPDqGyad2D3VSpr7L05X',
    mode: 'subscription',
    label: 'SouHimBou AI Starter',
    successPath:     '/dashboard?plan=starter&session_id={CHECKOUT_SESSION_ID}',
    anonSuccessPath: '/auth?registered=1&plan=starter&session_id={CHECKOUT_SESSION_ID}',
  },
  professional: {
    envKey: 'STRIPE_PRICE_PROFESSIONAL',
    fallbackPriceId: 'price_1TiVXoDqGyad2D3V5AZQ0EiW',
    mode: 'subscription',
    label: 'SouHimBou AI Professional',
    successPath:     '/dashboard?plan=professional&session_id={CHECKOUT_SESSION_ID}',
    anonSuccessPath: '/auth?registered=1&plan=professional&session_id={CHECKOUT_SESSION_ID}',
  },
  enterprise: {
    envKey: 'STRIPE_PRICE_ENTERPRISE',
    fallbackPriceId: 'price_1TiVvyDqGyad2D3V4mszc5v5',
    mode: 'subscription',
    label: 'SouHimBou AI Enterprise',
    successPath:     '/dashboard?plan=enterprise&session_id={CHECKOUT_SESSION_ID}',
    anonSuccessPath: '/auth?registered=1&plan=enterprise&session_id={CHECKOUT_SESSION_ID}',
  },
  sovereign: {
    envKey: 'STRIPE_PRICE_SOVEREIGN',
    fallbackPriceId: 'price_1TiVXoDqGyad2D3Vr78bgbTI',
    mode: 'subscription',
    label: 'ADINKHEPRA ASAF Sovereign',
    successPath:     '/dashboard?plan=sovereign&session_id={CHECKOUT_SESSION_ID}',
    anonSuccessPath: '/auth?registered=1&plan=sovereign&session_id={CHECKOUT_SESSION_ID}',
  },
  diagnostic: {
    envKey: 'STRIPE_PRICE_DIAGNOSTIC',
    fallbackPriceId: 'price_1TiVXpDqGyad2D3VXMnYnrZP',
    mode: 'payment',
    label: 'Diagnostic Assessment',
    successPath:     '/dashboard?plan=diagnostic&session_id={CHECKOUT_SESSION_ID}',
    anonSuccessPath: '/auth?registered=1&plan=diagnostic&session_id={CHECKOUT_SESSION_ID}',
  },
  advisory: {
    envKey: 'STRIPE_PRICE_ADVISORY',
    fallbackPriceId: 'price_1TiVXqDqGyad2D3VQizyv9o7',
    mode: 'payment',
    label: 'Advisory Package',
    successPath:     '/dashboard?plan=advisory&session_id={CHECKOUT_SESSION_ID}',
    anonSuccessPath: '/auth?registered=1&plan=advisory&session_id={CHECKOUT_SESSION_ID}',
  },
  deadline_sprint: {
    envKey: 'STRIPE_PRICE_DEADLINE_SPRINT',
    fallbackPriceId: 'price_1TiVw1DqGyad2D3VTs0ewSp0',
    mode: 'payment',
    label: 'Deadline Sprint',
    successPath:     '/dashboard?plan=deadline_sprint&session_id={CHECKOUT_SESSION_ID}',
    anonSuccessPath: '/auth?registered=1&plan=deadline_sprint&session_id={CHECKOUT_SESSION_ID}',
  },
};

export async function POST(req: NextRequest) {
  const stripeKey = process.env.STRIPE_SECRET_KEY;
  const appUrl    = process.env.NEXT_PUBLIC_APP_URL || 'https://souhimbou.ai';

  if (!stripeKey) {
    return NextResponse.json(
      { error: 'Stripe is not configured. Contact support@souhimbou.ai' },
      { status: 500 }
    );
  }

  const body     = await req.json().catch(() => ({}));
  const email    = typeof body.email === 'string' ? body.email.trim() : undefined;
  const planKey  = (typeof body.plan === 'string' ? body.plan : 'certify').toLowerCase();
  // loggedIn = true  → user already has a session → send to /dashboard after payment
  // loggedIn = false → anonymous checkout → send to /auth?registered=1 after payment
  const loggedIn = body.loggedIn === true;

  const plan = PLANS[planKey] ?? PLANS.certify;

  // Select the correct success path based on auth state
  const rawSuccessPath = loggedIn ? plan.successPath : plan.anonSuccessPath;

  // Resolve price ID: prefer env var, fall back to canonical ID hardcoded above
  const priceId = process.env[plan.envKey] || plan.fallbackPriceId;

  const params = new URLSearchParams({
    mode: plan.mode,
    'success_url': `${appUrl}${rawSuccessPath}`,
    'cancel_url':  `${appUrl}/billing?cancelled=1`,
    'allow_promotion_codes':      'true',
    'billing_address_collection': 'auto',
  });

  params.set('line_items[0][price]',    priceId);
  params.set('line_items[0][quantity]', '1');

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
    const msg = (responseData as any)?.error?.message || `Stripe error ${response.status}`;
    console.error(`[checkout] plan=${planKey} price=${priceId} mode=${plan.mode} error:`, msg);
    return NextResponse.json({ error: msg }, { status: response.status });
  }

  return NextResponse.json({ url: (responseData as any).url });
}
