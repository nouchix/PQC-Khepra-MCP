import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

// ---------------------------------------------------------------------------
// KHEPRA License Generator — Stripe Webhook Handler
// Supabase Edge Function: supabase/functions/generate-license/index.ts
//
// Env vars required (set via `supabase secrets set`):
//   STRIPE_SECRET_KEY
//   STRIPE_WEBHOOK_SECRET
//   KHEPRA_SIGNING_KEY_B64   (base64-encoded ML-DSA-65 private key)
//   RESEND_API_KEY           (for license email delivery)
// ---------------------------------------------------------------------------

const STRIPE_SECRET_KEY     = Deno.env.get("STRIPE_SECRET_KEY")!;
const WEBHOOK_SECRET        = Deno.env.get("STRIPE_WEBHOOK_SECRET")!;
const SUPABASE_URL          = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_KEY  = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const RESEND_API_KEY        = Deno.env.get("RESEND_API_KEY")!;

// Tier mapping from Stripe product metadata or product ID
const TIER_MAP: Record<string, string> = {
  "prod_sovereign": "sovereign",
  "prod_pharaoh":   "pharaoh",
  // Add your actual Stripe product IDs here
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function randomHex(bytes: number): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => b.toString(16).padStart(2, "0"))
    .join("").toUpperCase().slice(0, bytes * 2);
}

function generateLicenseKey(): string {
  return `KHRPA-${randomHex(2)}-${randomHex(2)}-${randomHex(2)}-${randomHex(2)}`;
}

/**
 * Sign the license payload.
 * 
 * In production, use the ML-DSA-65 WASM module or call an internal
 * signing microservice. For now we use HMAC-SHA256 as a placeholder
 * until the WASM signing module is integrated.
 * 
 * TODO: Replace with actual ML-DSA-65 signature via:
 *   import { sign } from "./mldsa65.wasm.js"
 */
async function signPayload(payload: object, signingKeyB64: string): Promise<string> {
  const keyBytes = Uint8Array.from(atob(signingKeyB64), c => c.charCodeAt(0));
  const cryptoKey = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const data = new TextEncoder().encode(JSON.stringify(payload));
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, data);
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

async function sendLicenseEmail(
  to: string,
  licenseKey: string,
  tier: string,
  expiresAt: string,
  licenseFileContent: string
): Promise<void> {
  if (!RESEND_API_KEY) return; // skip if not configured

  await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: "licenses@nouchix.com",
      to: [to],
      subject: `Your KHEPRA ${tier.toUpperCase()} License — ${licenseKey}`,
      html: `
        <h2>KHEPRA MCP License Issued</h2>
        <p>Thank you for your purchase. Your license details:</p>
        <ul>
          <li><strong>License Key:</strong> ${licenseKey}</li>
          <li><strong>Tier:</strong> ${tier}</li>
          <li><strong>Expires:</strong> ${expiresAt}</li>
        </ul>
        <p>Save the attached <code>.adinkhepra</code> file and set its path via:</p>
        <pre>KHEPRA_LICENSE_PATH=/path/to/license.adinkhepra</pre>
        <p>Support: <a href="mailto:support@nouchix.com">support@nouchix.com</a></p>
      `,
      attachments: [
        {
          filename: `${licenseKey}.adinkhepra`,
          content: btoa(licenseFileContent),
        },
      ],
    }),
  });
}

// ---------------------------------------------------------------------------
// Stripe webhook verification (manual — no Stripe SDK in Deno edge)
// ---------------------------------------------------------------------------

async function verifyStripeSignature(
  body: string,
  sigHeader: string,
  secret: string
): Promise<boolean> {
  const parts = Object.fromEntries(
    sigHeader.split(",").map(p => p.split("=") as [string, string])
  );
  const timestamp = parts["t"];
  const signature = parts["v1"];
  if (!timestamp || !signature) return false;

  const payload = `${timestamp}.${body}`;
  const keyBytes = new TextEncoder().encode(secret);
  const msgBytes = new TextEncoder().encode(payload);

  const key = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const mac = await crypto.subtle.sign("HMAC", key, msgBytes);
  const expected = Array.from(new Uint8Array(mac))
    .map(b => b.toString(16).padStart(2, "0")).join("");

  return expected === signature;
}

// ---------------------------------------------------------------------------
// Main handler
// ---------------------------------------------------------------------------

Deno.serve(async (req: Request) => {
  if (req.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  const body = await req.text();
  const sigHeader = req.headers.get("stripe-signature") ?? "";

  if (!await verifyStripeSignature(body, sigHeader, WEBHOOK_SECRET)) {
    return new Response("Invalid signature", { status: 400 });
  }

  const event = JSON.parse(body);
  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);
  const signingKeyB64 = Deno.env.get("KHEPRA_SIGNING_KEY_B64") ?? "";

  try {
    switch (event.type) {

      // -----------------------------------------------------------------------
      case "checkout.session.completed":
      case "invoice.payment_succeeded": {
        const obj = event.data.object;

        // Resolve subscription (may be nested differently per event type)
        const subId: string = obj.subscription ?? obj.id;
        const customerId: string = obj.customer;
        const customerEmail: string = obj.customer_email ?? obj.customer_details?.email ?? "";

        // Fetch subscription for period end + product metadata
        const subResp = await fetch(
          `https://api.stripe.com/v1/subscriptions/${subId}`,
          { headers: { "Authorization": `Bearer ${STRIPE_SECRET_KEY}` } }
        );
        const sub = await subResp.json();
        const productId: string = sub.items?.data?.[0]?.price?.product ?? "";
        const tier = sub.metadata?.tier ?? TIER_MAP[productId] ?? "sovereign";
        const expiresAt = new Date(sub.current_period_end * 1000).toISOString();

        // Build and sign license payload
        const licenseKey = generateLicenseKey();
        const payload = {
          license_key:  licenseKey,
          tier,
          customer_id:  customerId,
          issued_at:    new Date().toISOString(),
          expires_at:   expiresAt,
          version:      "1.0",
          algorithm:    "ML-DSA-65",
        };
        const signature = await signPayload(payload, signingKeyB64);
        const licenseFile = JSON.stringify({ ...payload, signature }, null, 2);

        // Upsert license record
        const { error } = await supabase.from("licenses").upsert(
          {
            customer_id:       customerId,
            stripe_sub_id:     subId,
            stripe_product_id: productId,
            tier,
            license_key:       licenseKey,
            expires_at:        expiresAt,
            signed_payload:    btoa(licenseFile),
          },
          { onConflict: "stripe_sub_id" }
        );
        if (error) throw error;

        // Audit event
        await supabase.from("license_events").insert({
          license_id: (await supabase
            .from("licenses").select("id").eq("license_key", licenseKey).single()
          ).data?.id,
          event:    event.type === "checkout.session.completed" ? "issued" : "renewed",
          actor:    "stripe-webhook",
          metadata: { stripe_event_id: event.id, tier, expires_at: expiresAt },
        });

        // Email license to customer
        await sendLicenseEmail(customerEmail, licenseKey, tier, expiresAt, licenseFile);
        break;
      }

      // -----------------------------------------------------------------------
      case "customer.subscription.deleted": {
        const sub = event.data.object;
        const { error } = await supabase.from("licenses")
          .update({ revoked_at: new Date().toISOString(), revoke_reason: "subscription_cancelled" })
          .eq("stripe_sub_id", sub.id);
        if (error) throw error;
        break;
      }

      // -----------------------------------------------------------------------
      case "customer.subscription.updated": {
        const sub = event.data.object;
        const productId = sub.items?.data?.[0]?.price?.product ?? "";
        const newTier = sub.metadata?.tier ?? TIER_MAP[productId] ?? "sovereign";
        const expiresAt = new Date(sub.current_period_end * 1000).toISOString();
        await supabase.from("licenses")
          .update({ tier: newTier, expires_at: expiresAt })
          .eq("stripe_sub_id", sub.id);
        break;
      }

      default:
        // Ignore unhandled event types
        break;
    }
  } catch (err) {
    console.error("License generation error:", err);
    return new Response(JSON.stringify({ error: String(err) }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }

  return new Response("OK", { status: 200 });
});
