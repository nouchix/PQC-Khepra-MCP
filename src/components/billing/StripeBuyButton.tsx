import React, { useEffect } from "react";

interface StripeBuyButtonProps {
  buyButtonId?: string;
  publishableKey?: string;
}

export function StripeBuyButton({
  buyButtonId = "buy_btn_1UHe6rDqGyad2D3VM7ukMyBG",
  publishableKey = "pk_live_51OPq4hDqGyad2D3VpC986VD3Jg9pOuv6tLymZByVMEOw9HxIRVY1frkcTFHqQL66q9aymxX0Sd3vYl2uN3viXtiq00oAzUrsVE",
}: StripeBuyButtonProps) {
  useEffect(() => {
    const scriptId = "stripe-buy-button-script";
    if (!document.getElementById(scriptId)) {
      const script = document.createElement("script");
      script.id = scriptId;
      script.src = "https://js.stripe.com/v3/buy-button.js";
      script.async = true;
      document.body.appendChild(script);
    }
  }, []);

  return React.createElement("stripe-buy-button", {
    "buy-button-id": buyButtonId,
    "publishable-key": publishableKey,
  });
}

export default StripeBuyButton;
