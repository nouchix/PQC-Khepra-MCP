import { useEffect, ReactNode } from 'react';

interface SecurityHeadersProps {
  children: ReactNode;
}

// HTTP security headers (CSP, X-Frame-Options, HSTS, COEP, COOP, Permissions-Policy)
// are set at the HTTP response level in next.config.mjs — NOT here.
// Browsers ignore frame-ancestors, report-uri, and X-Frame-Options in <meta> tags per spec.
// This component only handles runtime JS-level hardening.
const SecurityHeaders = ({ children }: SecurityHeadersProps) => {
  useEffect(() => {
    // Disable autocomplete on password forms
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
      if (form.querySelector('input[type="password"]')) {
        form.setAttribute('autocomplete', 'off');
      }
    });

    // Redact sensitive strings from console output in production
    if (process.env.NODE_ENV === 'production') {
      const isSensitive = (arg: unknown) =>
        typeof arg === 'string' &&
        (arg.includes('password') || arg.includes('token') || arg.includes('key'));

      const redact = (...args: unknown[]) => args.map(a => isSensitive(a) ? '[REDACTED]' : a);

      const origLog   = console.log.bind(console);
      const origWarn  = console.warn.bind(console);
      const origError = console.error.bind(console);

      console.log   = (...args) => origLog(...redact(...args));
      console.warn  = (...args) => origWarn(...redact(...args));
      console.error = (...args) => origError(...redact(...args));
    }
  }, []);

  return <>{children}</>;
};

export default SecurityHeaders;
