/**
 * Next.js Pages Router custom App.
 *
 * All files under src/pages/ are React SPA view components that run
 * exclusively in the browser (they depend on BrowserRouter, AuthProvider,
 * OrganizationProvider, localStorage, etc.). Server-side rendering of any
 * individual page would fail because the full client provider tree is absent.
 *
 * The application is served through the App Router catch-all
 * (src/app/[...slug]/page.tsx) which already wraps the entire SPA with
 * `next/dynamic` and `ssr: false`. The Pages Router entries are only here
 * because Next.js auto-discovers .tsx files in src/pages/.
 *
 * This _app.tsx disables SSR for every Pages Router page with a single
 * dynamic(ssr: false) wrapper, matching the App Router behaviour.
 */
import type { AppProps } from 'next/app';
import dynamic from 'next/dynamic';

// PageShell renders the actual page component. It is imported dynamically
// with ssr: false so Next.js never attempts server-side rendering for any
// Pages Router route.
const PageShell = dynamic(
  () => Promise.resolve(function Shell({ Component, pageProps }: AppProps) {
    return <Component {...pageProps} />;
  }),
  { ssr: false },
);

export default function MyApp(props: AppProps) {
  return <PageShell {...props} />;
}
