import type { Metadata } from "next";
import Providers from "@/components/Providers";
import "../index.css";

export const metadata: Metadata = {
  title: "ASAF by NouchiX — Agentic Security Attestation Framework",
  description: "Scan, audit, and certify your AI agent deployments. Get your ADINKHEPRA badge — the enterprise security standard for agentic AI.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <meta charSet="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      </head>
      <body className="min-h-screen bg-background antialiased">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
