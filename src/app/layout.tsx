import type { Metadata } from "next";
import Providers from "@/components/Providers";
import "../index.css";

export const metadata: Metadata = {
  title: "SouHimBou AI — Agentic Security Operations Center",
  description: "The AI Security Architect for your Agentic SOC. Monitor, detect, investigate, and respond to threats across AI agent deployments. PQC-signed attestation included.",
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
