"use client";
/**
 * Client-side provider tree — extracted from the old Vite App.tsx so it can
 * be mounted once in src/app/layout.tsx without breaking server components.
 */
import { Suspense } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AuthProvider, useAuth } from "@/hooks/useAuth";
import { OrganizationProvider } from "@/components/OrganizationProvider";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import ErrorBoundary from "@/components/ErrorBoundary";
import SecurityHeaders from "@/components/security/SecurityHeaders";
import CommandPalette from "@/components/CommandPalette";
import NLChatPanel from "@/components/NLChatPanel";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

function AuthAwareCommandPalette() {
  const { user } = useAuth();
  return <CommandPalette isAuthenticated={!!user} />;
}

export default function Providers({ children }: { children: React.ReactNode }) {
  return (
    // Suspense is required by Next.js for useSearchParams used inside the tree
    <Suspense>
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <SecurityHeaders>
            <TooltipProvider>
              <OrganizationProvider>
                <ErrorBoundary>
                  <AuthAwareCommandPalette />
                  <Toaster />
                  <Sonner />
                  {children}
                  <NLChatPanel />
                </ErrorBoundary>
              </OrganizationProvider>
            </TooltipProvider>
          </SecurityHeaders>
        </AuthProvider>
      </QueryClientProvider>
    </Suspense>
  );
}
