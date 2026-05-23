"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { supabase } from "@/integrations/supabase/client";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      if (!session) router.replace("/Auth?next=/dashboard");
      else setChecking(false);
    });
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_, session) => {
      if (!session) router.replace("/Auth?next=/dashboard");
    });
    return () => subscription.unsubscribe();
  }, [router]);

  if (checking) {
    return (
      <div className="min-h-screen bg-zinc-950 flex items-center justify-center">
        <div className="w-6 h-6 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <header className="border-b border-zinc-800 bg-zinc-950/80 backdrop-blur-lg sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <a href="/" className="flex items-center gap-2">
              <span className="text-sm font-black uppercase tracking-tight text-white">
                SouHimBou <span className="text-cyan-400">AI</span>
              </span>
              <span className="text-[10px] text-zinc-500 uppercase tracking-widest hidden sm:block">
                PQC-MCP Server
              </span>
            </a>
            <span className="text-zinc-700">|</span>
            <span className="text-xs text-zinc-400 font-medium">MCP Dashboard</span>
          </div>
          <div className="flex items-center gap-3">
            <a
              href="/mcp-quickstart"
              className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
            >
              Quickstart
            </a>
            <button
              onClick={() => supabase.auth.signOut()}
              className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
            >
              Sign out
            </button>
          </div>
        </div>
      </header>
      <main className="max-w-7xl mx-auto px-6 py-8">
        {children}
      </main>
    </div>
  );
}
