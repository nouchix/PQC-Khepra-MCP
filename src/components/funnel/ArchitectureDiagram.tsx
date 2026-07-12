"use client";
import { Shield, Server, Lock, Database, ArrowRight, Activity, Globe } from "lucide-react";

export const ArchitectureDiagram = () => {
  return (
    <div className="w-full py-12">
      <div className="text-center mb-10 space-y-3">
        <h2 className="text-3xl font-bold text-white">Sovereign Architecture: The PQC Edge</h2>
        <p className="text-gray-400 max-w-2xl mx-auto">
          Standard TLS for public access. Encapsulated Military-Grade Post-Quantum Cryptography for the internal agentic network.
        </p>
      </div>
      
      <div className="max-w-5xl mx-auto bg-slate-900/50 border border-slate-800 rounded-3xl p-8 backdrop-blur-sm relative overflow-hidden">
        {/* Background Gradients */}
        <div className="absolute top-0 left-0 w-full h-full pointer-events-none opacity-20">
          <div className="absolute top-[20%] left-[10%] w-64 h-64 bg-cyan-500 rounded-full blur-[100px]"></div>
          <div className="absolute bottom-[20%] right-[10%] w-64 h-64 bg-purple-600 rounded-full blur-[100px]"></div>
        </div>

        <div className="relative z-10 flex flex-col md:flex-row items-stretch justify-between gap-6">
          
          {/* Column 1: Public Edge */}
          <div className="flex-1 flex flex-col items-center justify-center p-6 bg-slate-800/40 border border-slate-700/50 rounded-2xl relative">
            <Globe className="w-10 h-10 text-blue-400 mb-4" />
            <h3 className="font-bold text-white text-lg">Public Internet</h3>
            <p className="text-xs text-center text-gray-400 mt-2">Claude Web / Standard Client</p>
            
            <div className="w-0.5 h-10 bg-gradient-to-b from-blue-500/50 to-orange-500/50 my-4"></div>
            
            <Server className="w-10 h-10 text-orange-400 mb-4" />
            <h3 className="font-bold text-white text-lg">Public Edge</h3>
            <p className="text-xs text-center text-gray-400 mt-2">
              <span className="text-orange-300 font-semibold">Caddy Reverse Proxy</span><br/>
              TLS Termination (ECDSA P-384)
            </p>
          </div>

          <div className="hidden md:flex flex-col justify-center items-center">
            <ArrowRight className="w-8 h-8 text-slate-500 animate-pulse" />
          </div>

          {/* Column 2: PQC Edge */}
          <div className="flex-1 flex flex-col items-center justify-center p-6 bg-purple-900/20 border border-purple-500/30 rounded-2xl relative shadow-[0_0_30px_rgba(147,51,234,0.1)]">
            <div className="absolute -top-3 px-3 py-1 bg-purple-900/80 border border-purple-500/50 rounded-full text-[10px] font-bold text-purple-300 tracking-wider">
              SOVEREIGN BOUNDARY
            </div>
            
            <Shield className="w-12 h-12 text-purple-400 mb-4" />
            <h3 className="font-bold text-white text-xl text-center">SEKHEM Gateway<br/>& PQC-WAF</h3>
            <p className="text-xs text-center text-gray-300 mt-3 leading-relaxed">
              Intercepts payload for SSRF & prompt injection. Acts as Blackhole-VPN.
            </p>
            
            <div className="w-full flex items-center justify-center gap-2 mt-4 pt-4 border-t border-purple-500/20">
              <Activity className="w-4 h-4 text-pink-400" />
              <span className="text-xs text-pink-300 font-medium">KASA Guardian (Anomaly Detection)</span>
            </div>
          </div>

          <div className="hidden md:flex flex-col justify-center items-center">
            <ArrowRight className="w-8 h-8 text-slate-500 animate-pulse" />
          </div>

          {/* Column 3: Internal Services */}
          <div className="flex-1 flex flex-col gap-4">
            <div className="p-5 bg-green-900/20 border border-green-500/30 rounded-2xl flex flex-col items-center justify-center">
              <Lock className="w-8 h-8 text-green-400 mb-2" />
              <h3 className="font-bold text-white text-md text-center">PQC-KHEPRA-MCP</h3>
              <p className="text-[10px] text-center text-gray-400 mt-1">Air-gapped Agentic Channel</p>
            </div>
            
            <div className="p-5 bg-green-900/20 border border-green-500/30 rounded-2xl flex flex-col items-center justify-center">
              <Server className="w-8 h-8 text-green-400 mb-2" />
              <h3 className="font-bold text-white text-md text-center">ERT Engine</h3>
              <p className="text-[10px] text-center text-gray-400 mt-1">Compliance & Exposure Scoring</p>
            </div>

            <div className="p-5 bg-slate-800/40 border border-slate-600/50 rounded-2xl flex flex-col items-center justify-center relative overflow-hidden">
              <div className="absolute inset-0 border-2 border-dashed border-slate-500/30 rounded-2xl animate-[spin_20s_linear_infinite]"></div>
              <Database className="w-8 h-8 text-slate-300 mb-2" />
              <h3 className="font-bold text-white text-md text-center">Immutable DAG</h3>
              <p className="text-[10px] text-center text-cyan-400 mt-1 font-mono">ML-DSA-65 Signed</p>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
};
