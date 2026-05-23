import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "KHEPRA MCP Quickstart | SouHimBou AI",
  description:
    "Install the KHEPRA MCP server and generate signed, policy-routed agent tool-call evidence.",
};

const installConfig = `{
  "mcpServers": {
    "khepra-mcp": {
      "command": "go",
      "args": ["run", "./cmd/khepra-mcp"],
      "env": {
        "KHEPRA_MANIFEST_PATH": "./manifest.json",
        "PHANTOM_SYMBOL": "Eban"
      }
    }
  }
}`;

const smokeCommand = `go run ./cmd/khepra-mcp\n./scripts/mcp-smoke-test.ps1`;

const registryCommand = `docker build -f Dockerfile.mcp \\
  -t ghcr.io/etherversecodemate/khepra-mcp:1.0.0 .

mcp-publisher login github
mcp-publisher publish`;

export default function MCPQuickstartPage() {
  return (
    <main className="min-h-screen bg-zinc-950 text-zinc-100">
      {/* Hero */}
      <section className="border-b border-zinc-800 bg-zinc-950">
        <div className="mx-auto grid max-w-7xl gap-10 px-6 py-12 lg:grid-cols-[1.1fr_0.9fr] lg:px-10 lg:py-16">
          <div className="flex flex-col justify-center">
            <div className="mb-6 flex items-center gap-3">
              <img
                src="/lovable-uploads/94f06ba5-2c93-4be0-a03f-e3fff4157ca6.png"
                alt="SouHimBou AI"
                className="h-10 w-auto"
              />
              <span className="rounded border border-cyan-400/30 px-2 py-1 text-xs font-semibold uppercase tracking-[0.14em] text-cyan-300">
                MCP Registry Ready
              </span>
            </div>
            <h1 className="max-w-4xl text-4xl font-semibold tracking-normal text-white md:text-6xl">
              Secure AI agent tool calls with signed MCP evidence.
            </h1>
            <p className="mt-6 max-w-2xl text-lg leading-8 text-zinc-300">
              KHEPRA MCP wraps stdio tool execution with manifest verification,
              risk routing, post-quantum signed responses, and DAG-oriented audit
              provenance for regulated AI workflows.
            </p>
            <div className="mt-8 flex flex-col gap-3 sm:flex-row">
              <a
                href="https://github.com/EtherVerseCodeMate/giza-cyber-shield/blob/main/docs/khepra-mcp-quickstart.md"
                className="inline-flex items-center justify-center rounded-md bg-cyan-300 px-5 py-3 text-sm font-semibold text-zinc-950 hover:bg-cyan-200 transition-colors"
              >
                Read quickstart
              </a>
              <a
                href="https://github.com/EtherVerseCodeMate/giza-cyber-shield/blob/main/docs/mcp-registry-publishing.md"
                className="inline-flex items-center justify-center rounded-md border border-zinc-700 px-5 py-3 text-sm font-semibold text-zinc-100 hover:border-zinc-500 transition-colors"
              >
                Registry notes
              </a>
            </div>
          </div>

          <div className="self-end border border-zinc-800 bg-zinc-900/60 p-5 rounded-lg">
            <div className="mb-3 flex items-center justify-between text-xs uppercase tracking-[0.14em] text-zinc-400">
              <span>Smoke Test</span>
              <span>stdio · json-rpc</span>
            </div>
            <pre className="overflow-x-auto whitespace-pre-wrap text-sm leading-6 text-cyan-100">
              <code>{smokeCommand}</code>
            </pre>
          </div>
        </div>
      </section>

      {/* Three steps */}
      <section className="border-b border-zinc-800 bg-zinc-900">
        <div className="mx-auto grid max-w-7xl gap-8 px-6 py-10 lg:grid-cols-3 lg:px-10">
          <div>
            <p className="text-sm font-semibold uppercase tracking-[0.14em] text-cyan-300">1. Install</p>
            <p className="mt-3 text-sm leading-6 text-zinc-300">
              Run from source while iterating, then switch to the OCI image or
              compiled binary for repeatable installs.
            </p>
          </div>
          <div>
            <p className="text-sm font-semibold uppercase tracking-[0.14em] text-amber-300">2. Verify</p>
            <p className="mt-3 text-sm leading-6 text-zinc-300">
              The smoke test initializes the server, lists tools, and confirms
              ping without polluting stdout.
            </p>
          </div>
          <div>
            <p className="text-sm font-semibold uppercase tracking-[0.14em] text-emerald-300">3. Publish</p>
            <p className="mt-3 text-sm leading-6 text-zinc-300">
              The OCI label and <code className="text-zinc-400">server.json</code> namespace are aligned for MCP
              Registry ownership verification via GitHub OIDC.
            </p>
          </div>
        </div>
      </section>

      {/* Code blocks */}
      <section className="bg-zinc-950">
        <div className="mx-auto grid max-w-7xl gap-8 px-6 py-12 lg:grid-cols-2 lg:px-10">
          <div>
            <h2 className="text-2xl font-semibold text-white">Project config</h2>
            <pre className="mt-5 overflow-x-auto border border-zinc-800 bg-black p-5 text-sm leading-6 text-zinc-200 rounded-lg">
              <code>{installConfig}</code>
            </pre>
          </div>
          <div>
            <h2 className="text-2xl font-semibold text-white">Registry publish</h2>
            <pre className="mt-5 overflow-x-auto border border-zinc-800 bg-black p-5 text-sm leading-6 text-zinc-200 rounded-lg">
              <code>{registryCommand}</code>
            </pre>
          </div>
        </div>
      </section>

      {/* Compliance buyer */}
      <section className="border-t border-zinc-800 bg-zinc-900">
        <div className="mx-auto max-w-7xl px-6 py-12 lg:px-10">
          <div className="max-w-2xl">
            <h2 className="text-2xl font-semibold text-white">Turn agent activity into evidence.</h2>
            <p className="mt-4 text-zinc-300 leading-7">
              KHEPRA records what the agent requested, which policy applied, how the
              tool executed, and which signed result returned to the host. That evidence
              can be exported into a compliance packet for CMMC readiness work mapped
              to NIST SP 800-171 control expectations.
            </p>
            <a
              href="https://adinkhepra.com"
              className="mt-6 inline-flex items-center justify-center rounded-md bg-zinc-700 px-5 py-3 text-sm font-semibold text-zinc-100 hover:bg-zinc-600 transition-colors"
            >
              Request the AI Agent Evidence Gap Assessment →
            </a>
          </div>
        </div>
      </section>

      {/* Tools table */}
      <section className="border-t border-zinc-800 bg-zinc-950">
        <div className="mx-auto max-w-7xl px-6 py-12 lg:px-10">
          <h2 className="text-2xl font-semibold text-white mb-6">Available tools</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead>
                <tr className="border-b border-zinc-800 text-zinc-400 uppercase text-xs tracking-widest">
                  <th className="py-3 pr-6">Tool</th>
                  <th className="py-3 pr-6">Risk</th>
                  <th className="py-3">Purpose</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/50">
                {[
                  { tool: "acp_status",    risk: "read-only",   riskColor: "text-emerald-400", purpose: "List active Agent Control Plane credentials." },
                  { tool: "acp_issue",     risk: "destructive", riskColor: "text-red-400",     purpose: "Issue a new PQC credential." },
                  { tool: "acp_revoke",    risk: "destructive", riskColor: "text-red-400",     purpose: "Revoke an ACP credential." },
                  { tool: "nhi_inventory", risk: "read-only",   riskColor: "text-emerald-400", purpose: "List non-human identities." },
                  { tool: "nhi_orphans",   risk: "read-only",   riskColor: "text-emerald-400", purpose: "Identify identities without active owners." },
                  { tool: "nhi_excessive", risk: "read-only",   riskColor: "text-emerald-400", purpose: "Identify identities with broad permissions." },
                  { tool: "nhi_expired",   risk: "read-only",   riskColor: "text-emerald-400", purpose: "List expired or soon-to-expire identities." },
                  { tool: "nhi_revoke",    risk: "destructive", riskColor: "text-red-400",     purpose: "Revoke a non-human identity credential." },
                  { tool: "ert_scan",      risk: "sandboxed",   riskColor: "text-amber-400",   purpose: "Run an ERT security scan." },
                ].map(({ tool, risk, riskColor, purpose }) => (
                  <tr key={tool}>
                    <td className="py-3 pr-6 font-mono text-cyan-300">{tool}</td>
                    <td className={`py-3 pr-6 font-semibold ${riskColor}`}>{risk}</td>
                    <td className="py-3 text-zinc-300">{purpose}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </main>
  );
}
