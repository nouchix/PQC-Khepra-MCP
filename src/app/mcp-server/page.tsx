import type { Metadata } from "next";
import MCPServerDashboard from "@/pages/MCPServerDashboard";

export const metadata: Metadata = {
  title: "KHEPRA MCP Server Dashboard | SouHimBou AI",
  description:
    "Real-time status dashboard for the KHEPRA MCP server — PQC-01-STIG-V1R1 compliance tool status, DAG audit chain depth, ML-DSA-65 key status, and per-tool invocation metrics.",
};

export default function MCPServerDashboardPage() {
  return <MCPServerDashboard />;
}
