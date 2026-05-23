"use client";
import ProtectedRoute from "@/components/ProtectedRoute";
import GlobalIntelligenceDashboard from "@/pages/GlobalIntelligenceDashboard";
export default function Page() {
  return <ProtectedRoute><GlobalIntelligenceDashboard /></ProtectedRoute>;
}
