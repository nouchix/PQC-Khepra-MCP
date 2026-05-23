"use client";
import ProtectedRoute from "@/components/ProtectedRoute";
import UltimateDashboard from "@/pages/UltimateDashboard";
export default function Page() {
  return <ProtectedRoute><UltimateDashboard /></ProtectedRoute>;
}
