"use client";
import ProtectedRoute from "@/components/ProtectedRoute";
import STIGDashboard from "@/pages/STIGDashboard";
export default function Page() {
  return <ProtectedRoute><STIGDashboard /></ProtectedRoute>;
}
