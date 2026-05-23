"use client";
import ProtectedRoute from "@/components/ProtectedRoute";
import { ThreatHuntingDashboard } from "@/pages/ThreatHuntingDashboard";
export default function Page() {
  return <ProtectedRoute><ThreatHuntingDashboard /></ProtectedRoute>;
}
