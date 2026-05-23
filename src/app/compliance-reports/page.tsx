"use client";
import ProtectedRoute from "@/components/ProtectedRoute";
import ComplianceReports from "@/pages/ComplianceReports";
export default function Page() {
  return <ProtectedRoute><ComplianceReports /></ProtectedRoute>;
}
