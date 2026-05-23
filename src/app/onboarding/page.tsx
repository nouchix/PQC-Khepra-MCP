"use client";
import ProtectedRoute from "@/components/ProtectedRoute";
import Onboarding from "@/pages/Onboarding";
export default function Page() {
  return <ProtectedRoute><Onboarding /></ProtectedRoute>;
}
