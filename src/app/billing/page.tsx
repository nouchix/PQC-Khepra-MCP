"use client";
import ProtectedRoute from "@/components/ProtectedRoute";
import SimpleBilling from "@/pages/SimpleBilling";
export default function Page() {
  return <ProtectedRoute><SimpleBilling /></ProtectedRoute>;
}
