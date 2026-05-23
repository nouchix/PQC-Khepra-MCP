"use client";
import ProtectedRoute from "@/components/ProtectedRoute";
import ClientPortal from "@/pages/ClientPortal";
export default function Page() {
  return <ProtectedRoute><ClientPortal /></ProtectedRoute>;
}
