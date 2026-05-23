"use client";
import ProtectedRoute from "@/components/ProtectedRoute";
import CommandCenter from "@/pages/CommandCenter";
export default function Page() {
  return <ProtectedRoute><CommandCenter /></ProtectedRoute>;
}
