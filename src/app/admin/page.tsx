"use client";
import ProtectedRoute from "@/components/ProtectedRoute";
import MasterAdmin from "@/pages/MasterAdmin";
export default function Page() {
  return <ProtectedRoute><MasterAdmin /></ProtectedRoute>;
}
