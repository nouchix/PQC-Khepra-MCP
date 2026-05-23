"use client";
import ProtectedRoute from "@/components/ProtectedRoute";
import AssetScanning from "@/pages/AssetScanning";
export default function Page() {
  return <ProtectedRoute><AssetScanning /></ProtectedRoute>;
}
