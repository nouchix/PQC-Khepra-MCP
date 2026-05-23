"use client";
import ProtectedRoute from "@/components/ProtectedRoute";
import EvidenceCollectionMVP from "@/pages/EvidenceCollectionMVP";
export default function Page() {
  return <ProtectedRoute><EvidenceCollectionMVP /></ProtectedRoute>;
}
