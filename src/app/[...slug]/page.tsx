"use client";

import dynamic from "next/dynamic";

// Dynamic import to avoid SSR issues with BrowserRouter
const App = dynamic(() => import("../../App"), { ssr: false });

export default function CatchAllPage() {
  return <App />;
}
