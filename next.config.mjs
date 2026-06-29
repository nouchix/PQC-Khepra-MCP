/** @type {import('next').NextConfig} */
const nextConfig = {
  // src/ is the app root — all pages and API routes live there
  // tsconfig.json already maps @/* → ./src/*
  experimental: {
    // Required for App Router + src/ directory
  },
  // Rewrites are not needed — /api/scan is already a native App Router route
  // at src/app/api/scan/route.ts
};

export default nextConfig;
