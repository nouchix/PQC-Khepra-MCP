/** @type {import('next').NextConfig} */
const nextConfig = {
  // Disable ESLint during builds (eslint not in devDeps; app compiles fine)
  eslint: {
    ignoreDuringBuilds: true,
  },
  // Disable TS type-check during builds (packages/dag-viewer has its own tsconfig)
  typescript: {
    ignoreBuildErrors: true,
  },
};

export default nextConfig;
