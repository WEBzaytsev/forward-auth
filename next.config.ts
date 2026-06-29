import type { NextConfig } from "next";

// Edge security headers (X-Frame-Options, HSTS, etc.) are set in Caddy.
// CSP with per-request nonce is set in proxy.ts.
// Permissions-Policy is app-specific and not duplicated at the edge.
const securityHeaders = [
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=()",
  },
];

const nextConfig: NextConfig = {
  output: "standalone",
  poweredByHeader: false,
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
