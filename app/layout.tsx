import type { Metadata } from "next";
import { Inter } from "next/font/google";
import { headers } from "next/headers";
import "./globals.css";

const inter = Inter({ subsets: ["latin", "cyrillic"] });

export const metadata: Metadata = {
  title: "Вход в сервис",
  description: "Подтверждение доступа к защищённым сервисам",
};

export default async function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  // Reading x-nonce here causes Next.js to propagate the nonce to all inline
  // scripts it generates for this request (RSC flight data, hydration bootstrap).
  // The nonce itself is set on the request headers by proxy.ts.
  const nonce = (await headers()).get("x-nonce") ?? undefined;

  return (
    <html lang="ru" className="dark" data-theme="dark" suppressHydrationWarning>
      <body
        className={`${inter.className} bg-background text-foreground`}
        {...(nonce ? { nonce } : {})}
      >
        {children}
      </body>
    </html>
  );
}
