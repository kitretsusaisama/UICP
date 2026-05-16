import type { Metadata } from 'next';
import './globals.css';
import Providers from '../providers';

export const metadata: Metadata = {
  title: 'UICP — Unified Identity Communication Platform',
  description: 'Tenant-scoped identity operations, multi-provider OTP, real-time SOC monitoring',
  icons: {
    icon: '/favicon.ico',
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="light">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}