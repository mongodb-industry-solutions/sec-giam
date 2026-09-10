import type { Metadata } from 'next';
import './globals.css';
import { BRAND } from '../config/brand';
import { ConfirmProvider } from '../components/ConfirmProvider';

export const metadata: Metadata = {
  title: BRAND.full,
  description: BRAND.tagline,
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  // suppressHydrationWarning: browser extensions mutate the DOM before React hydrates, which
  // otherwise reports as an attribute mismatch that has nothing to do with this application.
  return (
    <html lang="en" suppressHydrationWarning>
      <body suppressHydrationWarning>
        <ConfirmProvider>{children}</ConfirmProvider>
      </body>
    </html>
  );
}
