import './globals.css';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'MITRE ATT&CK Incident Mapper',
  description: 'Automated security log analysis with MITRE mapping',
  keywords: ['MITRE', 'ATT&CK', 'SOC', 'Incident Response', 'Cybersecurity', 'Threat Intelligence'],
  authors: [{ name: 'Soham Shah' }],
  icons: {
    icon: '/icon.svg',
    shortcut: '/icon.svg',
  },
  openGraph: {
    title: 'MITRE ATT&CK Incident Mapper',
    description: 'Automated security log analysis with MITRE mapping',
    type: 'website',
    url: 'https://mitre-incident-mapper.vercel.app',
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="font-sans antialiased bg-slate-50 min-h-screen">{children}</body>
    </html>
  );
}
