'use client';

import { KeyRound } from 'lucide-react';
import { SectionHeader } from '../../../components/SectionHeader';
import { CredentialsPanel } from '../../../components/CredentialsPanel';

export default function ConsoleCredentialsPage() {
  return (
    <main className="space-y-5">
      <SectionHeader
        icon={KeyRound}
        title="Your authenticators"
        description="Devices that can approve a sign-in for you."
        info="Only the public half of each key is ever stored here, so this list cannot be used to sign in as you. Retiring one stops it immediately; the record of it stays, so a later question about what could sign at a given moment still has an answer."
      />
      <CredentialsPanel />
    </main>
  );
}
