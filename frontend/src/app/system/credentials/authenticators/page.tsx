'use client';

import { KeyRound } from 'lucide-react';
import { SectionHeader } from '../../../../components/SectionHeader';
import { CredentialsPanel } from '../../../../components/CredentialsPanel';
import { PasswordChangeForm } from '../../../../components/PasswordChangeForm';

export default function ConsoleCredentialsPage() {
  return (
    <main className="space-y-5">
      <SectionHeader
        icon={KeyRound}
        title="Your credentials"
        description="What signs you in: your password, and the devices that can approve a sign-in for you."
        info="Only the public half of each device key is ever stored here, so the authenticator list cannot be used to sign in as you. A password change requires the current one, which is what stands in for an administrator's permission. Retiring an authenticator stops it immediately; the record of it stays, so a later question about what could sign at a given moment still has an answer."
      />
      <PasswordChangeForm />
      <CredentialsPanel />
    </main>
  );
}
