import { CredentialsTabs } from '../../../components/credentials/CredentialsTabs';

// Every credential page carries the same tabs, so the section reads as one place with two views
// rather than two unrelated screens that happen to share a sidebar entry.
export default function CredentialsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="space-y-5">
      <CredentialsTabs />
      {children}
    </div>
  );
}
