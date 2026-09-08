import { redirect } from 'next/navigation';

// No content of its own: the section opens on its first tab, same as visiting `/system/help` opens
// on "What this is". Applications first because registering one is usually why an operator is here.
export default function CredentialsIndexPage() {
  redirect('/system/credentials/applications');
}
