// Prints the DEMO client credentials, since they are derived rather than written down in the fixture
// and "read the bcrypt hash in the database" is not an answer for someone configuring an app.
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

// The repo-root .env: reporting "unset" while a variable is set would point at the wrong value.
try {
  const { config } = await import('dotenv');
  config({ path: join(here, '../../../.env'), quiet: true });
} catch { /* no root .env in this context: every variable then reads as unset, which is true */ }

const { clientSecretFor, CLIENT_SECRET_REFS } = await import('@leafypay/platform-links');

const clients = JSON.parse(readFileSync(join(here, '../data/clients.json'), 'utf8'));

const confidential = clients.filter((client) => client.clientType === 'confidential');

console.log('\n  Demo client credentials. Preconfiguration only, never a production credential.\n');

for (const client of confidential) {
  const ref = CLIENT_SECRET_REFS[client.clientId];
  const pinned = ref && process.env[ref]?.trim();
  console.log(`  ${client.clientName}`);
  console.log(`    realm         ${client.realm}`);
  console.log(`    client_id     ${client.clientId}`);
  console.log(`    client_secret ${clientSecretFor(client.clientId)}`);
  if (ref) {
    console.log(`    pinned by     ${ref} ${pinned ? '(set, so it wins over the derived value)' : '(unset, so the derived value is used)'}`);
  }
  console.log('');
}

console.log(`  ${confidential.length} confidential clients. Public clients hold no secret by design.\n`);
