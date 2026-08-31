import { randomBytes } from 'crypto';

// GIAM's own customer master key, the one its DEKs are wrapped under.
//
// Its OWN, deliberately, and not the platform's. GIAM holds its own key vault with its own data
// encryption keys precisely so that an identity system shares no key material with the applications
// it protects, and reusing the applications' master key would put both vaults back under one root and
// undo that in a single line of configuration.
//
// Queryable Encryption's local KMS provider requires 96 bytes.
const key = randomBytes(96).toString('base64');

console.log('\nGIAM local master key generated (96 bytes, base64)\n');
console.log('Add this line to your .env, and do not reuse another service\'s key:\n');
console.log(`GIAM_KMS_LOCAL_MASTER_KEY=${key}`);
console.log('\nAlso ensure:\n  GIAM_KMS_PROVIDER=local\n');
console.log('Losing this key makes everything encrypted under GIAM\'s DEKs unreadable. That is');
console.log('recoverable here and only here, because setup plus seed rebuild the database entirely.\n');
