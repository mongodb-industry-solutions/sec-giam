import { getQEClient, closeQEClient } from '../src/vendors/encryption/qeClient';
import { validateSetup } from '../src/vendors/setup/validateSetup';
import { config } from '../src/config';

async function main(): Promise<void> {
  const client = await getQEClient();
  try {
    const { checks, ok } = await validateSetup(client.db(config.mongodb.dbName));
    for (const check of checks) {
      console.log(`  ${check.ok ? 'ok  ' : 'FAIL'}  ${check.name}${check.detail ? `  (${check.detail})` : ''}`);
    }
    console.log(ok ? '\nGIAM validation passed.' : '\nGIAM validation FAILED.');
    process.exitCode = ok ? 0 : 1;
  } finally {
    await closeQEClient();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
