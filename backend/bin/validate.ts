import { getQEClient, closeQEClient } from '../src/vendors/encryption/qeClient';
import { validateSetup } from '../src/vendors/setup/validateSetup';
import { config } from '../src/config';

async function main(): Promise<void> {
  const client = await getQEClient();
  try {
    const { checks, ok, verdict, resetReasons } = await validateSetup(client.db(config.mongodb.dbName));
    for (const check of checks) {
      const label = check.ok ? 'ok  ' : (check.severity === 'warning' ? 'WARN' : 'FAIL');
      console.log(`  ${label}  ${check.name}${check.detail ? `  (${check.detail})` : ''}`);
    }
    // A stable, single-line verdict: the console reads this rather than re-deriving it from the log.
    console.log(`\nverdict: ${verdict}`);
    for (const reason of resetReasons) console.log(`reset required: ${reason}`);
    console.log(ok ? 'GIAM validation passed.' : 'GIAM validation FAILED.');
    process.exitCode = ok ? 0 : 1;
  } finally {
    await closeQEClient();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
