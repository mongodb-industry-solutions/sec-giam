import { writeFileSync } from 'fs';
import { resolve } from 'path';
import { buildOpenApiApp } from '../src/shared/services/openapi';

/**
 * Emits the OpenAPI document to a committed file.
 *
 * Committed on purpose: a generated document that lives only in a running process is a contract
 * nobody can review. In the repository it diffs per change, so a breaking API change is visible in
 * review rather than discovered by an integrator.
 */
async function main(): Promise<void> {
  const { app, document } = await buildOpenApiApp();
  const target = resolve(__dirname, '../openapi.json');
  writeFileSync(target, `${JSON.stringify(document, null, 2)}\n`, 'utf8');
  await app.close();
  console.log(`wrote ${target} (${Object.keys(document.paths ?? {}).length} path(s))`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
