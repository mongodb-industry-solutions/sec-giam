'use server';

/**
 * The private, in-cluster API base, read fresh on every call.
 *
 * Never inlined into the client bundle: `GIAM_API_PRIVATE_URL` is only set inside the cluster and
 * differs per environment, so baking it in at build time would freeze whatever the build container
 * happened to see, exactly what `next.config.js`'s own `env` block already warns against. A server
 * action runs on the server for the same reason the same-origin proxy does, and reads `process.env`
 * at request time rather than at build time.
 */
export async function privateApiBase(): Promise<string | null> {
  const value = process.env.GIAM_API_PRIVATE_URL?.trim();
  return value ? value : null;
}
