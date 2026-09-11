import { Db } from 'mongodb';
import { RESOURCE_COLLECTION } from '../../../shared/models/collections';

/**
 * What each scope means, gathered from the resource servers that accept them.
 *
 * From the CATALOG rather than from a map in the caller: a description like "See your payments" is
 * one industry's vocabulary, and an authority that has to serve several cannot carry it. The
 * deployment declares them through the seeder and this renders what it is given.
 *
 * Shared rather than local to one controller: the authorization endpoint's own consent screen and
 * the sign-in screen's "who is asking, for what" both read the same catalogue, and a scope's
 * description should not depend on which of the two is asking.
 */
export async function scopeCatalogue(
  db: Db,
  realmId: string,
): Promise<Map<string, { description?: string; required?: boolean }>> {
  const servers = await db
    .collection<{ scopes?: Array<{ name: string; description: string; required?: boolean }> }>(RESOURCE_COLLECTION)
    .find({ realmId, scopes: { $exists: true } }, { projection: { _id: 0, scopes: 1 } })
    .toArray();
  const catalogue = new Map<string, { description?: string; required?: boolean }>();
  for (const server of servers) {
    for (const scope of server.scopes ?? []) {
      if (!catalogue.has(scope.name)) {
        catalogue.set(scope.name, { description: scope.description, required: scope.required });
      }
    }
  }
  return catalogue;
}
