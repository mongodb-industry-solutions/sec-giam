'use client';

import { Database, Lock, ShieldCheck, type LucideIcon } from 'lucide-react';
import { SectionHeader } from '../../../../components/SectionHeader';

/**
 * Why the database underneath is the right one for an identity authority.
 *
 * The security half leads, because for this kind of system it is the decisive half. An authority is a
 * concentration of the most sensitive data an organisation holds: who everybody is, what they may do,
 * and the keys that vouch for both. Every claim below names something this authority actually does.
 */

interface Point {
  title: string;
  body: string;
  /** Where in this console you can see it, so a claim is checkable rather than asserted. */
  here?: string;
}

const SECURITY: Point[] = [
  {
    title: 'Encrypted where it matters, and still queryable',
    body:
      'A directory is only useful if you can look somebody up, which is exactly what encrypting it usually prevents. Queryable Encryption removes that trade: the driver encrypts personal data inside this authority’s own process, the server stores nothing but ciphertext, and a query on those fields is still answered. Equality, and prefix, suffix or substring matching where a screen needs it, without the database ever holding a key or seeing a plaintext value.',
    here: 'Searching a principal by name or by email.',
  },
  {
    title: 'The database administrator is outside the trust boundary',
    body:
      'Because the keys never reach the server, somebody with full access to the storage, the backups, the replication stream or the running process sees masked values and nothing else. For an identity authority that is the threat that actually matters: not a stolen disk, but a legitimate operator whose reach quietly exceeds their mandate. This is the one control that a permission model cannot provide, because it protects against the person who administers the permission model.',
  },
  {
    title: 'Keys separated from the data they protect, and rotatable',
    body:
      'Each protected field is encrypted under its own data key; those keys live in a key vault of their own, themselves encrypted under a master key held by an external key manager. Three separate things to compromise instead of one, and a key can be rotated without rewriting a line of application code. Access to the vault is narrower than access to the data, which is what makes the separation real rather than nominal.',
  },
  {
    title: 'Least privilege reaches the database, not just the API',
    body:
      'Role-based access control at the database level means this authority connects as a principal scoped to the collections it owns, and every other institution in the platform connects as a different one to a different database. So a compromise of one service is not a compromise of the estate, and the boundary the architecture claims is enforced one layer below the code that claims it.',
    here: 'Each institution here holds its own database and its own credentials.',
  },
  {
    title: 'Encrypted in transit, at rest, and audited underneath',
    body:
      'Connections are TLS-only, storage is encrypted at rest independently of the field-level encryption above it, and the database keeps its own audit of privileged operations, separate from the identity trail this console shows. Network reach is closed by default and opened to named private endpoints rather than to addresses, so a leaked connection string is not by itself a way in.',
  },
  {
    title: 'An append-only trail that cannot be quietly edited',
    body:
      'The identity trail is written once per event and never updated. Writing it as a time series collection makes that shape explicit and cheap: compact storage, retention expressed as a property of the data rather than as a cleanup job somebody has to remember, and queries by time and actor that do not scan the rest of history.',
    here: 'The Activity section.',
  },
];

const MODELLING: Point[] = [
  {
    title: 'A principal is not a rectangle',
    body:
      'A person here carries several identifiers, several emails, a set of registered authenticators, a lifecycle, and attributes that differ by realm. A service principal carries almost none of that and other things instead. One document holds each as the shape it actually is, so reading a principal is one read rather than a join across six tables reassembled into the shape the domain started with.',
    here: 'Any record on the Principals screen.',
  },
  {
    title: 'One shape for many kinds of principal',
    body:
      'People, services and workloads are the same thing to an authority and different in their details. A single collection holds all three without a nullable column per variant, and adding a fourth kind is a write rather than a migration across the estate.',
  },
  {
    title: 'Roles compose, and composition is a graph',
    body:
      'A role can inherit another, so resolving what somebody holds means walking a hierarchy of unknown depth. That traversal runs inside the database in one operation, which is why an issuance resolves inherited roles without the application fetching a level at a time.',
    here: 'The Roles screen, where a composed role shows what it grants once flattened.',
  },
  {
    title: 'Policies are documents, so a rule is data',
    body:
      'A conditional statement evaluated after roles is a stored document, not code to deploy. That is what makes the simulator possible: the same statements can be run against a hypothetical request and asked which one decided, because the rules are readable objects rather than compiled behaviour.',
    here: 'The Policies screen and its simulator.',
  },
  {
    title: 'Deterministic identifiers, so a rebuild is reproducible',
    body:
      'Realms, roles, permissions and assignments are keyed by identifiers derived from their names rather than generated at random. Re-running the seed against an existing database updates the same documents instead of creating a second copy, which is what lets a fixture change be applied to a live environment rather than only to an empty one.',
  },
  {
    title: 'Validation without giving up flexibility',
    body:
      'Collections carry a schema the server enforces, so a required field stays required and a status stays inside its allowed set. The flexibility is in evolving that contract deliberately, not in having none, and an unindexed field added by accident is not the same as a field the model permits.',
  },
];

export default function AuthorityHelpMongoDB() {
  return (
    <div className="space-y-6">
      <SectionHeader
        icon={Database}
        title="Why MongoDB"
        description="Two arguments, and for an authority the security one decides it."
        info={
          <>
            An identity authority concentrates the most sensitive data an organisation holds: who everybody is, what
            they may do, and the keys that vouch for both. So the question is not whether the database can store it,
            but whether it can keep it unreadable to the people who run the database and still answer a query.
          </>
        }
      />

      <section className="space-y-3">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-500">
          Security, and what the database contributes to it
        </h2>

        <article className="rounded-xl border border-[#00ED64]/40 bg-[#00ED64]/5 p-4">
          <div className="flex items-start gap-2.5">
            <ShieldCheck size={16} className="mt-0.5 shrink-0 text-[#00684A]" />
            <div className="min-w-0">
              <h3 className="text-sm font-bold text-[#001E2B]">The problem this solves</h3>
              <p className="mt-1 text-sm leading-relaxed text-gray-700">
                Protecting personal data is easy until somebody has to find it again. The usual answer is to encrypt
                the field, lose the ability to query it, and then rebuild searchability with tokens, hashes or a
                plaintext index that quietly becomes the thing worth stealing. This authority does none of that: the
                fields stay encrypted, the keys stay with the application, and the lookups still work. That is the
                differentiator, and everything below follows from it.
              </p>
            </div>
          </div>
        </article>

        <div className="grid gap-4 lg:grid-cols-2">
          {SECURITY.map((point) => (
            <PointCard key={point.title} point={point} icon={Lock} />
          ))}
        </div>
      </section>

      <section className="space-y-3">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-500">
          Modelling an authority
        </h2>
        <div className="grid gap-4 lg:grid-cols-2">
          {MODELLING.map((point) => (
            <PointCard key={point.title} point={point} icon={Database} />
          ))}
        </div>
      </section>
    </div>
  );
}

function PointCard({ point, icon: Icon }: { point: Point; icon: LucideIcon }) {
  return (
    <article className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
      <div className="flex items-start gap-2.5">
        <Icon size={16} className="mt-0.5 shrink-0 text-[#00684A]" />
        <div className="min-w-0 space-y-1.5">
          <h3 className="text-sm font-bold text-[#001E2B]">{point.title}</h3>
          <p className="text-xs leading-relaxed text-gray-600">{point.body}</p>
          {point.here && (
            <p className="text-[11px] leading-relaxed text-gray-500">
              <span className="font-semibold text-[#001E2B]">See it here:</span> {point.here}
            </p>
          )}
        </div>
      </div>
    </article>
  );
}
