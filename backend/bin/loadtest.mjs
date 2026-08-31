/**
 * P8.7: measures what the runbook claims, rather than claiming it.
 *
 * Two replicas of the authority, and the questions that matter: does a token signed by one verify at
 * the other, how long does issuance actually take under concurrency, and how long does introspection
 * take, since that is the cost a resource server pays for the authoritative answer.
 *
 * A performance claim nobody measured is a claim that will be wrong at the worst moment.
 */
const REALM = 'leafypay';
const CLIENT_ID = 'leafypay-backend';
// Derived exactly as the seeder derives it, so the two cannot disagree and no credential is written
// down here.
const { clientSecretFor } = await import('@leafypay/platform-links');
const CLIENT_SECRET = clientSecretFor(CLIENT_ID);

const replicas = process.argv.slice(2);
if (replicas.length < 2) {
  console.error('usage: node loadtest.mjs <replicaA> <replicaB>');
  process.exit(1);
}

async function issue(base) {
  const response = await fetch(`${base}/realms/${REALM}/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    }),
  });
  if (!response.ok) throw new Error(`token endpoint answered ${response.status}`);
  return (await response.json()).access_token;
}

async function introspect(base, token) {
  const response = await fetch(`${base}/realms/${REALM}/protocol/openid-connect/token/introspect`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token, client_id: CLIENT_ID, client_secret: CLIENT_SECRET }),
  });
  return (await response.json()).active;
}

function percentile(samples, p) {
  const sorted = [...samples].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
}

async function measure(label, concurrency, rounds, work) {
  const samples = [];
  for (let round = 0; round < rounds; round += 1) {
    await Promise.all(Array.from({ length: concurrency }, async () => {
      const started = performance.now();
      await work();
      samples.push(performance.now() - started);
    }));
  }
  console.log(
    `${label.padEnd(34)} n=${String(samples.length).padStart(4)}  `
    + `p50=${percentile(samples, 50).toFixed(0)}ms  p95=${percentile(samples, 95).toFixed(0)}ms  `
    + `max=${Math.max(...samples).toFixed(0)}ms`,
  );
  return { p50: percentile(samples, 50), p95: percentile(samples, 95) };
}

const [a, b] = replicas;

// The claim the whole scalability position rests on.
const kids = [];
for (const base of replicas) {
  const token = await issue(base);
  kids.push(JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString()).kid);
}
console.log(`replica A signs with kid ${kids[0].slice(0, 12)}…`);
console.log(`replica B signs with kid ${kids[1].slice(0, 12)}…`);
console.log(`distinct signing keys: ${kids[0] !== kids[1]}`);

const setA = await (await fetch(`${a}/realms/${REALM}/protocol/openid-connect/certs`)).json();
const setB = await (await fetch(`${b}/realms/${REALM}/protocol/openid-connect/certs`)).json();
const idsA = setA.keys.map((k) => k.kid).sort();
const idsB = setB.keys.map((k) => k.kid).sort();
console.log(`published key sets identical: ${JSON.stringify(idsA) === JSON.stringify(idsB)}`);
console.log(`both signing keys published:  ${kids.every((kid) => idsA.includes(kid))}`);

const tokenFromA = await issue(a);
console.log(`token signed by A, introspected at B: ${await introspect(b, tokenFromA)}`);

console.log('');
await measure('token issuance, 20 concurrent', 20, 5, () => issue(a));
const sample = await issue(a);
await measure('introspection, 20 concurrent', 20, 5, () => introspect(b, sample));
