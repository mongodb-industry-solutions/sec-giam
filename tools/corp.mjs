// corp tool — session manager for testing against corp-SSO-protected hosts.
//
// Log in once in a real browser; this keeps the session and hands you the corp SSO cookie so
// Postman/curl can call *.corp.mongodb.com hosts (one cookie works for frontend and backend).
//
// Usage:
//   node tools/corp.mjs                 # staging (default)
//   node tools/corp.mjs --env prod      # production hosts
//   node tools/corp.mjs --url https://<any-corp-host>/   # explicit host
//
// Not hard-coded to this project — override the login host with (in precedence order):
//   --url <full-url>        exact host, wins over everything
//   CORP_LOGIN_URL          env, exact full URL
//   CORP_URL_TEMPLATE       env, template with {app} + {env} placeholders
//   CORP_APP                env, just the app name (default sec-fsi-pci-dss-frontend), keeps the template
//
// First run (or once the session expires): a browser window opens; complete the Okta login (MFA
// included), then press Enter in the terminal. Subsequent runs reuse the session silently.
//
// Outputs (all under .corp/ at the repo root, gitignored — they are YOUR session credentials, never
// commit them):
//   .corp/cookie.txt   the `Cookie:` header value
//   .corp/cookie.env   COOKIE=... (source it in a shell)
//   .corp/cookie.postman_environment.json   import into Postman (variable: corpCookie)
//   .corp/cookies.jar  Netscape cookie jar for curl -b (no string munging)
//   .corp/cookies.cookie-editor.json  import into the Cookie-Editor browser extension
//
// Consume (one cookie is valid for any *.corp.mongodb.com host):
//   curl -b .corp/cookies.jar https://<any-corp-host>/
//   curl -H "Cookie: $(cat .corp/cookie.txt)" https://<any-corp-host>/
//
// Setup once: npm i -D @playwright/test && npx playwright install chromium
import { chromium } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const TOOLS_DIR = path.dirname(fileURLToPath(import.meta.url));
// These outputs are your session credentials. Restrict new files/dirs to owner-only
// (no group/world read) in case the repo lives on a shared machine. No-op on Windows.
try { process.umask(0o077); } catch { /* umask unsupported on this platform */ }
const CORP_DIR = path.join(TOOLS_DIR, '..', '.corp'); // repo-root .corp/ (gitignored)
fs.mkdirSync(CORP_DIR, { recursive: true });
// umask only guards newly created files; harden .corp/ itself in case it predates this (non-Windows).
if (process.platform !== 'win32') {
  try { fs.chmodSync(CORP_DIR, 0o700); } catch { /* best effort */ }
}
const PROFILE_DIR = path.join(CORP_DIR, 'profile'); // persistent browser profile (remembers device/MFA)

// ── Args ────────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
function arg(name) {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
}
const envName = arg('env') ?? 'staging';
const host = envName === 'prod' || envName === 'production' ? 'prod' : 'staging';

// Login URL is not hard-coded to this project. Resolution order:
//   1. --url <full-url>                exact, wins over everything
//   2. CORP_LOGIN_URL env             exact full URL
//   3. CORP_URL_TEMPLATE env          template with {app} + {env} placeholders
//   4. built-in default template      {app} defaults to CORP_APP (this project's frontend)
// App name is its own placeholder ({app}) so you can keep the whole template and just swap the app.
const appName = process.env.CORP_APP ?? 'sec-fsi-pci-dss-frontend';
const URL_TEMPLATE =
  process.env.CORP_URL_TEMPLATE ??
  'https://{app}.industrysolutions.{env}.corp.mongodb.com/';
const url =
  arg('url') ??
  process.env.CORP_LOGIN_URL ??
  URL_TEMPLATE.replaceAll('{app}', appName).replaceAll('{env}', host);

const out = {
  header: path.join(CORP_DIR, 'cookie.txt'),
  env: path.join(CORP_DIR, 'cookie.env'),
  postman: path.join(CORP_DIR, 'cookie.postman_environment.json'),
  jar: path.join(CORP_DIR, 'cookies.jar'),
  editor: path.join(CORP_DIR, 'cookies.cookie-editor.json'),
};

function waitForEnter(msg) {
  // Fail fast when stdin isn't a TTY (piped/CI), otherwise this would hang forever waiting for Enter.
  if (!process.stdin.isTTY) {
    throw new Error('Interactive Okta login required, but stdin is not a TTY. Run this in a terminal.');
  }
  return new Promise((resolve) => {
    process.stdout.write(msg);
    process.stdin.resume();
    process.stdin.once('data', () => { process.stdin.pause(); resolve(); });
  });
}

// ── Main ────────────────────────────────────────────────────────────────────
const ctx = await chromium.launchPersistentContext(PROFILE_DIR, {
  headless: false,
  viewport: { width: 1100, height: 850 },
});
try {
  const page = ctx.pages()[0] ?? (await ctx.newPage());
  await page.goto(url, { waitUntil: 'domcontentloaded' });

  // If the corp SSO bounced us to Okta, let the user complete it (MFA included), then continue.
  if (/login\.corp\.mongodb\.com|okta/i.test(page.url())) {
    await waitForEnter('\n→ Complete the Okta login in the browser window, then press Enter here…\n');
    // Give the post-login redirect a moment to settle back onto the corp host.
    await page.waitForTimeout(1500).catch(() => {});
  }

  // Strict suffix match on the domain so lookalikes (e.g. corp.mongodb.com.evil.tld) can't
  // slip through; the leading-dot form used by cookie jars is matched via the '.corp…' suffix.
  const isCorpDomain = (d) => {
    const bare = d.replace(/^\./, '');
    return bare === 'corp.mongodb.com' || bare.endsWith('.corp.mongodb.com');
  };
  const authCookies = (await ctx.cookies()).filter(
    (c) => isCorpDomain(c.domain) && c.name.toLowerCase().startsWith('auth'),
  );
  if (authCookies.length === 0) {
    throw new Error('No auth* cookies found for *.corp.mongodb.com. Is the login complete?');
  }

  // Prefer root-domain cookies (.corp.mongodb.com / corp.mongodb.com) so the exported header
  // authenticates against any corp host. Host-scoped cookies (e.g. login.corp.mongodb.com) would
  // leak to unrelated hosts and cause duplicate-name parsing issues, so drop them when a root
  // cookie exists; fall back to whatever we have (with a warning) if none are root-scoped.
  const isRootDomain = (d) => d.replace(/^\./, '') === 'corp.mongodb.com';
  const rootCookies = authCookies.filter((c) => isRootDomain(c.domain));
  if (rootCookies.length === 0) {
    console.warn('⚠ No root-domain (.corp.mongodb.com) auth cookies found; using host-scoped cookies, which may not authenticate against every corp host.');
  }
  // Sort by name for deterministic output across runs.
  const cookies = (rootCookies.length > 0 ? rootCookies : authCookies).sort((a, b) =>
    a.name.localeCompare(b.name),
  );

  // umask covers files created fresh, but a rerun overwrites pre-existing files without changing
  // their mode. Write with an explicit owner-only mode so credentials never stay group/world-readable.
  const SECRET_MODE = 0o600;
  const writeSecret = (file, data) => fs.writeFileSync(file, data, { mode: SECRET_MODE });

  const header = cookies.map((c) => `${c.name}=${c.value}`).join('; ');
  writeSecret(out.header, header);
  // The header contains spaces and semicolons, so single-quote it to survive `source .corp/cookie.env`.
  writeSecret(out.env, `COOKIE='${header.replaceAll("'", `'\\''`)}'\n`);
  writeSecret(
    out.postman,
    JSON.stringify(
      {
        id: 'corp-sso-cookie',
        name: `corp-sso (${host})`,
        values: [{ key: 'corpCookie', value: header, type: 'secret', enabled: true }],
        _postman_variable_scope: 'environment',
      },
      null,
      2,
    ),
  );

  // Netscape cookie jar (curl -b). Tab-separated: domain, includeSubdomains, path, secure, expiry,
  // name, value. Playwright uses expires=-1 for session cookies → 0 (session) in the jar.
  const jarLines = ['# Netscape HTTP Cookie File'];
  for (const c of cookies) {
    const includeSub = c.domain.startsWith('.') ? 'TRUE' : 'FALSE';
    const expiry = c.expires && c.expires > 0 ? Math.floor(c.expires) : 0;
    jarLines.push([c.domain, includeSub, c.path || '/', c.secure ? 'TRUE' : 'FALSE', expiry, c.name, c.value].join('\t'));
  }
  writeSecret(out.jar, jarLines.join('\n') + '\n');

  // Cookie-Editor import format (browser extension): array of {name,value,domain,path,httpOnly,...}.
  writeSecret(
    out.editor,
    JSON.stringify(
      cookies.map((c) => ({
        name: c.name,
        value: c.value,
        domain: c.domain,
        path: c.path || '/',
        httpOnly: !!c.httpOnly,
        secure: !!c.secure,
        sameSite: c.sameSite ?? 'Lax',
        ...(c.expires && c.expires > 0 ? { expirationDate: c.expires } : {}),
      })),
      null,
      2,
    ),
  );

  // writeFileSync's mode only applies when a file is created, so chmod existing outputs (and the
  // persistent browser profile) explicitly to strip any broader permissions left by earlier runs.
  if (process.platform !== 'win32') {
    for (const file of Object.values(out)) {
      try { fs.chmodSync(file, SECRET_MODE); } catch { /* best effort */ }
    }
    try { fs.chmodSync(PROFILE_DIR, 0o700); } catch { /* best effort */ }
  }

  // Surface an expiry hint so the user knows when to re-run (auth_token is a JWT with exp).
  const authToken = cookies.find((c) => c.name.toLowerCase() === 'auth_token');
  let expiryNote = '';
  try {
    if (authToken) {
      const exp = JSON.parse(Buffer.from(authToken.value.split('.')[1], 'base64url').toString()).exp;
      if (exp) expiryNote = ` (auth_token expires ${new Date(exp * 1000).toISOString()})`;
    }
  } catch { /* non-JWT cookie — skip */ }

  console.log(`\n✓ Harvested ${cookies.length} corp SSO cookie(s) for ${host}${expiryNote}`);
  for (const p of Object.values(out)) console.log(`  ${p}`);
  // Example against the resolved host (the cookie is valid for every *.corp.mongodb.com host).
  const sampleOrigin = (() => { try { return new URL(url).origin; } catch { return url; } })();
  console.log(`\n  curl -b .corp/cookies.jar ${sampleOrigin}/\n`);
} finally {
  await ctx.close();
}
