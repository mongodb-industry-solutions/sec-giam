import { execSync, spawnSync } from "child_process";
import { createInterface } from "readline";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs";
import { resolve, join, dirname } from "path";
import { homedir, platform } from "os";
import * as dotenv from "dotenv";

// -- Resolve project root (works from any cwd) --
function findProjectRoot(): string {
  try {
    return execSync("git rev-parse --show-toplevel", { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] }).trim();
  } catch {
    let dir = resolve(__dirname, "..");
    while (dir !== dirname(dir)) {
      if (existsSync(join(dir, "package.json"))) return dir;
      dir = dirname(dir);
    }
    return resolve(__dirname, "..");
  }
}

const PROJECT_ROOT = findProjectRoot();
const ENV_PATH = join(PROJECT_ROOT, ".env");
if (existsSync(ENV_PATH)) dotenv.config({ path: ENV_PATH });

// -- Constants (override via KUBE_* env vars, defaults match MongoDB IST) --
const IST_NAMESPACE = process.env.KUBE_NAMESPACE ?? "industrysolutions";
const ECR_REGISTRY = process.env.KUBE_ECR_REGISTRY ?? "795250896452.dkr.ecr.us-east-1.amazonaws.com";
const STAGING_API = process.env.KUBE_STAGING_API ?? "https://api.staging.corp.mongodb.com";
const PROD_API = process.env.KUBE_PROD_API ?? "https://api.prod.corp.mongodb.com";
const HELM_REPO_NAME = process.env.KUBE_HELM_REPO_NAME ?? "mongodb";
const HELM_REPO_URL = process.env.KUBE_HELM_REPO_URL ?? "https://10gen.github.io/helm-charts";
const HELM_CHART_VERSION = process.env.KUBE_HELM_CHART_VERSION ?? "4.25.0";
const DRONE_URL = process.env.KUBE_DRONE_URL ?? "https://drone.corp.mongodb.com";

// kanopy-oidc creates kubectl contexts without the protocol prefix
function contextName(apiUrl: string): string {
  return apiUrl.replace(/^https?:\/\//, "");
}

const DEMO_NAME = process.env.KUBE_DEMO_NAME ?? "sec-fsi-pci-dss";
const RELEASE_BACKEND = process.env.KUBE_RELEASE_BACKEND ?? `${DEMO_NAME}-backend`;
const RELEASE_FRONTEND = process.env.KUBE_RELEASE_FRONTEND ?? `${DEMO_NAME}-frontend`;
const RELEASE_MERCHANT = process.env.KUBE_RELEASE_MERCHANT ?? `${DEMO_NAME}-merchant`;
// The bank (v37). Deployed with ingress.enabled=false, so it has a release and pods but no host: every
// menu below that asks for a URL deliberately leaves it out.
const RELEASE_BANKCORE = process.env.KUBE_RELEASE_BANKCORE ?? `${DEMO_NAME}-bankcore`;
const KSEC_SECRET_STAGING = process.env.KUBE_KSEC_SECRET_STAGING ?? `${DEMO_NAME}-secrets-staging`;
const KSEC_SECRET_PROD = process.env.KUBE_KSEC_SECRET_PROD ?? `${DEMO_NAME}-secrets-prod`;

const DOMAIN_SUFFIX = process.env.KUBE_DOMAIN_SUFFIX ?? "corp.mongodb.com";
const STAGING_HOST_BE = process.env.KUBE_STAGING_HOST_BE ?? `${RELEASE_BACKEND}.${IST_NAMESPACE}.staging.${DOMAIN_SUFFIX}`;
const STAGING_HOST_FE = process.env.KUBE_STAGING_HOST_FE ?? `${RELEASE_FRONTEND}.${IST_NAMESPACE}.staging.${DOMAIN_SUFFIX}`;
const PROD_HOST_BE = process.env.KUBE_PROD_HOST_BE ?? `${RELEASE_BACKEND}.${IST_NAMESPACE}.prod.${DOMAIN_SUFFIX}`;
const PROD_HOST_FE = process.env.KUBE_PROD_HOST_FE ?? `${RELEASE_FRONTEND}.${IST_NAMESPACE}.prod.${DOMAIN_SUFFIX}`;

const HOME = homedir();
const IS_WIN = platform() === "win32";
const KANOPY_CONFIG_PATH = join(HOME, process.env.KUBE_KANOPY_CONFIG_DIR ?? ".kanopy", "config.yaml");
const KUBE_DIR = join(HOME, process.env.KUBE_CONFIG_DIR ?? ".kube");
const CICD_TOKEN_SECRET = process.env.KUBE_CICD_TOKEN_SECRET ?? "kanopy-cicd-token";
const ECR_SECRET_NAME = process.env.KUBE_ECR_SECRET_NAME ?? "ecr";

// -- Target cluster --
// Every read/write command runs against ONE cluster, the selected target, using that cluster's own
// kubeconfig. Merging both files made kubectl resolve the first file's current-context, so a command
// silently reported staging right after a prod login, and a `use-context` write could strip the
// current-context from the other file.
type ClusterEnv = "staging" | "prod";
let TARGET: ClusterEnv = process.env.KUBE_TARGET_ENV === "prod" ? "prod" : "staging";
const kubeconfigPath = (env: ClusterEnv): string => join(KUBE_DIR, `config.${env}`);
const apiServerOf = (env: ClusterEnv): string => (env === "prod" ? PROD_API : STAGING_API);

// -- Helpers --
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const RED = "\x1b[31m";
const CYAN = "\x1b[36m";
const DIM = "\x1b[90m";
const NC = "\x1b[0m";

function ok(msg: string) { console.log(`${GREEN}[ok]${NC}     ${msg}`); }
function warn(msg: string) { console.log(`${YELLOW}[warn]${NC}   ${msg}`); }
function fail(msg: string) { console.log(`${RED}[error]${NC}  ${msg}`); }
function action(msg: string) { console.log(`${CYAN}[action]${NC} ${msg}`); }
function chk(msg: string) { console.log(`[check]  ${msg}`); }

function run(cmd: string, opts?: { silent?: boolean }): string {
  if (!opts?.silent) console.log(`${DIM}[cmd]    ${cmd}${NC}`);
  try {
    return execSync(cmd, { encoding: "utf-8", stdio: opts?.silent ? "pipe" : "inherit" }) || "";
  } catch (e: any) {
    return e.stdout || e.stderr || "";
  }
}

function runCapture(cmd: string): { stdout: string; status: number } {
  console.log(`${DIM}[cmd]    ${cmd}${NC}`);
  const result = spawnSync(cmd, { shell: true, encoding: "utf-8" });
  return { stdout: (result.stdout || "") + (result.stderr || ""), status: result.status || 0 };
}

function hasCommand(name: string): boolean {
  try {
    const cmd = IS_WIN ? `where ${name}` : `which ${name}`;
    execSync(cmd, { stdio: "pipe" });
    return true;
  } catch { return false; }
}

// -- Readline --
const rl = createInterface({ input: process.stdin, output: process.stdout });

function ask(prompt: string): Promise<string> {
  return new Promise((resolve) => rl.question(prompt, (answer) => resolve(answer.trim())));
}

function pause(): Promise<void> {
  return new Promise((resolve) => rl.question("\nPress Enter to return to menu...", () => resolve()));
}

// ============================================================
//  1. SETUP
// ============================================================

async function installKubectl() {
  chk("kubectl...");
  if (hasCommand("kubectl")) { ok("kubectl is available."); return; }
  if (IS_WIN) {
    action("Installing kubectl via winget...");
    run("winget install --id Kubernetes.kubectl --silent --accept-package-agreements --accept-source-agreements");
  } else {
    action("Installing kubectl via brew...");
    run("brew install kubectl");
  }
  hasCommand("kubectl") ? ok("kubectl installed.") : fail("Could not install kubectl. Install manually.");
}

async function installHelm() {
  chk("Helm...");
  if (hasCommand("helm")) { ok("Helm is available."); return; }
  if (IS_WIN) {
    action("Installing Helm via winget...");
    run("winget install --id Helm.Helm --silent --accept-package-agreements --accept-source-agreements");
  } else {
    action("Installing Helm via brew...");
    run("brew install helm");
  }
  hasCommand("helm") ? ok("Helm installed.") : fail("Could not install Helm. Install manually.");
}

async function installKanopyOidc() {
  chk("kanopy-oidc...");
  if (hasCommand("kanopy-oidc")) { ok("kanopy-oidc is available."); return; }
  console.log("");
  warn("kanopy-oidc is not installed.");
  console.log("  Manual steps:");
  console.log("  1. Download from: https://github.com/kanopy-platform/kanopy-oidc/releases/");
  if (IS_WIN) {
    console.log("     - Windows: kanopy-oidc-windows-amd64-v0.5.3.zip");
  } else {
    console.log("     - macOS ARM64: kanopy-oidc-macos-arm64-v0.5.3.tgz");
    console.log("     - macOS AMD64: kanopy-oidc-macos-amd64-v0.5.3.tgz");
    console.log("     - Linux: kanopy-oidc-linux-amd64-v0.5.3.tgz");
  }
  console.log("  2. Extract and place in your PATH.");
}

async function setupHelmRepo() {
  chk(`Helm repo '${HELM_REPO_NAME}'...`);
  const repos = runCapture("helm repo list").stdout;
  if (repos.includes(HELM_REPO_NAME)) {
    ok(`Helm repo '${HELM_REPO_NAME}' already added.`);
  } else {
    action(`Adding Helm repo '${HELM_REPO_NAME}'...`);
    run(`helm repo add ${HELM_REPO_NAME} ${HELM_REPO_URL}`);
  }
  action("Updating Helm repos...");
  run("helm repo update");
  ok("Helm repos up to date.");
}

async function installKsecPlugin() {
  chk("Helm ksec plugin...");
  const plugins = runCapture("helm plugin list").stdout;
  if (plugins.includes("ksec")) { ok("ksec plugin installed."); return; }
  action("Installing ksec Helm plugin...");
  const shellEnv = IS_WIN
    ? { ...process.env, PATH: `C:\\Program Files\\Git\\usr\\bin;${process.env.PATH}` }
    : process.env;
  spawnSync("helm", ["plugin", "install", "https://github.com/kanopy-platform/ksec", "--verify=false"], {
    shell: IS_WIN, stdio: "inherit", env: shellEnv,
  });
  runCapture("helm plugin list").stdout.includes("ksec")
    ? ok("ksec plugin installed.")
    : fail("ksec install failed. Try manually: helm plugin install https://github.com/kanopy-platform/ksec --verify=false");
}

async function createKanopyConfig() {
  chk(`Kanopy OIDC config at ${KANOPY_CONFIG_PATH}...`);
  if (existsSync(KANOPY_CONFIG_PATH)) {
    ok("Config already exists.");
    const overwrite = await ask("Overwrite? (y/N): ");
    if (overwrite.toLowerCase() !== "y") return;
  }

  const secret = process.env.KUBE_CLUSTER_SECRET || "";
  if (!secret) {
    fail("KUBE_CLUSTER_SECRET is not set. Add it to your .env file.");
    return;
  }

  const content = `domain: ${DOMAIN_SUFFIX}
issuer: dex
login:
  connector: oidc
clusters:
  prod:
    secret: ${secret}
  staging:
    secret: ${secret}
`;

  const dir = resolve(KANOPY_CONFIG_PATH, "..");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(KANOPY_CONFIG_PATH, content, "utf-8");
  ok(`Kanopy config created at ${KANOPY_CONFIG_PATH}`);
}

async function fullSetup() {
  console.log(`\n${CYAN}=== Full Kanopy Setup ===${NC}\n`);
  await installKubectl();
  await installHelm();
  await installKanopyOidc();
  await createKanopyConfig();
  await setupHelmRepo();
  await installKsecPlugin();
  console.log("");
  ok("Setup complete. Next: run 'Generate kubeconfig' from the menu.");
}

// ============================================================
//  2. CLUSTER CONFIG
// ============================================================

async function generateKubeconfig() {
  console.log("\nWhich cluster?");
  console.log("  1. staging (default)");
  console.log("  2. prod");
  console.log("  3. both");
  const input = await ask("Choice: ");
  const clusters = input === "2" ? ["prod"] : input === "3" ? ["staging", "prod"] : ["staging"];

  if (!existsSync(KUBE_DIR)) mkdirSync(KUBE_DIR, { recursive: true });

  for (const cluster of clusters) {
    console.log("");
    action(`Generating kubeconfig for '${cluster}'...`);
    const configFile = join(KUBE_DIR, `config.${cluster}`);
    const envPrefix = IS_WIN ? "set" : "export";

    const setupCmd = `kanopy-oidc kube setup ${cluster}`;
    console.log(`${DIM}[cmd]    ${setupCmd} > ${configFile}${NC}`);
    try {
      const output = execSync(setupCmd, { encoding: "utf-8", env: { ...process.env, KUBECONFIG: configFile } });
      writeFileSync(configFile, output, "utf-8");
    } catch (e: any) {
      fail(`Failed to setup kubeconfig for ${cluster}: ${e.message}`);
      continue;
    }

    const loginEnv = { ...process.env, KUBECONFIG: configFile };
    const ctx = contextName(cluster === "prod" ? PROD_API : STAGING_API);
    const ctxResult = spawnSync("kubectl", ["config", "use-context", ctx], { shell: IS_WIN, stdio: "pipe", env: loginEnv });
    if (ctxResult.status !== 0) {
      warn(`Could not select context "${ctx}" (it may not exist yet). Continuing to login, which can create it.`);
    }
    console.log(`${DIM}[cmd]    kanopy-oidc kube login${NC}`);
    const loginResult = spawnSync("kanopy-oidc", ["kube", "login"], { shell: IS_WIN, stdio: "inherit", env: loginEnv });
    if (loginResult.status !== 0) {
      warn(`Login failed for ${cluster}. You can retry with option 7 later.`);
    }

    console.log(`${DIM}[cmd]    kubectl config set-context ... --namespace=${IST_NAMESPACE}${NC}`);
    spawnSync("kubectl", ["config", "set-context", "--current", `--namespace=${IST_NAMESPACE}`], {
      shell: IS_WIN, stdio: "inherit", env: loginEnv,
    });

    ok(`Kubeconfig for '${cluster}' saved at ${configFile}`);
  }

  console.log("\nTo combine configs, set in your shell profile:");
  const sep = IS_WIN ? ";" : ":";
  const prefix = IS_WIN ? "set" : "export";
  console.log(`  ${prefix} KUBECONFIG=${join(KUBE_DIR, "config.staging")}${sep}${join(KUBE_DIR, "config.prod")}`);
}

async function kanopyLogin() {
  console.log("\n  1. staging\n  2. prod\n  3. both");
  const input = await ask("Which cluster to login? ");
  const clusters = input === "2" ? ["prod"] : input === "3" ? ["staging", "prod"] : ["staging"];

  for (const cluster of clusters as ClusterEnv[]) {
    const cfg = kubeconfigPath(cluster);
    // A kubeconfig can exist yet have lost its contexts, and then login succeeds while nothing authenticates.
    if (!ensureKubeconfig(cluster)) continue;

    // kanopy-oidc kube login authenticates the kubeconfig's current-context, so pin it first.
    action(`Selecting context '${contextName(apiServerOf(cluster))}' in ${cfg}`);
    if (!pinContext(cluster)) continue;

    action(`Logging in with config: ${cfg}`);
    const result = spawnSync("kanopy-oidc", ["kube", "login"], { shell: IS_WIN, stdio: "inherit", env: kubeEnv(cluster) });
    if (result.status !== 0) { fail(`Login failed for ${cluster}`); continue; }
    // Login exiting 0 is not proof of a usable token, so confirm against the API server.
    tokenIsValid(cluster)
      ? ok(`Login successful for ${cluster}`)
      : fail(`Login reported success for ${cluster} but the token is not accepted. Retry option 7 for ${cluster} alone.`);
  }

  // Follow the last cluster logged in, so the next command reads the cluster just authenticated.
  TARGET = (clusters[clusters.length - 1] as ClusterEnv) ?? TARGET;
  ok(`Target cluster: ${TARGET}`);
}

async function switchContext() {
  const target = await selectTarget("Context");
  if (!pinContext(target)) return;
  TARGET = target;
  ok(`Switched to ${apiServerOf(target)} / ${IST_NAMESPACE}`);
}

async function verifyAccess() {
  action(`Verifying cluster access (${TARGET})...`);
  const result = spawnSync("kubectl", ["get", "pods", "-n", IST_NAMESPACE], { shell: IS_WIN, stdio: "inherit", env: kubeEnv() });
  result.status === 0 ? ok(`Access verified (${TARGET}).`) : fail(`Access failed for ${TARGET}. Try option 7 (login) for ${TARGET}.`);
}

// ============================================================
//  3. SECRETS
// ============================================================

function kubeEnv(env: ClusterEnv = TARGET): NodeJS.ProcessEnv {
  return { ...process.env, KUBECONFIG: kubeconfigPath(env) };
}

// Pin context + namespace inside a single kubeconfig, never a merged one, so the file stays usable
// on its own (a merged write leaves the other file without a current-context).
function pinContext(env: ClusterEnv): boolean {
  const target = { ...process.env, KUBECONFIG: kubeconfigPath(env) };
  const ctx = contextName(apiServerOf(env));
  if (spawnSync("kubectl", ["config", "use-context", ctx], { shell: IS_WIN, stdio: "pipe", env: target }).status !== 0) {
    warn(`Context '${ctx}' not found in ${kubeconfigPath(env)}. Regenerate it with option 6.`);
    return false;
  }
  // An unpinned namespace would send Helm and kubectl to `default` while everything looks fine.
  const ns = spawnSync("kubectl", ["config", "set-context", "--current", `--namespace=${IST_NAMESPACE}`], {
    shell: IS_WIN, stdio: "pipe", env: target,
  });
  if (ns.status !== 0) {
    fail(`Could not pin namespace '${IST_NAMESPACE}' in ${kubeconfigPath(env)}: ${(ns.stderr ?? "").toString().trim()}`);
    return false;
  }
  return true;
}

// Rebuild the kubeconfig when the file is missing or no longer declares the cluster's context.
function ensureKubeconfig(env: ClusterEnv): boolean {
  const cfg = kubeconfigPath(env);
  const ctx = contextName(apiServerOf(env));
  const listed = spawnSync("kubectl", ["config", "get-contexts", "-o", "name"], {
    shell: IS_WIN, encoding: "utf-8", env: { ...process.env, KUBECONFIG: cfg },
  });
  if (existsSync(cfg) && (listed.stdout ?? "").split(/\r?\n/).map((l) => l.trim()).includes(ctx)) return true;

  warn(`${cfg} does not declare context '${ctx}', regenerating it.`);
  try {
    if (!existsSync(KUBE_DIR)) mkdirSync(KUBE_DIR, { recursive: true });
    const output = execSync(`kanopy-oidc kube setup ${env}`, { encoding: "utf-8", env: { ...process.env, KUBECONFIG: cfg } });
    writeFileSync(cfg, output, "utf-8");
    ok(`Kubeconfig regenerated at ${cfg}`);
    return true;
  } catch (e: any) {
    fail(`Could not regenerate ${cfg}: ${e.message}`);
    return false;
  }
}

// A token can be expired even when login reported success, so check it against the API server.
function tokenIsValid(env: ClusterEnv): boolean {
  return spawnSync("kubectl", ["get", "namespace", IST_NAMESPACE, "-o", "name"], {
    shell: IS_WIN, stdio: "pipe", env: kubeEnv(env),
  }).status === 0;
}

// Printed by every cluster command: which cluster the output belongs to is never a guess.
function targetBanner() {
  console.log(`${DIM}[cluster] ${TARGET} (${apiServerOf(TARGET)}) ns=${IST_NAMESPACE}${NC}`);
}

async function selectTarget(prompt = "Target cluster"): Promise<ClusterEnv> {
  console.log(`\n  1. staging (current: ${TARGET})\n  2. prod`);
  const input = await ask(`${prompt}: `);
  return input === "2" ? "prod" : "staging";
}

const KSEC_EXCLUDE_PREFIXES = ["KUBE_"];

async function createSecrets() {
  console.log("\nCreate ksec secrets for which environment?");
  console.log("  1. staging (default)\n  2. production");
  const input = await ask("Choice: ");
  const chosen: ClusterEnv = input === "2" ? "prod" : "staging";
  const secretName = chosen === "prod" ? KSEC_SECRET_PROD : KSEC_SECRET_STAGING;

  // The secret is pushed to the cluster chosen here, not to the current target.
  action(`Using ${chosen} (${apiServerOf(chosen)})...`);
  if (!pinContext(chosen)) return;
  const env = kubeEnv(chosen);

  if (!existsSync(ENV_PATH)) { fail(`.env not found at ${ENV_PATH}`); return; }

  const filtered = readFileSync(ENV_PATH, "utf-8")
    .split(/\r?\n/)
    .filter((line) => {
      const trimmed = line.trim();
      if (!trimmed || /^[#;]/.test(trimmed)) return false;
      const eq = trimmed.indexOf("=");
      if (eq === -1) return false;
      const key = trimmed.slice(0, eq).trim();
      if (!key) return false;
      return !KSEC_EXCLUDE_PREFIXES.some((p) => key.startsWith(p));
    })
    .join("\n");

  const tmpPath = join(PROJECT_ROOT, ".env.ksec.tmp");
  writeFileSync(tmpPath, filtered, "utf-8");

  const excluded = KSEC_EXCLUDE_PREFIXES.map((p) => `${p}*`).join(", ");
  console.log(`\nPushing .env to secret '${secretName}' (excluding ${excluded})...`);
  console.log(`  Source: ${ENV_PATH}\n`);

  const cmd = `helm ksec push "${tmpPath}" ${secretName}`;
  console.log(`${DIM}[cmd]    ${cmd}${NC}`);
  const result = spawnSync(cmd, { shell: true, stdio: "inherit", env });

  try { require("fs").unlinkSync(tmpPath); } catch { /* cleanup best-effort */ }

  result.status === 0 ? ok(`Secret '${secretName}' updated from .env`) : fail("Failed to push secret.");
}

async function listSecrets() {
  targetBanner();
  action("Listing ksec secrets in current context...");
  spawnSync("helm", ["ksec", "list"], { shell: IS_WIN, stdio: "inherit", env: kubeEnv() });
}

async function getSecret() {
  targetBanner();
  console.log(`\n  Known secrets:`);
  console.log(`    - ${KSEC_SECRET_STAGING} (staging)`);
  console.log(`    - ${KSEC_SECRET_PROD} (production)\n`);
  const name = (await ask(`Secret name (default: ${KSEC_SECRET_STAGING}): `)) || KSEC_SECRET_STAGING;
  spawnSync("helm", ["ksec", "get", name], { shell: IS_WIN, stdio: "inherit", env: kubeEnv() });
}

async function manageSecretKeys() {
  console.log(`\n${CYAN}=== Manage ksec secret keys ===${NC}\n`);
  console.log("  1. staging (default)\n  2. production");
  const envInput = await ask("Environment: ");
  const chosen: ClusterEnv = envInput === "2" ? "prod" : "staging";
  const secretName = chosen === "prod" ? KSEC_SECRET_PROD : KSEC_SECRET_STAGING;

  // Keys are edited on the cluster chosen here, not on the current target.
  action(`Using ${chosen} (${apiServerOf(chosen)})...`);
  if (!pinContext(chosen)) return;
  const env = kubeEnv(chosen);

  console.log(`\n  Secret: ${CYAN}${secretName}${NC}\n`);
  console.log("  1. Set/overwrite a key");
  console.log("  2. Delete a key");
  console.log("  3. Delete entire secret\n");
  const opInput = await ask("Operation: ");

  if (opInput === "1") {
    const key = await ask("Key name: ");
    if (!key) { warn("Key is required."); return; }
    const value = await ask("Value: ");
    if (!value) { warn("Value is required."); return; }
    const cmd = `helm ksec set ${secretName} ${key}="${value}"`;
    console.log(`${DIM}[cmd]    ${cmd}${NC}`);
    const result = spawnSync(cmd, { shell: true, stdio: "inherit", env });
    result.status === 0 ? ok(`Key '${key}' set in ${secretName}`) : fail("Failed to set key.");
  } else if (opInput === "2") {
    const key = await ask("Key to delete: ");
    if (!key) { warn("Key is required."); return; }
    const confirm = await ask(`Delete '${key}' from ${secretName}? (y/N): `);
    if (confirm.toLowerCase() !== "y") { warn("Aborted."); return; }
    const cmd = `helm ksec unset ${secretName} ${key}`;
    console.log(`${DIM}[cmd]    ${cmd}${NC}`);
    const result = spawnSync(cmd, { shell: true, stdio: "inherit", env });
    result.status === 0 ? ok(`Key '${key}' deleted from ${secretName}`) : fail("Failed to delete key.");
  } else if (opInput === "3") {
    const confirm = await ask(`${RED}Delete ENTIRE secret '${secretName}'?${NC} (type secret name to confirm): `);
    if (confirm !== secretName) { warn("Aborted — name did not match."); return; }
    const cmd = `helm ksec delete ${secretName}`;
    console.log(`${DIM}[cmd]    ${cmd}${NC}`);
    const result = spawnSync(cmd, { shell: true, stdio: ["pipe", "inherit", "inherit"], input: "y\n", env });
    result.status === 0 ? ok(`Secret '${secretName}' deleted. Use option 10 to recreate from .env.`) : fail("Failed to delete secret.");
  } else {
    warn("Invalid option.");
  }
}

// ============================================================
//  4. DEPLOYMENT
// ============================================================

// List all pods in the namespace (backend, frontend AND merchant). A label selector like
// `app.kubernetes.io/instance in (a,b)` contains spaces/parens that the Windows shell mangles under
// spawnSync (shell: IS_WIN) and it also silently excluded the merchant — so list them all with -o wide.
async function getPods() {
  targetBanner();
  spawnSync("kubectl", ["get", "pods", "-n", IST_NAMESPACE, "-o", "wide"], { shell: IS_WIN, stdio: "inherit", env: kubeEnv() });
}

async function getAll() {
  targetBanner();
  const env = kubeEnv();
  console.log("--- Pods ---");
  spawnSync("kubectl", ["get", "pods", "-n", IST_NAMESPACE, "-o", "wide"], { shell: IS_WIN, stdio: "inherit", env });
  console.log("\n--- Deployments ---");
  spawnSync("kubectl", ["get", "deployments", "-n", IST_NAMESPACE], { shell: IS_WIN, stdio: "inherit", env });
  console.log("\n--- Services ---");
  spawnSync("kubectl", ["get", "services", "-n", IST_NAMESPACE], { shell: IS_WIN, stdio: "inherit", env });
  console.log("\n--- Ingress ---");
  spawnSync("kubectl", ["get", "ingress", "-n", IST_NAMESPACE], { shell: IS_WIN, stdio: "inherit", env });
}

async function podLogs() {
  targetBanner();
  // Custom covers anything not fixed here (e.g. the merchant, which isn't always deployed, or any
  // pod visible under option 14) — enter its exact pod name.
  console.log("\n  1. backend\n  2. frontend\n  3. bankcore\n  4. custom (enter a pod name)");
  const input = await ask("Which service? ");
  if (!["1", "2", "3", "4"].includes(input)) { warn(`Invalid choice "${input}". Choose 1-4.`); return; }
  const tail = (await ask("Lines to show (default: 50): ")) || "50";
  const env = kubeEnv();

  if (input === "4") {
    const entered = (await ask("Pod or deployment name: ")).trim();
    if (!entered) { warn("No name given."); return; }
    // kubectl logs needs a real POD name. Accept a deployment/release name too: if the entry isn't an
    // exact pod, resolve the NEWEST pod whose name starts with it (pod = <deployment>-<hash>-<hash>).
    // --sort-by=.metadata.creationTimestamp gives true chronological order (a lexicographic sort of the
    // random hash suffix would NOT). `-o name` + that flag avoid braces/spaces → safe under the Windows shell.
    const list = spawnSync("kubectl", ["get", "pods", "-n", IST_NAMESPACE, "--sort-by=.metadata.creationTimestamp", "-o", "name"], { shell: IS_WIN, encoding: "utf-8", env });
    const names = (list.stdout || "").split(/\r?\n/).map((l) => l.replace(/^pod\//, "").trim()).filter(Boolean);
    let pod = entered;
    if (!names.includes(entered)) {
      const matches = names.filter((n) => n.startsWith(entered)); // preserve creation order (oldest→newest)
      if (matches.length === 0) { warn(`No pod found matching "${entered}" in ${IST_NAMESPACE}.`); return; }
      pod = matches[matches.length - 1]; // newest
      console.log(`${DIM}[resolved] ${entered} -> ${pod}${NC}`);
    }
    // --previous shows the last crashed instance (useful for CrashLoopBackOff).
    const prev = (await ask("Show the CRASHED (previous) container's logs instead of the current one? Use this for CrashLoopBackOff. [y/N]: ")).trim().toLowerCase() === "y";
    const args = ["logs", pod, "-n", IST_NAMESPACE, `--tail=${tail}`, "--all-containers"];
    if (prev) args.push("--previous");
    spawnSync("kubectl", args, { shell: IS_WIN, stdio: "inherit", env });
    return;
  }

  const release = input === "2" ? RELEASE_FRONTEND : input === "3" ? RELEASE_BANKCORE : RELEASE_BACKEND;
  spawnSync("kubectl", ["logs", "-l", `app.kubernetes.io/instance=${release}`, "-n", IST_NAMESPACE, `--tail=${tail}`, "--all-containers"], { shell: IS_WIN, stdio: "inherit", env });
}

async function helmStatus() {
  targetBanner();
  const env = kubeEnv();
  console.log("--- Backend ---");
  spawnSync("helm", ["status", RELEASE_BACKEND, "-n", IST_NAMESPACE], { shell: IS_WIN, stdio: "inherit", env });
  console.log("\n--- Frontend ---");
  spawnSync("helm", ["status", RELEASE_FRONTEND, "-n", IST_NAMESPACE], { shell: IS_WIN, stdio: "inherit", env });
  console.log("\n--- Bankcore (private, no ingress) ---");
  spawnSync("helm", ["status", RELEASE_BANKCORE, "-n", IST_NAMESPACE], { shell: IS_WIN, stdio: "inherit", env });
}

async function rolloutRestart() {
  targetBanner();
  console.log("\n  1. backend\n  2. frontend\n  3. merchant\n  4. bankcore\n  5. all");
  const input = await ask("Restart which? ");
  if (!["1", "2", "3", "4", "5"].includes(input)) { warn(`Invalid choice "${input}". Choose 1-5.`); return; }
  // Must run with KUBECONFIG pointing at the staging/prod configs (kubeEnv), otherwise kubectl hits
  // the default/wrong context. run()/execSync does not set it, so use spawnSync with env: kubeEnv().
  const env = kubeEnv();
  const restart = (release: string) =>
    spawnSync("kubectl", ["rollout", "restart", "deployment", `${release}-web-app`, "-n", IST_NAMESPACE], { shell: IS_WIN, stdio: "inherit", env });
  if (input === "1" || input === "5") restart(RELEASE_BACKEND);
  if (input === "2" || input === "5") restart(RELEASE_FRONTEND);
  if (input === "3" || input === "5") restart(RELEASE_MERCHANT);
  if (input === "4" || input === "5") restart(RELEASE_BANKCORE);
  ok("Rollout restart initiated.");
}

async function resourceUsage() {
  targetBanner();
  spawnSync("kubectl", ["top", "pods", "-n", IST_NAMESPACE, "--containers"], { shell: IS_WIN, stdio: "inherit", env: kubeEnv() });
}

// ============================================================
//  5. DRONE CI
// ============================================================

function getDroneRepo(): string {
  try {
    const remote = execSync("git remote get-url origin", { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] }).trim();
    const match = remote.match(/[:/]([^/]+\/[^/]+?)(?:\.git)?$/);
    if (match) return match[1];
  } catch { /* fallback below */ }
  return `mongodb-industry-solutions/${DEMO_NAME}`;
}

function decodeB64(raw: string): string {
  const cleaned = raw.replace(/"/g, "").trim();
  if (!cleaned) return "";
  return Buffer.from(cleaned, "base64").toString("utf-8").trim();
}

async function extractDroneSecrets() {
  console.log(`\n${CYAN}=== Extract Drone secrets (view only) ===${NC}\n`);
  // Drone reads the infra tokens from staging, whatever the current target.
  action("Using staging for the cluster tokens...");
  if (!pinContext("staging")) return;
  const env = kubeEnv("staging");

  console.log("\n--- staging_kubernetes_token ---");
  const stagingToken = runCapture(`kubectl get secret ${CICD_TOKEN_SECRET} -o jsonpath="{.data.token}" --kubeconfig="${join(KUBE_DIR, "config.staging")}"`);
  if (stagingToken.stdout) {
    const decoded = decodeB64(stagingToken.stdout);
    console.log(`  Value: ${DIM}${decoded.substring(0, 20)}...${NC}`);
  } else { warn("Could not extract staging token."); }

  console.log("\n--- ecr_access_key ---");
  const ecrAccess = runCapture(`kubectl get secret ${ECR_SECRET_NAME} -o jsonpath="{.data.ecr_access_key}" --kubeconfig="${join(KUBE_DIR, "config.staging")}"`);
  if (ecrAccess.stdout) {
    console.log(`  Value: ${decodeB64(ecrAccess.stdout)}`);
  } else { warn("Could not extract ECR access key."); }

  console.log("\n--- ecr_secret_key ---");
  const ecrSecret = runCapture(`kubectl get secret ${ECR_SECRET_NAME} -o jsonpath="{.data.ecr_secret_key}" --kubeconfig="${join(KUBE_DIR, "config.staging")}"`);
  if (ecrSecret.stdout) {
    const decoded = decodeB64(ecrSecret.stdout);
    console.log(`  Value: ${DIM}${decoded.substring(0, 10)}...${NC}`);
  } else { warn("Could not extract ECR secret key."); }

  action("Switching to prod context...");
  console.log("\n--- prod_kubernetes_token ---");
  const prodToken = runCapture(`kubectl get secret ${CICD_TOKEN_SECRET} -o jsonpath="{.data.token}" --kubeconfig="${join(KUBE_DIR, "config.prod")}"`);
  if (prodToken.stdout) {
    const decoded = decodeB64(prodToken.stdout);
    console.log(`  Value: ${DIM}${decoded.substring(0, 20)}...${NC}`);
  } else { warn("Could not extract prod token."); }

  console.log(`\n${CYAN}To push these automatically, use option 20 (Configure Drone secrets).${NC}`);
}

async function configureDroneSecrets() {
  console.log(`\n${CYAN}=== Configure Drone CI secrets ===${NC}\n`);

  if (!hasCommand("drone")) {
    fail("drone CLI not found. Install it from: https://docs.drone.io/cli/install/");
    console.log("  After installing, set DRONE_SERVER and DRONE_TOKEN in your .env or shell:");
    console.log(`  DRONE_SERVER=${DRONE_URL}`);
    console.log("  DRONE_TOKEN=<your personal token from Drone UI → User Settings>");
    return;
  }

  const repo = getDroneRepo();
  console.log(`  Drone repo: ${CYAN}${repo}${NC}`);
  console.log(`  Drone URL:  ${DRONE_URL}\n`);

  // ── 1. Cluster secrets (4 infra tokens) ──────────────────────
  action("Extracting cluster secrets...\n");
  // Same as the extract flow: the cluster tokens live in staging.
  if (!pinContext("staging")) return;
  const env = kubeEnv("staging");
  const clusterSecrets: Array<{ name: string; value: string }> = [];

  const stagingToken = decodeB64(runCapture(`kubectl get secret ${CICD_TOKEN_SECRET} -o jsonpath="{.data.token}" --kubeconfig="${join(KUBE_DIR, "config.staging")}"`).stdout);
  if (stagingToken) clusterSecrets.push({ name: "staging_kubernetes_token", value: stagingToken });
  else warn("Could not extract staging_kubernetes_token");

  const ecrAccess = decodeB64(runCapture(`kubectl get secret ${ECR_SECRET_NAME} -o jsonpath="{.data.ecr_access_key}" --kubeconfig="${join(KUBE_DIR, "config.staging")}"`).stdout);
  if (ecrAccess) clusterSecrets.push({ name: "ecr_access_key", value: ecrAccess });
  else warn("Could not extract ecr_access_key");

  const ecrSecret = decodeB64(runCapture(`kubectl get secret ${ECR_SECRET_NAME} -o jsonpath="{.data.ecr_secret_key}" --kubeconfig="${join(KUBE_DIR, "config.staging")}"`).stdout);
  if (ecrSecret) clusterSecrets.push({ name: "ecr_secret_key", value: ecrSecret });
  else warn("Could not extract ecr_secret_key");

  const prodToken = decodeB64(runCapture(`kubectl get secret ${CICD_TOKEN_SECRET} -o jsonpath="{.data.token}" --kubeconfig="${join(KUBE_DIR, "config.prod")}"`).stdout);
  if (prodToken) clusterSecrets.push({ name: "prod_kubernetes_token", value: prodToken });
  else warn("Could not extract prod_kubernetes_token");

  // ── Summary before push ──────────────────────────────────────
  // Only CI/CD infra secrets belong in Drone. App secrets reach the pod via ksec
  // (option 10) and the envSecrets section in environments/*.yaml.
  console.log(`\n${CYAN}Secrets to configure:${NC}\n`);
  for (const s of clusterSecrets) {
    console.log(`    ${GREEN}+${NC} ${s.name}  ${DIM}(${s.value.substring(0, 12)}...)${NC}`);
  }

  if (clusterSecrets.length === 0) { warn("No secrets to push."); return; }

  console.log("");
  const confirm = await ask(`Push ${clusterSecrets.length} secrets to ${repo}? (y/N): `);
  if (confirm.toLowerCase() !== "y") { warn("Aborted."); return; }

  // ── 2. Push ─────────────────────────────────────────────────
  let pushed = 0, failed_count = 0;
  const droneEnv = { ...process.env, DRONE_SERVER: process.env.DRONE_SERVER || DRONE_URL };

  for (const s of clusterSecrets) {
    const result = spawnSync("drone", ["secret", "add", "--repository", repo, "--name", s.name, "--data", s.value], {
      shell: IS_WIN, encoding: "utf-8", stdio: "pipe", env: droneEnv,
    });
    if (result.status === 0) {
      console.log(`  ${GREEN}[ok]${NC} ${s.name}`);
      pushed++;
    } else {
      const err = (result.stderr || result.stdout || "").trim();
      // "update" means the secret exists — try drone secret update instead
      if (err.includes("exists") || err.includes("update")) {
        const upd = spawnSync("drone", ["secret", "update", "--repository", repo, "--name", s.name, "--data", s.value], {
          shell: IS_WIN, encoding: "utf-8", stdio: "pipe", env: droneEnv,
        });
        if (upd.status === 0) {
          console.log(`  ${GREEN}[ok]${NC} ${s.name} (updated)`);
          pushed++;
        } else {
          console.log(`  ${RED}[fail]${NC} ${s.name}: ${(upd.stderr || upd.stdout || "").trim()}`);
          failed_count++;
        }
      } else {
        console.log(`  ${RED}[fail]${NC} ${s.name}: ${err}`);
        failed_count++;
      }
    }
  }

  console.log(`\n  ${pushed} pushed, ${failed_count} failed.`);
  if (failed_count === 0) ok(`All ${pushed} secrets configured in Drone.`);
  else warn("Some secrets failed. Check DRONE_TOKEN is set and valid.");
}

async function showDroneInfo() {
  console.log(`\n${CYAN}=== Drone CI Info ===${NC}\n`);
  console.log(`  Drone URL: ${DRONE_URL}`);
  console.log("\n  Pipeline triggers:");
  console.log("    staging    -> push to 'staging' branch");
  console.log("    production -> push to 'main' branch");
  console.log("\n  Required Drone secrets:");
  console.log("    - staging_kubernetes_token");
  console.log("    - prod_kubernetes_token");
  console.log("    - ecr_access_key");
  console.log("    - ecr_secret_key");
  console.log(`\n  ECR repositories:`);
  console.log(`    - ${ECR_REGISTRY}/${IST_NAMESPACE}/${DEMO_NAME}-backend`);
  console.log(`    - ${ECR_REGISTRY}/${IST_NAMESPACE}/${DEMO_NAME}-frontend`);
  console.log(`\n  Staging URLs:`);
  console.log(`    Backend:  https://${STAGING_HOST_BE}`);
  console.log(`    Frontend: https://${STAGING_HOST_FE}`);
  console.log(`\n  Production URLs:`);
  console.log(`    Backend:  https://${PROD_HOST_BE}`);
  console.log(`    Frontend: https://${PROD_HOST_FE}`);
}

// ============================================================
//  6. DIAGNOSTICS
// ============================================================

async function describePod() {
  targetBanner();
  const env = kubeEnv();
  let podName = await ask("Pod name (Enter to list): ");
  if (!podName) {
    spawnSync("kubectl", ["get", "pods", "-n", IST_NAMESPACE, "-o", "name"], { shell: IS_WIN, stdio: "inherit", env });
    podName = await ask("\nPod name: ");
  }
  if (podName) spawnSync("kubectl", ["describe", "pod", podName, "-n", IST_NAMESPACE], { shell: IS_WIN, stdio: "inherit", env });
}

async function execIntoPod() {
  targetBanner();
  console.log("\n  1. backend\n  2. frontend\n  3. merchant\n  4. bankcore");
  const input = await ask("Which service? ");
  if (!["1", "2", "3", "4"].includes(input)) { warn(`Invalid choice "${input}". Choose 1-4.`); return; }
  const release = input === "2" ? RELEASE_FRONTEND
    : input === "3" ? RELEASE_MERCHANT
      : input === "4" ? RELEASE_BANKCORE : RELEASE_BACKEND;
  const deployment = `${release}-web-app`;
  console.log(`${DIM}[cmd]    kubectl exec -it deployment/${deployment} -n ${IST_NAMESPACE} -- sh${NC}`);
  spawnSync("kubectl", ["exec", "-it", `deployment/${deployment}`, "-n", IST_NAMESPACE, "--", "sh"], { shell: IS_WIN, stdio: "inherit", env: kubeEnv() });
}

async function checkEnvVars() {
  targetBanner();
  console.log("\n  1. backend\n  2. frontend\n  3. merchant\n  4. bankcore");
  const input = await ask("Which service? ");
  if (!["1", "2", "3", "4"].includes(input)) { warn(`Invalid choice "${input}". Choose 1-4.`); return; }
  const release = input === "2" ? RELEASE_FRONTEND
    : input === "3" ? RELEASE_MERCHANT
      : input === "4" ? RELEASE_BANKCORE : RELEASE_BACKEND;
  const deployment = `${release}-web-app`;
  spawnSync("kubectl", ["exec", `deployment/${deployment}`, "-n", IST_NAMESPACE, "--", "env"], { shell: IS_WIN, stdio: "inherit", env: kubeEnv() });
}

async function getIngress() {
  targetBanner();
  spawnSync("kubectl", ["get", "ingress", "-n", IST_NAMESPACE], { shell: IS_WIN, stdio: "inherit", env: kubeEnv() });
}

async function describeIngress() {
  targetBanner();
  const env = kubeEnv();
  const result = spawnSync("kubectl", ["get", "ingress", "-n", IST_NAMESPACE, "-o", "name"], { shell: IS_WIN, encoding: "utf-8", env });
  const names = (result.stdout || "").split(/\r?\n/).filter(Boolean);
  if (names.length === 0) { warn("No ingress resources found."); return; }

  console.log("\nAvailable ingress resources:");
  names.forEach((n, i) => console.log(`  ${i + 1}. ${n}`));
  console.log(`  ${names.length + 1}. All`);

  const input = await ask("Which ingress to describe? ");
  const idx = parseInt(input, 10) - 1;

  if (input === String(names.length + 1) || input.toLowerCase() === "all") {
    for (const n of names) {
      console.log(`\n--- ${n} ---`);
      spawnSync("kubectl", ["describe", n, "-n", IST_NAMESPACE], { shell: IS_WIN, stdio: "inherit", env });
    }
  } else if (idx >= 0 && idx < names.length) {
    spawnSync("kubectl", ["describe", names[idx], "-n", IST_NAMESPACE], { shell: IS_WIN, stdio: "inherit", env });
  } else {
    warn("Invalid selection.");
  }
}

async function helmGetValues() {
  targetBanner();
  console.log("\n  1. backend\n  2. frontend\n  3. both");
  const input = await ask("Which release? ");
  const env = kubeEnv();

  const releases = input === "1" ? [RELEASE_BACKEND]
    : input === "2" ? [RELEASE_FRONTEND]
    : [RELEASE_BACKEND, RELEASE_FRONTEND];

  for (const release of releases) {
    console.log(`\n${CYAN}--- ${release} ---${NC}`);
    spawnSync("helm", ["get", "values", release, "-n", IST_NAMESPACE], { shell: IS_WIN, stdio: "inherit", env });
  }
}

async function testUrls() {
  const env = kubeEnv();
  const ctx = spawnSync("kubectl", ["config", "current-context"], { shell: IS_WIN, encoding: "utf-8", env }).stdout.trim();
  const isStaging = ctx.includes("staging");
  const bUrl = `https://${isStaging ? STAGING_HOST_BE : PROD_HOST_BE}/health`;
  const fUrl = `https://${isStaging ? STAGING_HOST_FE : PROD_HOST_FE}`;

  console.log(`  Testing backend health: ${bUrl}`);
  try {
    const resp = await fetch(bUrl, { signal: AbortSignal.timeout(10000) });
    resp.ok ? ok(`Backend: ${resp.status}`) : warn(`Backend: HTTP ${resp.status}`);
  } catch (e: any) { warn(`Backend unreachable: ${e.message}`); }

  console.log(`  Testing frontend: ${fUrl}`);
  try {
    const resp = await fetch(fUrl, { signal: AbortSignal.timeout(10000) });
    resp.ok ? ok(`Frontend: ${resp.status}`) : warn(`Frontend: HTTP ${resp.status}`);
  } catch (e: any) { warn(`Frontend unreachable: ${e.message}`); }
}

// ============================================================
//  7. PRE-DEPLOYMENT CHECKLIST
// ============================================================

async function preDeployChecklist() {
  console.log(`\n${CYAN}=== Pre-Deployment Checklist ===${NC}\n`);
  let passed = 0, failed = 0;

  function check(label: string, condition: boolean) {
    if (condition) { console.log(`  ${GREEN}[PASS]${NC} ${label}`); passed++; }
    else { console.log(`  ${RED}[FAIL]${NC} ${label}`); failed++; }
  }

  check("kubectl installed", hasCommand("kubectl"));
  check("helm installed", hasCommand("helm"));
  check("kanopy-oidc installed", hasCommand("kanopy-oidc"));
  check("ksec plugin installed", runCapture("helm plugin list").stdout.includes("ksec"));
  check("Kanopy config exists", existsSync(KANOPY_CONFIG_PATH));
  check("Staging kubeconfig exists", existsSync(join(KUBE_DIR, "config.staging")));
  check("Production kubeconfig exists", existsSync(join(KUBE_DIR, "config.prod")));
  check(".drone.yml exists", existsSync(join(PROJECT_ROOT, ".drone.yml")));
  check("environments/staging.yaml", existsSync(join(PROJECT_ROOT, "environments", "staging.yaml")));
  check("environments/production.yaml", existsSync(join(PROJECT_ROOT, "environments", "production.yaml")));
  check("psp/backend/Dockerfile exists", existsSync(join(PROJECT_ROOT, "psp/backend", "Dockerfile")));
  check("psp/frontend/Dockerfile exists", existsSync(join(PROJECT_ROOT, "psp/frontend", "Dockerfile")));
  check("bank/backend/Dockerfile exists", existsSync(join(PROJECT_ROOT, "bank/backend", "Dockerfile")));

  const color = failed === 0 ? GREEN : YELLOW;
  console.log(`\n  ${color}Result: ${passed} passed, ${failed} failed${NC}`);
}

// ============================================================
//  8. FULL DEPLOY SETUP (per environment)
// ============================================================

async function deployEnvSetup() {
  console.log(`\n${CYAN}=== Full Deploy Setup ===${NC}\n`);
  console.log("  1. staging");
  console.log("  2. production");
  const input = await ask("Target environment: ");
  const isProd = input === "2";
  const envLabel = isProd ? "production" : "staging";
  const apiServer = isProd ? PROD_API : STAGING_API;
  const secretName = isProd ? KSEC_SECRET_PROD : KSEC_SECRET_STAGING;
  const configFile = join(KUBE_DIR, `config.${isProd ? "prod" : "staging"}`);
  const envYaml = join(PROJECT_ROOT, "environments", `${isProd ? "production" : "staging"}.yaml`);

  let passed = 0;
  let failed = 0;
  const step = (label: string, ok: boolean) => {
    if (ok) { console.log(`  ${GREEN}[OK]${NC}   ${label}`); passed++; }
    else { console.log(`  ${RED}[FAIL]${NC} ${label}`); failed++; }
  };

  console.log(`\n${CYAN}Target: ${envLabel}${NC}\n`);

  // ── Phase 1: Prerequisites ────────────────────────────────
  console.log(`${CYAN}── 1. Prerequisites ──${NC}\n`);

  step("kubectl installed", hasCommand("kubectl"));
  step("helm installed", hasCommand("helm"));
  step("kanopy-oidc installed", hasCommand("kanopy-oidc"));
  step("ksec plugin installed", runCapture("helm plugin list").stdout.includes("ksec"));

  if (!hasCommand("kubectl") || !hasCommand("helm") || !hasCommand("kanopy-oidc")) {
    console.log(`\n  ${YELLOW}Missing prerequisites. Run option 1 (Full setup) first.${NC}`);
    const fix = await ask("  Run full setup now? (y/N): ");
    if (fix.toLowerCase() === "y") {
      await fullSetup();
    } else {
      warn("Cannot continue without prerequisites."); return;
    }
  }

  // ── Phase 2: Kanopy config ────────────────────────────────
  console.log(`\n${CYAN}── 2. Kanopy config ──${NC}\n`);

  if (existsSync(KANOPY_CONFIG_PATH)) {
    step("Kanopy config exists", true);
  } else {
    step("Kanopy config exists", false);
    const fix = await ask("  Create kanopy config now? (y/N): ");
    if (fix.toLowerCase() === "y") await createKanopyConfig();
  }

  // ── Phase 3: Kubeconfig + login ───────────────────────────
  console.log(`\n${CYAN}── 3. Kubeconfig (${envLabel}) ──${NC}\n`);

  if (existsSync(configFile)) {
    step(`Kubeconfig exists: ${configFile}`, true);
  } else {
    step(`Kubeconfig exists: ${configFile}`, false);
    console.log(`  ${YELLOW}Generating kubeconfig for ${envLabel}...${NC}\n`);
    const setupCmd = `kanopy-oidc kube setup ${isProd ? "prod" : "staging"}`;
    try {
      if (!existsSync(KUBE_DIR)) mkdirSync(KUBE_DIR, { recursive: true });
      const output = execSync(setupCmd, { encoding: "utf-8", env: { ...process.env, KUBECONFIG: configFile } });
      writeFileSync(configFile, output, "utf-8");
      ok(`Kubeconfig saved at ${configFile}`);
    } catch (e: any) {
      fail(`Failed: ${e.message}`); return;
    }
  }

  // Login
  action(`Authenticating to ${envLabel}...`);
  const loginEnv = { ...process.env, KUBECONFIG: configFile };
  const ctxResult = spawnSync("kubectl", ["config", "use-context", contextName(apiServer)], { shell: IS_WIN, stdio: "pipe", env: loginEnv });
  if (ctxResult.status !== 0) {
    warn(`Could not select context "${contextName(apiServer)}" (it may not exist yet). Continuing to login, which can create it.`);
  }
  const loginResult = spawnSync("kanopy-oidc", ["kube", "login"], {
    shell: IS_WIN, stdio: "inherit", env: loginEnv,
  });
  step(`Login to ${envLabel}`, loginResult.status === 0);
  if (loginResult.status !== 0) {
    warn("Login failed. Check your credentials and retry.");
    return;
  }

  // Follow the environment being deployed for the rest of the checklist.
  TARGET = isProd ? "prod" : "staging";
  if (!pinContext(TARGET)) { fail(`Cannot target ${TARGET}: fix the kubeconfig (option 6) and retry.`); return; }
  const env = kubeEnv();

  // ── Phase 4: Verify cluster access ────────────────────────
  console.log(`\n${CYAN}── 4. Cluster access ──${NC}\n`);

  const accessResult = spawnSync("kubectl", ["get", "pods", "-n", IST_NAMESPACE, "--no-headers"], {
    shell: IS_WIN, stdio: "pipe", env, encoding: "utf-8",
  });
  step(`Access to namespace '${IST_NAMESPACE}'`, accessResult.status === 0);
  if (accessResult.status !== 0) {
    fail("Cannot access the cluster. Check VPN, token, or namespace permissions.");
    return;
  }

  // ── Phase 5: Secrets ──────────────────────────────────────
  console.log(`\n${CYAN}── 5. Secrets (${secretName}) ──${NC}\n`);

  const secretCheck = spawnSync("helm", ["ksec", "get", secretName], {
    shell: IS_WIN, stdio: "pipe", env, encoding: "utf-8",
  });
  const secretExists = secretCheck.status === 0 && (secretCheck.stdout as string).trim().length > 0;

  if (secretExists) {
    step(`ksec secret '${secretName}' exists`, true);
    const keys = (secretCheck.stdout as string).trim().split("\n").length;
    console.log(`  ${DIM}  ${keys} key(s) found${NC}`);
  } else {
    step(`ksec secret '${secretName}' exists`, false);
    const fix = await ask("  Create secrets from .env now? (y/N): ");
    if (fix.toLowerCase() === "y") {
      await createSecrets();
    } else {
      warn("Secrets are required for deployment.");
    }
  }

  // ── Phase 6: Drone CI secrets ─────────────────────────────
  console.log(`\n${CYAN}── 6. Drone CI secrets ──${NC}\n`);

  const droneTokens = [
    { name: "staging_kubernetes_token", cfg: "config.staging", secret: CICD_TOKEN_SECRET },
    { name: "ecr_access_key", cfg: "config.staging", secret: ECR_SECRET_NAME, key: "ecr_access_key" },
    { name: "ecr_secret_key", cfg: "config.staging", secret: ECR_SECRET_NAME, key: "ecr_secret_key" },
  ];
  if (isProd) {
    droneTokens.push({ name: "prod_kubernetes_token", cfg: "config.prod", secret: CICD_TOKEN_SECRET });
  }

  for (const t of droneTokens) {
    const cfgPath = join(KUBE_DIR, t.cfg);
    if (!existsSync(cfgPath)) {
      step(`${t.name} extractable`, false);
      continue;
    }
    const jsonpath = t.key ? `{.data.${t.key}}` : "{.data.token}";
    const raw = runCapture(`kubectl get secret ${t.secret} -o jsonpath="${jsonpath}" --kubeconfig="${cfgPath}"`).stdout;
    const decoded = decodeB64(raw);
    step(`${t.name} extractable`, !!decoded);
  }

  // ── Phase 7: Files ────────────────────────────────────────
  console.log(`\n${CYAN}── 7. Required files ──${NC}\n`);

  step(".drone.yml", existsSync(join(PROJECT_ROOT, ".drone.yml")));
  step(`environments/${envLabel}.yaml`, existsSync(envYaml));
  step("psp/backend/Dockerfile", existsSync(join(PROJECT_ROOT, "psp/backend", "Dockerfile")));
  step("psp/frontend/Dockerfile", existsSync(join(PROJECT_ROOT, "psp/frontend", "Dockerfile")));

  // ── Summary ───────────────────────────────────────────────
  const total = passed + failed;
  const color = failed === 0 ? GREEN : failed <= 2 ? YELLOW : RED;
  console.log(`\n${CYAN}── Summary ──${NC}\n`);
  console.log(`  ${color}${passed}/${total} checks passed${NC}`);

  if (failed === 0) {
    console.log(`\n  ${GREEN}✓ ${envLabel} is ready for deployment.${NC}`);
    console.log(`  Push to '${isProd ? "main" : "staging"}' branch to trigger Drone pipeline.`);
  } else {
    console.log(`\n  ${YELLOW}⚠ ${failed} issue(s) found. Fix them before deploying.${NC}`);
  }
}

// ============================================================
//  9. MESH / CORS FIX
// ============================================================

const BACKEND_SVC_URL = `http://${RELEASE_BACKEND}-web-app:80`;

async function applyApiProxy() {
  const dronePath = join(PROJECT_ROOT, ".drone.yml");
  const nextConfigPath = join(PROJECT_ROOT, "psp/frontend", "next.config.js");
  const dockerfilePath = join(PROJECT_ROOT, "psp/frontend", "Dockerfile");

  if (!existsSync(dronePath)) { fail(".drone.yml not found"); return; }
  if (!existsSync(nextConfigPath)) { fail("psp/frontend/next.config.js not found"); return; }

  console.log(`\n${CYAN}=== Next.js API Proxy ===${NC}\n`);
  console.log("  Kanopy mesh enforces OIDC/SSO on every ingress host.");
  console.log("  Disabling mesh causes ERR_CONNECTION_CLOSE (ingress depends on it).");
  console.log("  Solution: proxy all /api/* through the frontend (same-origin).\n");
  console.log(`${CYAN}Changes to apply:${NC}\n`);
  console.log(`  1. ${GREEN}psp/frontend/next.config.js${NC}`);
  console.log(`     Add rewrites() proxying /api/* and /health → backend pod\n`);
  console.log(`  2. ${GREEN}psp/frontend/Dockerfile${NC}`);
  console.log(`     Add NEXT_PUBLIC_PSP_URL_BACKEND_PRIVATE build arg\n`);
  console.log(`  3. ${GREEN}.drone.yml${NC}`);
  console.log(`     Rename build args to _PUBLIC / _PRIVATE\n`);
  console.log(`     Ensure mesh.enabled=true on backend (required by Kanopy ingress)\n`);

  const input = await ask("Apply all changes? (y/N): ");
  if (input.toLowerCase() !== "y") { warn("Aborted."); return; }

  // 1. Update next.config.js
  const nextConfig = `/** @type {import('next').NextConfig} */
const nextConfig = {
    allowedDevOrigins: ['127.0.0.1', 'localhost'],
    async rewrites() {
        const backendUrl =
            process.env.NEXT_PUBLIC_PSP_URL_BACKEND_PRIVATE ||
            process.env.NEXT_PUBLIC_PSP_URL_BACKEND_PUBLIC ||
            'http://localhost:8081';
        return [
            { source: '/api/:path*', destination: \`\${backendUrl}/api/:path*\` },
            { source: '/health', destination: \`\${backendUrl}/health\` },
        ];
    },
};
module.exports = nextConfig;
`;
  writeFileSync(nextConfigPath, nextConfig, "utf-8");
  ok("psp/frontend/next.config.js updated with API proxy rewrites");

  // 2. Add NEXT_PUBLIC_PSP_URL_BACKEND_PRIVATE ARG/ENV to Dockerfile if missing
  if (existsSync(dockerfilePath)) {
    let df = readFileSync(dockerfilePath, "utf-8");
    if (!df.includes("NEXT_PUBLIC_PSP_URL_BACKEND_PRIVATE")) {
      df = df.replace(
        /^(ENV NEXT_PUBLIC_PSP_URL_BACKEND[_A-Z]*=\$NEXT_PUBLIC_PSP_URL_BACKEND[_A-Z]*)$/m,
        `$1\n\nARG NEXT_PUBLIC_PSP_URL_BACKEND_PRIVATE\nENV NEXT_PUBLIC_PSP_URL_BACKEND_PRIVATE=$NEXT_PUBLIC_PSP_URL_BACKEND_PRIVATE`,
      );
      writeFileSync(dockerfilePath, df, "utf-8");
      ok("psp/frontend/Dockerfile: added NEXT_PUBLIC_PSP_URL_BACKEND_PRIVATE ARG/ENV");
    } else {
      console.log(`  ${DIM}[skip]${NC} Dockerfile: NEXT_PUBLIC_PSP_URL_BACKEND_PRIVATE already present`);
    }
  }

  // 3. Update .drone.yml: rename build args, add PRIVATE, ensure mesh=true
  let drone = readFileSync(dronePath, "utf-8");
  let changes = 0;

  // Rename NEXT_PUBLIC_PSP_URL_BACKEND= to NEXT_PUBLIC_PSP_URL_BACKEND_PUBLIC=
  if (drone.includes("NEXT_PUBLIC_PSP_URL_BACKEND=") && !drone.includes("NEXT_PUBLIC_PSP_URL_BACKEND_PUBLIC=")) {
    drone = drone.replace(/NEXT_PUBLIC_PSP_URL_BACKEND=/g, "NEXT_PUBLIC_PSP_URL_BACKEND_PUBLIC=");
    changes++;
  }

  // Add NEXT_PUBLIC_PSP_URL_BACKEND_PRIVATE if missing
  if (!drone.includes("NEXT_PUBLIC_PSP_URL_BACKEND_PRIVATE")) {
    drone = drone.replace(
      /(\s+- NEXT_PUBLIC_PSP_URL_BACKEND_PUBLIC=.*)/g,
      `$1\n        - NEXT_PUBLIC_PSP_URL_BACKEND_PRIVATE=${BACKEND_SVC_URL}`,
    );
    changes++;
  }

  // Remove old PSP_BACKEND_INTERNAL_URL lines
  drone = drone.replace(/\s+- PSP_BACKEND_INTERNAL_URL=[^\n\r]*/g, "");

  // Ensure mesh.enabled=true on backend steps
  const escapedBackend = RELEASE_BACKEND.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const meshFalseRe = new RegExp(
    `(ingress\\.hosts\\[0\\]=${escapedBackend}[^\\n]*\\n\\s+- )mesh\\.enabled=false`, "g",
  );
  if (meshFalseRe.test(drone)) {
    drone = readFileSync(dronePath, "utf-8"); // re-read since .test() advances lastIndex
    drone = drone.replace(meshFalseRe, "$1mesh.enabled=true");
    changes++;
  }

  writeFileSync(dronePath, drone, "utf-8");
  ok(`.drone.yml updated (${changes} change(s))`);

  console.log(`\n${CYAN}Next steps:${NC}`);
  console.log("  1. Commit and push to the staging/main branch");
  console.log("  2. Drone rebuilds frontend with same-origin API calls");
  console.log("  3. Frontend pod proxies /api/* → backend pod (internal K8s network)");
  console.log("  4. Browser never talks to backend directly — no mesh/OIDC conflict");
}

async function fixMesh302() {
  await applyApiProxy();
}

// ============================================================
//  MAIN MENU
// ============================================================

const menu = (): string => `
============================================
 Menu  (target: ${TARGET})
============================================
  --- Setup ---
  1.  Full setup (install all prerequisites)
  2.  Install kubectl only
  3.  Install Helm + MongoDB repo + ksec
  4.  Install/check kanopy-oidc
  5.  Create kanopy OIDC config file
  --- Cluster ---
  6.  Generate kubeconfig (staging/prod/both)
  7.  Login (re-authenticate token)
  8.  Switch target cluster (staging/prod)
  9.  Verify cluster access
  --- Secrets ---
  10. Create/update ksec secrets
  11. List ksec secrets
  12. Get ksec secret values
  13. Manage secret keys (set/delete)
  --- Deployment ---
  14. Get pods (this demo)
  15. Get all resources (pods/deploy/svc/ingress)
  16. View pod logs
  17. Helm release status
  18. Rollout restart
  19. Resource usage (top)
  --- Drone CI ---
  20. Extract Drone secrets (view only)
  21. Configure Drone secrets (extract + push)
  22. Show Drone/deployment info
  --- Diagnostics ---
  23. Describe pod
  24. Exec into pod (shell)
  25. Check env vars in pod
  26. Test staging/prod URLs
  27. Pre-deployment checklist
  --- Inspect ---
  28. Get ingress resources
  29. Describe ingress (detail)
  30. Helm get values (backend/frontend)
  --- Fix ---
  31. Fix mesh 302 (Next.js API proxy)
  --- Deploy ---
  32. Full deploy setup (staging or prod)
  --- ---
  0.  Exit
`;

async function main() {
  console.log(`\n${CYAN}============================================${NC}`);
  console.log(`${CYAN} Kanopy Deployment Manager${NC}`);
  console.log(`${DIM} ${DEMO_NAME}${NC}`);
  console.log(`${CYAN}============================================${NC}`);

  while (true) {
    console.log(menu());
    const choice = await ask("Select an option: ");

    switch (choice) {
      case "1": await fullSetup(); break;
      case "2": await installKubectl(); break;
      case "3": await installHelm(); await setupHelmRepo(); await installKsecPlugin(); break;
      case "4": await installKanopyOidc(); break;
      case "5": await createKanopyConfig(); break;
      case "6": await generateKubeconfig(); break;
      case "7": await kanopyLogin(); break;
      case "8": await switchContext(); break;
      case "9": await verifyAccess(); break;
      case "10": await createSecrets(); break;
      case "11": await listSecrets(); break;
      case "12": await getSecret(); break;
      case "13": await manageSecretKeys(); break;
      case "14": await getPods(); break;
      case "15": await getAll(); break;
      case "16": await podLogs(); break;
      case "17": await helmStatus(); break;
      case "18": await rolloutRestart(); break;
      case "19": await resourceUsage(); break;
      case "20": await extractDroneSecrets(); break;
      case "21": await configureDroneSecrets(); break;
      case "22": await showDroneInfo(); break;
      case "23": await describePod(); break;
      case "24": await execIntoPod(); break;
      case "25": await checkEnvVars(); break;
      case "26": await testUrls(); break;
      case "27": await preDeployChecklist(); break;
      case "28": await getIngress(); break;
      case "29": await describeIngress(); break;
      case "30": await helmGetValues(); break;
      case "31": await fixMesh302(); break;
      case "32": await deployEnvSetup(); break;
      case "0": console.log("\nGoodbye."); rl.close(); process.exit(0);
      default: warn("Invalid option.");
    }

    if (choice !== "0") await pause();
  }
}

main().catch((err) => { console.error(err); process.exit(1); });
