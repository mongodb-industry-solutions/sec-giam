#!/usr/bin/env node
/**
 * Stops the local development services.
 *
 * Two safeguards, both because a dev stopper that overreaches is worse than stopping things by hand.
 *
 * BY PORT, not by process name. `taskkill /IM node.exe` or `pkill node` would also take down whatever else the
 * machine runs on Node: an editor's language server, a test run, another project's server, the terminal agent
 * you typed the command into.
 *
 * AND ONLY THIS REPOSITORY'S PROCESSES. A port is not proof of ownership. `tmp/leafy-wallet` serves its
 * frontend on 8080, exactly where this project serves its own, so "kill whatever holds 8080" would stop
 * another project that happens to be running instead. Each candidate is checked against its command line and
 * skipped when it belongs somewhere else, with the reason printed rather than silently passed over.
 *
 * Usage:
 *   npm run dev:stop                 stop this project's development services
 *   npm run dev:stop -- 8081 8083    stop only these ports
 *   npm run dev:stop -- --any        stop whatever holds the ports, ownership unchecked
 */
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

// The services `npm run dev` starts, each on the port its own package declares.
const SERVICES = [
  { port: 8080, name: 'psp/frontend' },
  { port: 8081, name: 'psp/backend' },
  { port: 8082, name: 'merchant' },
  { port: 8083, name: 'bank/backend' },
  { port: 8084, name: 'bank/frontend' },
];

const isWindows = process.platform === 'win32';
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function run(command, args) {
  try {
    return execFileSync(command, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  } catch {
    // A non-zero exit here means "nothing matched", which is a normal answer rather than a problem.
    return '';
  }
}

/** The process ids listening on a port. More than one appears when a port is bound on several interfaces. */
function listenersOn(port) {
  const found = new Set();

  if (isWindows) {
    for (const line of run('netstat', ['-ano']).split('\n')) {
      // Only LISTENING rows, and only where the LOCAL address ends in exactly this port: a row whose REMOTE
      // address happens to end in the same digits is a client of ours, not a server of ours.
      if (!line.includes('LISTENING')) continue;
      const columns = line.trim().split(/\s+/);
      if (!(columns[1] ?? '').endsWith(`:${port}`)) continue;
      const pid = Number(columns[columns.length - 1]);
      if (Number.isInteger(pid) && pid > 0) found.add(pid);
    }
    return [...found];
  }

  for (const pid of run('lsof', ['-nP', `-iTCP:${port}`, '-sTCP:LISTEN', '-t']).split('\n')) {
    const parsed = Number(pid.trim());
    if (Number.isInteger(parsed) && parsed > 0) found.add(parsed);
  }
  return [...found];
}

/** How a process was launched, used to tell whose it is. Empty when it cannot be read. */
function commandLineOf(pid) {
  if (isWindows) {
    const output = run('wmic', ['process', 'where', `processid=${pid}`, 'get', 'commandline', '/format:list']);
    return (output.split('CommandLine=')[1] ?? '').trim();
  }
  return run('ps', ['-o', 'command=', '-p', String(pid)]).trim();
}

/**
 * Whether the process was started from this repository.
 *
 * Compared case-insensitively and with both separators, because a Windows command line mixes `\` and `/`
 * freely: the tsx loader appears as a `file:///C:/...` url in the same line as a `C:\...` path.
 */
function belongsToThisRepo(commandLine) {
  if (!commandLine) return null; // unreadable, which is not the same as "not ours"
  const haystack = commandLine.replace(/\\/g, '/').toLowerCase();
  return haystack.includes(repoRoot.replace(/\\/g, '/').toLowerCase());
}

/**
 * A short, useful description of whose process this is.
 *
 * The interpreter's own path is deliberately skipped: every Node process is launched by `node.exe`, so naming
 * it says nothing about which project is being looked at. What identifies the owner is the script or the
 * directory that follows it. Quoted paths are read first, because a Windows install path contains spaces and
 * an unquoted match would stop at the first one, reporting "C:\Program".
 */
function describeOwner(commandLine) {
  const quoted = [...commandLine.matchAll(/"([A-Za-z]:[\\/][^"]+)"/g)].map((match) => match[1]);
  const bare = [...commandLine.matchAll(/(?:^|\s)([A-Za-z]:[\\/][^\s"]+)/g)].map((match) => match[1]);
  const owner = [...quoted, ...bare].find((path) => !/[\\/]node(\.exe)?$/i.test(path));
  if (owner) return owner;
  const trimmed = commandLine.replace(/\s+/g, ' ').trim();
  if (!trimmed) return 'another process';
  return trimmed.length > 90 ? `${trimmed.slice(0, 90)}...` : trimmed;
}

function stop(pid) {
  if (isWindows) {
    // `/T` takes the child processes with it. A Next.js or tsx watcher spawns the server as a child, so
    // killing only the parent leaves the port held and the next `npm run dev` cannot bind.
    run('taskkill', ['/PID', String(pid), '/T', '/F']);
    return !run('tasklist', ['/FI', `PID eq ${pid}`]).includes(String(pid));
  }
  try {
    process.kill(pid, 'SIGTERM');
    return true;
  } catch {
    return false;
  }
}

const args = process.argv.slice(2);
const skipOwnershipCheck = args.includes('--any');
const requested = args.map(Number).filter((value) => Number.isInteger(value) && value > 0);

const targets = requested.length
  ? SERVICES.filter((service) => requested.includes(service.port))
    // A port asked for that is not one of ours is still honoured: it is the caller's machine.
    .concat(requested
      .filter((port) => !SERVICES.some((service) => service.port === port))
      .map((port) => ({ port, name: 'requested' })))
  : SERVICES;

let stopped = 0;
let idle = 0;
let skipped = 0;

for (const service of targets) {
  const pids = listenersOn(service.port);
  if (pids.length === 0) {
    console.log(`  ${String(service.port).padEnd(6)} ${service.name.padEnd(14)} not running`);
    idle += 1;
    continue;
  }

  for (const pid of pids) {
    const label = `  ${String(service.port).padEnd(6)} ${service.name.padEnd(14)}`;
    const commandLine = commandLineOf(pid);
    const owned = belongsToThisRepo(commandLine);

    if (!skipOwnershipCheck && owned === false) {
      // Another project on one of our ports. Named so the reason is obvious, and left alone.
      console.log(`${label} SKIPPED (pid ${pid}) belongs to ${describeOwner(commandLine)}`);
      skipped += 1;
      continue;
    }
    if (!skipOwnershipCheck && owned === null) {
      console.log(`${label} SKIPPED (pid ${pid}) its command line could not be read; use --any to stop it anyway`);
      skipped += 1;
      continue;
    }

    const gone = stop(pid);
    console.log(`${label} ${gone ? 'stopped' : 'signalled'} (pid ${pid})`);
    stopped += 1;
  }
}

console.log(`\n${stopped} stopped, ${idle} already idle${skipped ? `, ${skipped} left alone (not this project)` : ''}.`);
// Always a success: "nothing was running" is the outcome asked for, not a failure to achieve it.
process.exit(0);
