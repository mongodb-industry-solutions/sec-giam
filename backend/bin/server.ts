import dotenv from 'dotenv';
import { resolve } from 'path';

// The repo root .env, three levels up from giam/backend/bin/.
dotenv.config({ path: resolve(__dirname, '../../../.env') });

import { buildApp } from '../src/app';
import { appendLog } from '../src/shared/services/logBuffer';
import { configurationReport, readinessReport, formatReport } from '../src/shared/services/startupReport';
import { buildPostureReport, postureBanner } from '../src/modules/admin/services/posture.service';
import { config } from '../src/config';

// Async errors thrown outside a request never reach the onError hook, so mirror them too.
function installProcessErrorHooks(): void {
  const record = (kind: string, err: unknown) => {
    const e = err as { name?: string; message?: string };
    const message = String(e?.message ?? err).replace(/\s+/g, ' ').slice(0, 500);
    appendLog(`[${new Date().toISOString()}] PROCESS ${kind}: ${e?.name ?? typeof err}: ${message}`);
  };
  process.on('unhandledRejection', (reason) => record('unhandledRejection', reason));
  process.on('warning', (w) => record('warning', w));
  process.on('uncaughtException', (err) => {
    record('uncaughtException', err);
    console.error(err);
    process.exit(1);
  });
}

async function start() {
  installProcessErrorHooks();
  const app = await buildApp();
  try {
    await app.listen({ port: config.server.port, host: config.server.host });

    const report = [
      ...configurationReport(),
      ...await readinessReport(app.dbError === null ? app.db : undefined, app.dbError),
    ];
    const separator = '.........................................................................';
    for (const line of [separator, 'giam is up', ...formatReport(report), separator]) {
      console.log(line);
      appendLog(`[${new Date().toISOString()}] STARTUP ${line.trim()}`);
    }
    // The posture, in the startup log and as a console banner. Two of the four places a weaker
    // configuration has to surface; the endpoint and the runbook are the other two. A warning nobody
    // sees is the same as no warning.
    const posture = buildPostureReport({ databaseReachable: app.dbError === null, databaseError: app.dbError });
    for (const line of postureBanner(posture)) {
      console.warn(line);
      appendLog(`[${new Date().toISOString()}] POSTURE ${line.trim()}`);
    }
    if (posture.status === 'ok') {
      appendLog(`[${new Date().toISOString()}] POSTURE ok, key custody ${posture.keyCustody.provider}`);
    }
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

if (require.main === module) {
  start();
}
