import * as fs from 'fs';
import * as path from 'path';

// The running version, read once from the package file that was actually deployed.
// Read at import rather than per request: it cannot change without a restart.

function readVersion(): string {
  const candidates = [
    path.resolve(__dirname, '../../../package.json'),
    path.resolve(__dirname, '../../../../package.json'),
  ];
  for (const file of candidates) {
    try {
      const raw = JSON.parse(fs.readFileSync(file, 'utf-8')) as { name?: string; version?: string };
      if (raw.name === 'giam-backend' && raw.version) return raw.version;
    } catch { /* try the next candidate */ }
  }
  return '0.0.0';
}

export const RELEASE_VERSION = readVersion();
