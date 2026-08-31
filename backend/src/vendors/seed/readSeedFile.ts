import { readFileSync } from 'fs';
import { resolve } from 'path';
import { config } from '../../config';

// Seed fixtures are plain JSON in giam/backend/data/, environment agnostic: no hostname ever lands in
// a fixture, because a fixture that names a host is a fixture that only works in one deployment.
export function seedDataDir(): string {
  return config.app.seedDataDir ?? resolve(__dirname, '../../../data');
}

export function readSeedFile<T>(name: string): T {
  return JSON.parse(readFileSync(resolve(seedDataDir(), name), 'utf8')) as T;
}
