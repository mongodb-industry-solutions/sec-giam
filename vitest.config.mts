import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

// `.mts` so it is loaded as the ES module it is written as: as `.ts` it was read as CommonJS and
// every run printed a deprecation warning about the mismatch.
const here = import.meta.dirname;

export default defineConfig({
  resolve: {
    // Run the shared packages from source, so a test never sees a stale dist build.
    alias: {
      '@leafypay/eventbus': resolve(here, 'packages/eventbus/src/index.ts'),
      '@leafypay/platform-links': resolve(here, 'packages/platform-links/src/index.ts'),
      '@leafypay/giam-client': resolve(here, 'packages/giam-client/src/index.ts'),
      // The driver is a backend dependency, not a root one, and a test that measures what the
      // driver sends has to import the same copy the backend uses.
      mongodb: resolve(here, 'backend/node_modules/mongodb'),
    },
  },
  test: {
    globals: true,
    environment: 'node',
    setupFiles: ['./test/setup.ts'],
    // Integration suites build the QE clients in beforeAll (crypt_shared load, DEK provisioning,
    // cluster connection), which does not fit the 10s default on a cold start.
    hookTimeout: 60000,
    // The integration suites all drive ONE live authority, so they are not independent of each
    // other: run unbounded, thirty-odd files each signing several people in saturated that single
    // process and a third of them timed out, in a different third each run. `test:integration`
    // caps the workers for that reason (fully serial passes too, and takes four times as long).
    testTimeout: 30000,
    include: [
      'test/backend/unit/**/*.test.ts',
      'test/backend/integration/**/*.test.ts',
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      include: ['backend/src/**', 'packages/*/src/**'],
      exclude: ['**/__tests__/**', '**/node_modules/**'],
    },
  },
});
