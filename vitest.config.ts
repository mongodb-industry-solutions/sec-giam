import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
  resolve: {
    // Run the shared packages from source, so a test never sees a stale dist build.
    alias: {
      '@leafypay/eventbus': resolve(__dirname, 'packages/eventbus/src/index.ts'),
      '@leafypay/platform-links': resolve(__dirname, 'packages/platform-links/src/index.ts'),
      '@leafypay/giam-client': resolve(__dirname, 'packages/giam-client/src/index.ts'),
      // The driver is a backend dependency, not a root one, and a test that measures what the
      // driver sends has to import the same copy the backend uses.
      mongodb: resolve(__dirname, 'backend/node_modules/mongodb'),
    },
  },
  test: {
    globals: true,
    environment: 'node',
    setupFiles: ['./test/setup.ts'],
    // Integration suites build the QE clients in beforeAll (crypt_shared load, DEK provisioning,
    // cluster connection), which does not fit the 10s default on a cold start.
    hookTimeout: 60000,
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
