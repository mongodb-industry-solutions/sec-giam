// Global test setup - loaded by vitest before each test file
import { vi } from 'vitest';

// Every module that imports config.ts calls dotenv.config() at import time, so dotenv v17 prints its
// banner once per test file (129 times) and buries the run summary. Setup runs before those imports.
process.env.DOTENV_CONFIG_QUIET = 'true';

// Silence console output in tests unless explicitly needed
vi.spyOn(console, 'error').mockImplementation(() => {});
vi.spyOn(console, 'warn').mockImplementation(() => {});
