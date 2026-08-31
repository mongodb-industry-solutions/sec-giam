import * as path from 'path';

/**
 * Test results the console can render, taken from the runner's own machine-readable report.
 *
 * Reconstructing counts from streamed terminal text is fragile and silently wrong the moment a
 * reporter changes its output, which is the failure this replaces: the panel showed a green run for
 * a suite that had failed. The run writes the runner's JSON report and it is parsed here, so the
 * console never reads prose to decide whether something passed.
 */

export interface TestSummary {
  tool: 'vitest' | 'all';
  total: number;
  passed: number;
  failed: number;
  skipped: number;
  durationMs: number;
  failures: Array<{ title: string; reason?: string }>;
}

export interface TestStrategy {
  /** The arguments to run, including the reporter flags that write the report. */
  args: string[];
  /** Where the report lands. Removed before the run, so a crash cannot surface a stale one. */
  outputFile: string;
  parse(raw: string): TestSummary;
}

function firstLine(text?: string): string | undefined {
  return text?.split('\n').map((line) => line.trim()).find(Boolean);
}

/** An absolute path shortened to the part a reader recognises. */
function shortFile(file?: string): string {
  if (!file) return '';
  const normalised = file.replace(/\\/g, '/');
  const index = normalised.indexOf('/test/');
  return index === -1 ? normalised.split('/').pop() ?? normalised : normalised.slice(index + 1);
}

/** The default reporter streams readable output; the json one writes the report parsed here. */
function vitestStrategy(script: string, outputFile: string): TestStrategy {
  return {
    args: ['run', script, '--', '--reporter=default', '--reporter=json', `--outputFile=${outputFile}`],
    outputFile,
    parse(raw) {
      const report = JSON.parse(raw);
      const failures: TestSummary['failures'] = [];
      const start = typeof report.startTime === 'number' ? report.startTime : 0;
      let lastEnd = 0;

      for (const file of report.testResults ?? []) {
        if (typeof file.endTime === 'number') lastEnd = Math.max(lastEnd, file.endTime);
        for (const assertion of file.assertionResults ?? []) {
          if (assertion.status !== 'failed') continue;
          failures.push({
            title: `${shortFile(file.name)} > ${(assertion.fullName || assertion.title || '').trim()}`,
            reason: firstLine(assertion.failureMessages?.[0]),
          });
        }
      }

      return {
        tool: 'vitest',
        total: report.numTotalTests ?? 0,
        passed: report.numPassedTests ?? 0,
        failed: report.numFailedTests ?? 0,
        skipped: (report.numPendingTests ?? 0) + (report.numTodoTests ?? 0),
        durationMs: start && lastEnd ? Math.max(0, lastEnd - start) : 0,
        failures,
      };
    },
  };
}

function reportDir(projectRoot: string): string {
  return path.join(projectRoot, 'test-results');
}

/** The strategy for one suite, or null when the command is not a test run. */
export function resolveTestStrategy(command: string, projectRoot: string): TestStrategy | null {
  const dir = reportDir(projectRoot);
  if (command === 'test:unit') return vitestStrategy('test:unit', path.join(dir, 'unit.json'));
  if (command === 'test:integration') return vitestStrategy('test:integration', path.join(dir, 'integration.json'));
  return null;
}

/** The suites the aggregate run chains, in order. Null for anything that is not the aggregate. */
export function resolveTestSequence(command: string, projectRoot: string): Array<{ script: string; strategy: TestStrategy }> | null {
  if (command !== 'test') return null;
  const dir = reportDir(projectRoot);
  return [
    { script: 'test:unit', strategy: vitestStrategy('test:unit', path.join(dir, 'unit.json')) },
    { script: 'test:integration', strategy: vitestStrategy('test:integration', path.join(dir, 'integration.json')) },
  ];
}

export function aggregateSummaries(parts: TestSummary[]): TestSummary {
  return parts.reduce<TestSummary>((total, part) => ({
    tool: 'all',
    total: total.total + part.total,
    passed: total.passed + part.passed,
    failed: total.failed + part.failed,
    skipped: total.skipped + part.skipped,
    durationMs: total.durationMs + part.durationMs,
    failures: [...total.failures, ...part.failures],
  }), { tool: 'all', total: 0, passed: 0, failed: 0, skipped: 0, durationMs: 0, failures: [] });
}
