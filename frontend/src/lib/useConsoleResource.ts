'use client';

import { useCallback, useEffect, useState } from 'react';
import { ApiError } from './console';

/**
 * Read something from the authority, and act on it.
 *
 * Every administrative section is the same three states and the same two verbs: read, show what came
 * back or why it did not, and run an action that changes something and reads again. Written once
 * because three copies is how one of them ends up not clearing its error, or leaving a button
 * disabled after a failure, and nobody notices until the failure happens.
 *
 * `read` must be a stable callback: it carries the filters, and the read reruns whenever it changes.
 */

export interface ConsoleResource<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  /** Which row, if any, has an action in flight. Null when nothing is running. */
  busy: string | null;
  reload: () => Promise<void>;
  setError: (message: string | null) => void;
  /**
   * Runs an action, then reads again.
   *
   * The reload is not optional: an action whose result is only guessed at by mutating local state is
   * an interface that disagrees with the authority the moment anything unexpected happens.
   */
  run: (key: string, action: () => Promise<unknown>, failureMessage: string) => Promise<boolean>;
}

export function useConsoleResource<T>(
  read: () => Promise<T>,
  failureMessage: string,
): ConsoleResource<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      setData(await read());
      setError(null);
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : failureMessage);
    } finally {
      setLoading(false);
    }
  }, [read, failureMessage]);

  useEffect(() => { void reload(); }, [reload]);

  const run = useCallback(async (key: string, action: () => Promise<unknown>, message: string) => {
    setBusy(key);
    try {
      await action();
      setError(null);
      await reload();
      return true;
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : message);
      return false;
    } finally {
      setBusy(null);
    }
  }, [reload]);

  return { data, loading, error, busy, reload, run, setError };
}

/** Pages a list the authority returned whole, so every section pages identically. */
export function paginate<T>(rows: T[], page: number, limit: number): T[] {
  return rows.slice((page - 1) * limit, page * limit);
}
