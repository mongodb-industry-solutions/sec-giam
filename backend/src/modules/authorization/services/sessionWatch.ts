import { ChangeStream, Db } from 'mongodb';
import { SESSION_COLLECTION } from '../../../shared/models/collections';

/**
 * Layer 2 of revocation propagation: the live session set, kept fresh by a change stream.
 *
 * For validators inside THIS process. Latency in milliseconds with no polling, which is the use a
 * change stream is actually for. External resource servers are layer 3 and go through SSF.
 *
 * What is cached is the set of live session ids, so a check is a set membership test rather than a
 * database read. That is what lets introspection stay cheap while still being authoritative.
 *
 * THE FAILURE MODE THIS FILE IS SHAPED AROUND: a resume token gap. If the stream falls too far
 * behind, MongoDB cannot resume from where it left off, and the cache is then quietly stale with no
 * error anywhere. Serving stale state would mean honouring revoked sessions, so a gap triggers a
 * FULL RELOAD instead. Being briefly slow is recoverable; being confidently wrong is not.
 */
export class SessionWatch {
  private live = new Set<string>();

  private stream: ChangeStream | null = null;

  private loaded = false;

  constructor(private readonly db: Db) {}

  /** Whether the cache can be trusted yet. A caller must fall back to a read until it can. */
  get ready(): boolean {
    return this.loaded;
  }

  get size(): number {
    return this.live.size;
  }

  /**
   * Whether this session is live, according to the cache.
   *
   * Returns null when the cache is not ready, rather than false. False would mean "revoked", and
   * answering "revoked" because we have not finished loading would sign everybody out on a restart.
   */
  isLive(sessionId: string): boolean | null {
    if (!this.loaded) return null;
    return this.live.has(sessionId);
  }

  /** Reads the whole live set. Also the recovery path when the stream cannot be resumed. */
  async reload(): Promise<void> {
    const sessions = await this.db
      .collection<{ sessionId: string }>(SESSION_COLLECTION)
      .find({}, { projection: { _id: 0, sessionId: 1 } })
      .toArray();
    this.live = new Set(sessions.map((session) => session.sessionId));
    this.loaded = true;
  }

  /**
   * Starts watching, after loading the current state.
   *
   * The order matters: load first, then watch. Watching first would miss everything that already
   * existed, and the cache would report every pre-existing session as revoked.
   */
  async start(): Promise<void> {
    await this.reload();

    this.stream = this.db.collection(SESSION_COLLECTION).watch(
      [{ $match: { operationType: { $in: ['insert', 'delete', 'invalidate'] } } }],
      { fullDocument: 'updateLookup' },
    );

    this.stream.on('change', (change) => {
      if (change.operationType === 'insert') {
        const inserted = change.fullDocument as { sessionId?: string } | undefined;
        if (inserted?.sessionId) this.live.add(inserted.sessionId);
        return;
      }
      if (change.operationType === 'delete') {
        /**
         * A delete carries only the `_id`, not the document, because it is already gone.
         *
         * So the cached id cannot be resolved from the event and a reload is the honest response.
         * Cheaper alternatives exist (an index on _id to sessionId), and all of them are a second
         * copy of the same state that can disagree with this one.
         */
        void this.reload();
        return;
      }
      // `invalidate`: the collection was dropped or renamed, which a reset does. Nothing to resume.
      void this.reload();
    });

    this.stream.on('error', () => {
      /**
       * A resume token gap, or any other stream failure.
       *
       * Reloaded rather than left alone. The alternative is a cache that silently stops receiving
       * updates and keeps answering from whatever it last saw, which is how a revoked session goes
       * on working with nothing in the logs to explain it.
       */
      this.loaded = false;
      void this.reload();
    });
  }

  async stop(): Promise<void> {
    await this.stream?.close();
    this.stream = null;
  }
}
