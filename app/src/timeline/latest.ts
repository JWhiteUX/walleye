// Debounced, latest-wins async runner. IPC calls cannot be aborted, so a
// newer request makes every older one stale: its result is dropped instead
// of overwriting fresher data. Used by the timeline and the queue.

export interface LatestRunner<A> {
  /** Run `fn(args)` after `delayMs` of quiet; earlier pending calls are cancelled. */
  schedule: (args: A, delayMs?: number) => void;
  /** Drop the pending call and make any in-flight result stale. */
  cancel: () => void;
}

export function createLatestRunner<A, R>(
  fn: (args: A) => Promise<R>,
  onResult: (r: R, args: A) => void,
  onError: (e: unknown, args: A) => void,
  defaultDelayMs = 0,
): LatestRunner<A> {
  let seq = 0;
  let timer: ReturnType<typeof setTimeout> | null = null;

  const run = (args: A, mine: number) => {
    fn(args).then(
      (r) => {
        if (mine === seq) onResult(r, args);
      },
      (e) => {
        if (mine === seq) onError(e, args);
      },
    );
  };

  return {
    schedule(args, delayMs = defaultDelayMs) {
      const mine = ++seq;
      if (timer !== null) clearTimeout(timer);
      timer = null;
      if (delayMs <= 0) run(args, mine);
      else
        timer = setTimeout(() => {
          timer = null;
          run(args, mine);
        }, delayMs);
    },
    cancel() {
      seq++;
      if (timer !== null) clearTimeout(timer);
      timer = null;
    },
  };
}
