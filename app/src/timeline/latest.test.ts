import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createLatestRunner } from "./latest";

const deferred = <T,>() => {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((a, b) => {
    resolve = a;
    reject = b;
  });
  return { promise, resolve, reject };
};

describe("createLatestRunner", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("debounces: only the last call within the delay runs", async () => {
    const fn = vi.fn(async (n: number) => n * 2);
    const onResult = vi.fn();
    const r = createLatestRunner(fn, onResult, () => {}, 100);
    r.schedule(1);
    r.schedule(2);
    r.schedule(3);
    expect(fn).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(100);
    expect(fn).toHaveBeenCalledTimes(1);
    expect(fn).toHaveBeenCalledWith(3);
    expect(onResult).toHaveBeenCalledWith(6, 3);
  });

  it("drops a stale in-flight result when a newer one was scheduled", async () => {
    const d1 = deferred<string>();
    const d2 = deferred<string>();
    const queue = [d1, d2];
    const onResult = vi.fn();
    const r = createLatestRunner(() => queue.shift()!.promise, onResult, () => {}, 0);
    r.schedule("a");
    r.schedule("b");
    d2.resolve("B");
    d1.resolve("A"); // arrives late: must be ignored
    await vi.runAllTimersAsync();
    expect(onResult).toHaveBeenCalledTimes(1);
    expect(onResult).toHaveBeenCalledWith("B", "b");
  });

  it("stale errors are dropped too; current errors are reported", async () => {
    const d1 = deferred<string>();
    const d2 = deferred<string>();
    const queue = [d1, d2];
    const onError = vi.fn();
    const r = createLatestRunner(() => queue.shift()!.promise, () => {}, onError, 0);
    r.schedule("a");
    r.schedule("b");
    d1.reject(new Error("old"));
    d2.reject(new Error("new"));
    await vi.runAllTimersAsync();
    expect(onError).toHaveBeenCalledTimes(1);
    expect((onError.mock.calls[0]![0] as Error).message).toBe("new");
  });

  it("cancel drops pending and in-flight work", async () => {
    const d = deferred<number>();
    const fn = vi.fn(() => d.promise);
    const onResult = vi.fn();
    const r = createLatestRunner(fn, onResult, () => {}, 50);
    r.schedule(1, 0);
    r.schedule(2);
    r.cancel();
    d.resolve(1);
    await vi.runAllTimersAsync();
    expect(fn).toHaveBeenCalledTimes(1);
    expect(onResult).not.toHaveBeenCalled();
  });
});
