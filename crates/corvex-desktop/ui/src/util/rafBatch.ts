// Coalesces high-frequency Tauri events into one flush per animation
// frame. Under heavy scans or busy proxy sessions, each event used to
// trigger its own setState, which made React re-render per-event and
// dropped frames. Buffering to a single rAF tick collapses a burst of
// N events into one state update while keeping arrival order intact.
//
// Order is preserved: items are pushed in arrival order and flushed as
// a contiguous slice, so consumers can safely `[...prev, ...batch]`
// (append) or `[...batch.reverse(), ...prev]` (prepend newest-first)
// without losing the relative ordering inside the batch.

export type RafBatcher<T> = {
  push: (item: T) => void;
  flush: () => void;
  dispose: () => void;
};

export function createRafBatcher<T>(flush: (items: T[]) => void): RafBatcher<T> {
  let buf: T[] = [];
  let frame: number | null = null;
  let disposed = false;

  const doFlush = () => {
    frame = null;
    if (buf.length === 0) return;
    const batch = buf;
    buf = [];
    try {
      flush(batch);
    } catch {
      // surface-safe: a flush error must not wedge the batcher
    }
  };

  return {
    push(item) {
      if (disposed) return;
      buf.push(item);
      if (frame === null) {
        frame = window.requestAnimationFrame(doFlush);
      }
    },
    flush() {
      if (frame !== null) {
        window.cancelAnimationFrame(frame);
        frame = null;
      }
      doFlush();
    },
    dispose() {
      disposed = true;
      if (frame !== null) {
        window.cancelAnimationFrame(frame);
        frame = null;
      }
      buf = [];
    },
  };
}
