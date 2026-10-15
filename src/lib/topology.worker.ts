// Layout Web Worker: dagre on a few hundred / thousand nodes can take a while, so it runs off
// the main thread. Requests carry a sequence number; the UI ignores stale replies.

import { stableLayout, type LayoutRequest, type LayoutResult } from "./topologyLayout.ts";

interface WorkerScope {
  onmessage: ((e: MessageEvent<LayoutRequest>) => void) | null;
  postMessage(msg: LayoutResult | { seq: number; error: string }): void;
}

const scope = self as unknown as WorkerScope;

scope.onmessage = (e) => {
  try {
    scope.postMessage(stableLayout(e.data));
  } catch (err) {
    scope.postMessage({ seq: e.data.seq, error: err instanceof Error ? err.message : String(err) });
  }
};
