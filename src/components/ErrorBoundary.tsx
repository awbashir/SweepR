// Error boundaries: a crash in one area (the whole app, the details drawer, the topology map
// including a failed lazy-chunk load) shows a friendly message with Try Again / Reload instead
// of a blank window. While a fallback is shown, ⌘R reloads the window (the app otherwise uses
// ⌘R to start a scan).

import { Component, useEffect, type ErrorInfo, type ReactNode } from "react";
import { RefreshCw, RotateCcw, TriangleAlert } from "lucide-react";
import { describeCrash, disarmCrashTests } from "../lib/crash.ts";
import { Button, Kbd } from "./ui.tsx";

interface Props {
  /** Names the area in the message, e.g. "The topology map". */
  what: string;
  children: ReactNode;
  /** Fill the window (root boundary) instead of the area. */
  fullPage?: boolean;
  /** A change of this value clears the error (e.g. another device selected). */
  resetKey?: unknown;
  /** Called on Try Again, before the children render again (e.g. retry a lazy import). */
  onReset?: () => void;
  className?: string;
}

interface State {
  error: unknown;
  failed: boolean;
}

/** Number of fallbacks on screen; the app's ⌘R shortcut stands aside while any is shown. */
let shownFallbacks = 0;
export const errorFallbackShown = (): boolean => shownFallbacks > 0;

export class ErrorBoundary extends Component<Props, State> {
  override state: State = { error: null, failed: false };

  static getDerivedStateFromError(error: unknown): State {
    return { error, failed: true };
  }

  override componentDidCatch(error: unknown, info: ErrorInfo): void {
    console.error(`[SweepR] ${this.props.what} crashed:`, error, info.componentStack);
  }

  override componentDidUpdate(prev: Props): void {
    if (this.state.failed && !Object.is(prev.resetKey, this.props.resetKey)) this.reset();
  }

  reset = (): void => {
    disarmCrashTests();
    this.props.onReset?.();
    this.setState({ error: null, failed: false });
  };

  override render(): ReactNode {
    if (!this.state.failed) return this.props.children;
    return <Fallback what={this.props.what} error={this.state.error} fullPage={this.props.fullPage === true} onReset={this.reset} className={this.props.className} />;
  }
}

function Fallback({ what, error, fullPage, onReset, className }: { what: string; error: unknown; fullPage: boolean; onReset: () => void; className?: string }) {
  const info = describeCrash(what, error);
  useEffect(() => {
    shownFallbacks += 1;
    // Capture phase on window: runs before (and stops) the app's own ⌘R handler.
    const onKey = (e: KeyboardEvent): void => {
      if ((e.metaKey || e.ctrlKey) && !e.shiftKey && e.key.toLowerCase() === "r") {
        e.preventDefault();
        e.stopImmediatePropagation();
        window.location.reload();
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => {
      shownFallbacks -= 1;
      window.removeEventListener("keydown", onKey, true);
    };
  }, []);
  return (
    <div
      role="alert"
      className={
        fullPage
          ? "flex h-full flex-1 items-center justify-center bg-bg p-6 text-fg"
          : `flex items-center justify-center p-4 ${className ?? "flex-1"}`
      }
    >
      <div className="flex max-w-[440px] flex-col items-center gap-2 text-center">
        <TriangleAlert size={22} className="text-warn" aria-hidden />
        <h2 className="text-[14px] font-semibold">{info.title}</h2>
        <p className="text-muted">
          {info.chunk
            ? "Part of the app failed to load. Try again, or reload the window."
            : "Your scan results are kept. Try again, or reload the window if the problem persists (results are not kept across a reload)."}
        </p>
        <p className="selectable max-w-full break-words font-mono text-[11px] text-faint">{info.detail}</p>
        <div className="mt-1 flex gap-2">
          <Button icon={RotateCcw} onClick={onReset}>
            Try Again
          </Button>
          <Button variant="primary" icon={RefreshCw} onClick={() => window.location.reload()}>
            Reload
          </Button>
        </div>
        <p className="text-[11px] text-muted">
          <Kbd>⌘R</Kbd> reloads the window
        </p>
      </div>
    </div>
  );
}
