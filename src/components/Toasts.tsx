import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react";
import { CircleAlert, CircleCheck, Info, TriangleAlert, X } from "lucide-react";
import { cx } from "./ui.tsx";

export type ToastKind = "error" | "warn" | "info" | "success";

interface Toast {
  id: number;
  kind: ToastKind;
  title: string;
  detail?: string;
}

interface ToastApi {
  push: (kind: ToastKind, title: string, detail?: string) => void;
}

const ToastContext = createContext<ToastApi>({ push: () => undefined });

export function useToasts(): ToastApi {
  return useContext(ToastContext);
}

const ICON = { error: CircleAlert, warn: TriangleAlert, info: Info, success: CircleCheck } as const;
const TONE: Record<ToastKind, string> = {
  error: "text-danger",
  warn: "text-warn",
  info: "text-accent",
  success: "text-ok",
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const seq = useRef(0);

  const dismiss = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);

  const push = useCallback(
    (kind: ToastKind, title: string, detail?: string) => {
      const id = ++seq.current;
      setToasts((t) => [...t.slice(-4), { id, kind, title, detail }]);
      window.setTimeout(() => dismiss(id), kind === "error" ? 9000 : 5000);
    },
    [dismiss],
  );

  const api = useMemo(() => ({ push }), [push]);

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div
        className="pointer-events-none fixed right-3 bottom-10 z-50 flex w-[340px] max-w-[90vw] flex-col gap-2"
        aria-live="polite"
        role="status"
      >
        {toasts.map((t) => {
          const Icon = ICON[t.kind];
          return (
            <div
              key={t.id}
              role={t.kind === "error" ? "alert" : undefined}
              className="pointer-events-auto flex items-start gap-2 rounded-[8px] border border-line bg-panel/95 px-3 py-2 shadow-pop backdrop-blur-xl"
            >
              <Icon size={15} className={cx("mt-px shrink-0", TONE[t.kind])} aria-hidden />
              <div className="min-w-0 flex-1">
                <div className="font-medium">{t.title}</div>
                {t.detail && <div className="selectable mt-0.5 break-words text-muted">{t.detail}</div>}
              </div>
              <button
                type="button"
                aria-label="Dismiss"
                onClick={() => dismiss(t.id)}
                className="rounded p-0.5 text-muted hover:bg-chrome-2"
              >
                <X size={12} aria-hidden />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}
