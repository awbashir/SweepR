// Minimal accessible modal dialog (focus trap via <dialog>-like behavior, Escape to close).

import { useEffect, useRef, type ReactNode } from "react";
import { X } from "lucide-react";

export function Modal({
  title,
  onClose,
  children,
  footer,
  width = 440,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  width?: number;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const prevFocus = useRef<Element | null>(null);

  useEffect(() => {
    prevFocus.current = document.activeElement;
    const first = ref.current?.querySelector<HTMLElement>(
      "input:not([disabled]), select:not([disabled]), textarea, button:not([data-close])",
    );
    first?.focus();
    return () => {
      if (prevFocus.current instanceof HTMLElement) prevFocus.current.focus();
    };
  }, []);

  return (
    <div
      className="fixed inset-0 z-40 flex items-start justify-center bg-black/25 pt-[12vh]"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        style={{ width }}
        className="max-w-[92vw] rounded-[10px] border border-line bg-panel shadow-pop"
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.stopPropagation();
            onClose();
          }
          if (e.key === "Tab") {
            // Keep focus inside the dialog.
            const items = ref.current?.querySelectorAll<HTMLElement>(
              "input:not([disabled]), select:not([disabled]), textarea, button:not([disabled])",
            );
            if (!items || items.length === 0) return;
            const first = items[0]!;
            const last = items[items.length - 1]!;
            if (e.shiftKey && document.activeElement === first) {
              e.preventDefault();
              last.focus();
            } else if (!e.shiftKey && document.activeElement === last) {
              e.preventDefault();
              first.focus();
            }
          }
        }}
      >
        <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
          <h2 className="text-[13px] font-semibold">{title}</h2>
          <button
            type="button"
            data-close
            aria-label="Close"
            onClick={onClose}
            className="rounded p-0.5 text-muted hover:bg-chrome-2"
          >
            <X size={14} aria-hidden />
          </button>
        </div>
        <div className="px-4 py-3">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t border-line px-4 py-2.5">{footer}</div>}
      </div>
    </div>
  );
}
