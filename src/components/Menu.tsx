// Keyboard-accessible popup / context menu, positioned at a point and clamped to the viewport.

import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { Check, type LucideIcon } from "lucide-react";
import { cx } from "./ui.tsx";

export type MenuItem =
  | {
      kind: "item";
      label: string;
      icon?: LucideIcon;
      onSelect: () => void;
      disabled?: boolean;
      shortcut?: string;
    }
  | { kind: "check"; label: string; checked: boolean; onSelect: () => void; keepOpen?: boolean; disabled?: boolean }
  | { kind: "separator" }
  | { kind: "header"; label: string };

export interface MenuState {
  x: number;
  y: number;
  items: MenuItem[];
  label: string;
}

function actionable(item: MenuItem): boolean {
  return (item.kind === "item" || item.kind === "check") && !item.disabled;
}

export function ContextMenu({ menu, onClose }: { menu: MenuState; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ left: menu.x, top: menu.y });
  const [active, setActive] = useState(() => menu.items.findIndex(actionable));

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const left = Math.max(4, Math.min(menu.x, window.innerWidth - r.width - 4));
    const top = Math.max(4, Math.min(menu.y, window.innerHeight - r.height - 4));
    setPos({ left, top });
    el.focus();
  }, [menu.x, menu.y]);

  useEffect(() => {
    const onDown = (e: MouseEvent): void => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    const close = (): void => onClose();
    window.addEventListener("mousedown", onDown, true);
    window.addEventListener("blur", close);
    window.addEventListener("resize", close);
    return () => {
      window.removeEventListener("mousedown", onDown, true);
      window.removeEventListener("blur", close);
      window.removeEventListener("resize", close);
    };
  }, [onClose]);

  const activate = (i: number): void => {
    const item = menu.items[i];
    if (!item || !actionable(item)) return;
    if (item.kind === "item") {
      onClose();
      item.onSelect();
    } else if (item.kind === "check") {
      item.onSelect();
      if (!item.keepOpen) onClose();
    }
  };

  const move = (dir: 1 | -1): void => {
    const n = menu.items.length;
    let i = active;
    for (let step = 0; step < n; step++) {
      i = (i + dir + n) % n;
      const it = menu.items[i];
      if (it && actionable(it)) {
        setActive(i);
        return;
      }
    }
  };

  return (
    <div
      ref={ref}
      role="menu"
      aria-label={menu.label}
      tabIndex={-1}
      onContextMenu={(e) => e.preventDefault()}
      onKeyDown={(e) => {
        if (e.key === "Escape") {
          e.preventDefault();
          onClose();
        } else if (e.key === "ArrowDown") {
          e.preventDefault();
          move(1);
        } else if (e.key === "ArrowUp") {
          e.preventDefault();
          move(-1);
        } else if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          activate(active);
        } else if (e.key === "Tab") {
          e.preventDefault();
          onClose();
        }
      }}
      style={{ left: pos.left, top: pos.top }}
      className="fixed z-50 max-h-[80vh] focus-visible:outline-none min-w-[200px] overflow-y-auto rounded-[8px] border border-line bg-panel/95 p-1 text-[12.5px] shadow-pop backdrop-blur-xl"
    >
      {menu.items.map((item, i) => {
        if (item.kind === "separator") return <div key={i} role="separator" className="mx-2 my-1 h-px bg-line" />;
        if (item.kind === "header") {
          return (
            <div key={i} className="px-2.5 pt-1.5 pb-0.5 text-[11px] font-semibold text-muted">
              {item.label}
            </div>
          );
        }
        const Icon = item.kind === "item" ? item.icon : undefined;
        return (
          <div
            key={i}
            role={item.kind === "check" ? "menuitemcheckbox" : "menuitem"}
            aria-checked={item.kind === "check" ? item.checked : undefined}
            aria-disabled={item.disabled || undefined}
            onMouseEnter={() => actionable(item) && setActive(i)}
            onClick={() => activate(i)}
            className={cx(
              "flex h-[22px] items-center gap-2 rounded-[4px] px-2 whitespace-nowrap",
              item.disabled ? "text-faint" : i === active ? "bg-accent text-accent-fg" : "",
            )}
          >
            <span className="flex w-3.5 justify-center">
              {item.kind === "check" ? (
                item.checked && <Check size={13} strokeWidth={2.25} aria-hidden />
              ) : Icon ? (
                <Icon size={13} strokeWidth={1.75} aria-hidden />
              ) : null}
            </span>
            <span className="flex-1">{item.label}</span>
            {item.kind === "item" && item.shortcut && (
              <span className={cx("pl-4 text-[11px]", i === active ? "text-accent-fg/80" : "text-muted")}>
                {item.shortcut}
              </span>
            )}
          </div>
        );
      })}
    </div>
  );
}
