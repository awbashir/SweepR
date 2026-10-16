// Small shared controls with a compact macOS look.

import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes } from "react";
import { forwardRef } from "react";
import {
  Cctv,
  CircleDot,
  Clapperboard,
  HardDrive,
  Monitor,
  Network,
  Phone,
  PhoneForwarded,
  Printer,
  Router,
  ScanText,
  Shield,
  Speaker,
  Tv,
  Wifi,
  type LucideIcon,
} from "lucide-react";
import type { DeviceRole } from "../types.ts";

export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

type BtnVariant = "default" | "primary" | "danger" | "ghost";

export const Button = forwardRef<
  HTMLButtonElement,
  ButtonHTMLAttributes<HTMLButtonElement> & { variant?: BtnVariant; icon?: LucideIcon; pressed?: boolean }
>(function Button({ variant = "default", icon: Icon, pressed, className, children, type, ...rest }, ref) {
  return (
    <button
      ref={ref}
      type={type ?? "button"}
      aria-pressed={pressed}
      className={cx(
        "inline-flex h-[24px] shrink-0 items-center gap-1.5 rounded-[6px] px-2 text-[12px] whitespace-nowrap transition-colors disabled:cursor-not-allowed disabled:opacity-45",
        variant === "default" &&
          "border border-line bg-field shadow-[0_0.5px_1px_rgb(0_0_0/0.08)] hover:bg-panel active:bg-chrome-2",
        variant === "primary" && "border border-transparent bg-accent font-medium text-accent-fg hover:brightness-110 active:brightness-95",
        variant === "danger" && "border border-transparent bg-danger font-medium text-white hover:brightness-110 active:brightness-95",
        variant === "ghost" && "border border-transparent hover:bg-chrome-2 active:bg-line-soft",
        pressed && "border-accent/60 bg-accent-soft text-accent",
        className,
      )}
      {...rest}
    >
      {Icon && <Icon size={14} strokeWidth={1.75} aria-hidden className="shrink-0" />}
      {children}
    </button>
  );
});

export function Toggle({
  checked,
  onChange,
  label,
  title,
  disabled,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: ReactNode;
  title?: string;
  disabled?: boolean;
}) {
  return (
    <label
      title={title}
      className={cx(
        "inline-flex h-[24px] shrink-0 items-center gap-1.5 rounded-[6px] px-1.5 whitespace-nowrap",
        disabled ? "opacity-45" : "hover:bg-chrome-2",
      )}
    >
      <input
        type="checkbox"
        className="size-3.5 accent-[var(--accent)]"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      {label}
    </label>
  );
}

export const TextInput = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement> & { invalid?: boolean }>(
  function TextInput({ className, invalid, ...rest }, ref) {
    return (
      <input
        ref={ref}
        spellCheck={false}
        autoCorrect="off"
        autoCapitalize="off"
        aria-invalid={invalid || undefined}
        className={cx(
          "h-[24px] min-w-0 rounded-[6px] border bg-field px-2 text-[12px] placeholder:text-faint",
          invalid ? "border-danger" : "border-line",
          "focus-visible:border-accent",
          className,
        )}
        {...rest}
      />
    );
  },
);

export function Select({ className, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={cx(
        "h-[24px] min-w-0 rounded-[6px] border border-line bg-field pr-6 pl-2 text-[12px]",
        className,
      )}
      {...rest}
    >
      {children}
    </select>
  );
}

export function Separator() {
  return <div className="mx-1 h-5 w-px shrink-0 bg-line" aria-hidden />;
}

export const ROLE_ICON: Record<DeviceRole, LucideIcon> = {
  switch: Network,
  firewall: Shield,
  access_point: Wifi,
  router: Router,
  host: Monitor,
};

const ROLE_TONE: Record<DeviceRole, string> = {
  switch: "text-[#0a7bd8] dark:text-[#5fb1ff]",
  firewall: "text-[#d6342c] dark:text-[#ff7a72]",
  access_point: "text-[#8a4fd8] dark:text-[#bf94ff]",
  router: "text-[#c26a00] dark:text-[#ffb340]",
  host: "text-muted",
};

export function RoleIcon({ role, size = 13, inherit }: { role: DeviceRole; size?: number; inherit?: boolean }) {
  const Icon = ROLE_ICON[role];
  return <Icon size={size} strokeWidth={1.75} aria-hidden className={cx("shrink-0", !inherit && ROLE_TONE[role])} />;
}

export function Kbd({ children }: { children: ReactNode }) {
  return (
    <kbd className="rounded border border-line bg-panel px-1 font-mono text-[10px] text-muted">{children}</kbd>
  );
}

export function SectionTitle({ children, right }: { children: ReactNode; right?: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-2 pt-3 pb-1">
      <h3 className="text-[11px] font-semibold tracking-wide text-muted uppercase">{children}</h3>
      {right}
    </div>
  );
}

/** Icons for `Device.deviceKind`; unknown kinds get a neutral dot. */
export const KIND_ICON: Record<string, LucideIcon> = {
  voip_phone: Phone,
  pbx: PhoneForwarded,
  camera: Cctv,
  computer: Monitor,
  media_server: Clapperboard,
  igd_router: Router,
  printer: Printer,
  scanner: ScanText,
  tv: Tv,
  nas: HardDrive,
  media_player: Speaker,
};

export function KindIcon({ kind, size = 13, inherit, className }: { kind: string; size?: number; inherit?: boolean; className?: string }) {
  const Icon = KIND_ICON[kind] ?? CircleDot;
  return <Icon size={size} strokeWidth={1.75} aria-hidden className={cx("shrink-0", !inherit && "text-accent", className)} />;
}

/** A small pill next to a role ("DHCP server", "IPv6 RA"). */
export function MiniBadge({ label, title, inherit }: { label: string; title?: string; inherit?: boolean }) {
  return (
    <span
      className={cx(
        "shrink-0 rounded-[4px] border px-1 text-[10px] leading-[14px] whitespace-nowrap",
        inherit ? "border-current opacity-90" : "border-line bg-field text-muted",
      )}
      title={title}
    >
      {label}
    </span>
  );
}

/** Text colour per tone (latency / loss / PoE load); every colour also has a text cue. */
export const TONE_TEXT_CLASS: Record<"ok" | "warn" | "bad" | "down" | "none", string> = {
  ok: "text-ok",
  warn: "text-warn",
  bad: "text-danger",
  down: "text-danger font-semibold",
  none: "text-faint",
};
