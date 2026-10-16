import { useSyncExternalStore } from "react";

/** `true` while the window is at least `px` wide (media query; re-renders on change). */
export function useMinWidth(px: number): boolean {
  const query = `(min-width: ${px}px)`;
  return useSyncExternalStore(
    (onChange) => {
      try {
        const mq = window.matchMedia(query);
        mq.addEventListener("change", onChange);
        return () => mq.removeEventListener("change", onChange);
      } catch {
        return () => undefined;
      }
    },
    () => {
      try {
        return window.matchMedia(query).matches;
      } catch {
        return true;
      }
    },
  );
}
