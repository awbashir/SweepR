import { useEffect, useRef, useState, type Dispatch, type SetStateAction } from "react";
import { loadJson, saveJson } from "../lib/storage.ts";

/** `useState` backed by localStorage (debounced writes, best effort). */
export function usePersistentState<T>(
  key: string,
  initial: T,
  serialize: (v: T) => unknown = (v) => v,
): [T, Dispatch<SetStateAction<T>>] {
  const [value, setValue] = useState<T>(() => loadJson<T>(key, initial));
  const serializeRef = useRef(serialize);
  serializeRef.current = serialize;
  useEffect(() => {
    const t = window.setTimeout(() => saveJson(key, serializeRef.current(value)), 250);
    return () => window.clearTimeout(t);
  }, [key, value]);
  return [value, setValue];
}
