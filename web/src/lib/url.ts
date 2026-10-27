import { useCallback, useSyncExternalStore } from "react";

// The view and selection live in the query string so reloads and links keep them.

const subscribe = (cb: () => void) => {
  window.addEventListener("popstate", cb);
  return () => window.removeEventListener("popstate", cb);
};

export function useUrlParam(name: string): [string | null, (value: string | null) => void] {
  const value = useSyncExternalStore(subscribe, () => new URLSearchParams(location.search).get(name));
  const set = useCallback(
    (next: string | null) => {
      const params = new URLSearchParams(location.search);
      if (next === null) params.delete(name);
      else params.set(name, next);
      const qs = params.toString();
      history.pushState(null, "", qs ? `?${qs}` : location.pathname);
      window.dispatchEvent(new PopStateEvent("popstate"));
    },
    [name],
  );
  return [value, set];
}
