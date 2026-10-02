/** The plugin's own navigation (one page, inner sidebar) and the rule dialog that any view can open. */
import { useSyncExternalStore } from 'react';
import type { RuleSpec } from './model';

export type View = 'overview' | 'rules' | 'logs' | 'bans' | 'activity' | 'settings';

function store<T>(initial: T) {
  let v = initial;
  const subs = new Set<() => void>();
  return {
    get: () => v,
    set(n: T) {
      v = n;
      subs.forEach((f) => f());
    },
    use: () =>
      useSyncExternalStore(
        (f) => {
          subs.add(f);
          return () => subs.delete(f);
        },
        () => v,
      ),
  };
}

const view = store<View>('overview');
export const useView = view.use;
export const go = (v: View): void => view.set(v);

/** null = closed; otherwise the values the form starts with. */
const dialog = store<Partial<RuleSpec> | null>(null);
export const useRuleDialog = dialog.use;
export const openRuleDialog = (prefill: Partial<RuleSpec> = {}): void => dialog.set(prefill);
export const closeRuleDialog = (): void => dialog.set(null);
