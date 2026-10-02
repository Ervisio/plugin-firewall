/**
 * Running manifest commands and caching what they return.
 *
 *   const out = await run('ufw-status');          // stdout; throws CmdError on a non-zero exit
 *   const ufw = resource('ufw', async () => parseUfwStatus(await run('ufw-status')));
 *   const { data, error, loading } = ufw.use();   // in a component; ufw.refresh() reloads
 */
import { useEffect, useSyncExternalStore } from 'react';
import type { Call } from './backends/translate';
import { t } from './i18n';
import { getSdk, type PluginError } from './sdk';

export class CmdError extends Error {
  command: string;
  exitCode: number;
  constructor(command: string, message: string, exitCode: number) {
    super(message);
    this.command = command;
    this.exitCode = exitCode;
  }
}

export async function run(command: string, args: string[] = []): Promise<string> {
  const r = await getSdk().api.exec(command, args);
  if (r.exitCode !== 0) throw new CmdError(command, (r.stderr || r.stdout).trim() || `exit ${r.exitCode}`, r.exitCode);
  return r.stdout;
}

/** Runs calls one after the other; stops at the first failure. */
export async function runAll(calls: Call[]): Promise<void> {
  for (const c of calls) await run(c.command, c.args);
}

/** A message for a toast or an error card. */
export function errorText(e: unknown): string {
  const pe = e as PluginError;
  if (pe?.code === 'needs_admin') return t('err.needsAdmin');
  if (pe?.code === 'unavailable' && /not found|no such file|executable/i.test(pe.message)) return t('err.missing');
  if (pe?.code === 'forbidden') return t('err.forbidden', { msg: pe.message });
  if (e instanceof Error) return e.message.replace(/^ERROR:\s*/i, '');
  return String(e);
}

/* ---------- a small cache shared by components ---------- */

interface Snap<T> {
  data?: T;
  error?: unknown;
  loading: boolean;
}

export interface Resource<T> {
  use(): Snap<T>;
  refresh(): Promise<void>;
  get(): Snap<T>;
  /** Clears the data: the next use() loads again. */
  reset(): void;
}

export function resource<T>(loader: () => Promise<T>): Resource<T> {
  let snap: Snap<T> = { loading: false };
  let started = false;
  let inflight: Promise<void> | null = null;
  const subs = new Set<() => void>();
  const set = (s: Snap<T>) => {
    snap = s;
    subs.forEach((f) => f());
  };
  const refresh = (): Promise<void> => {
    if (inflight) return inflight;
    started = true;
    set({ ...snap, loading: true });
    inflight = loader()
      .then((data) => set({ data, loading: false }))
      .catch((error) => set({ data: snap.data, error, loading: false }))
      .finally(() => {
        inflight = null;
      });
    return inflight;
  };
  const subscribe = (f: () => void) => {
    subs.add(f);
    return () => subs.delete(f);
  };
  return {
    use() {
      const s = useSyncExternalStore(subscribe, () => snap);
      // No deps: a component may switch resources between renders (another backend).
      useEffect(() => {
        if (!started) void refresh();
      });
      return s;
    },
    refresh,
    get: () => snap,
    reset() {
      started = false;
      set({ loading: false });
    },
  };
}

/** Same as resource(), one per key (an iptables table, a firewalld config view). */
export function resourceMap<T>(loader: (key: string) => Promise<T>): (key: string) => Resource<T> {
  const map = new Map<string, Resource<T>>();
  return (key) => {
    if (!map.has(key)) map.set(key, resource(() => loader(key)));
    return map.get(key)!;
  };
}
