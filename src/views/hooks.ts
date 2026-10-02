import { useEffect, useState } from 'react';
import { errorText, resource } from '../api';
import { firewalld, inboundRules, ipt, listeners, nft, ufw } from '../data';
import { isAny } from '../parse/ports';
import { sshOpen } from '../guard';
import type { BackendId, Rule } from '../model';
import { getSdk, type JobInstance } from '../sdk';

const none = resource(async () => null);

/** Loads the backend's rules (in a component) and returns the incoming ones, or null while loading. */
export function useInbound(b: BackendId | null): { rules: Rule[] | null; error?: unknown } {
  const u = (b === 'ufw' ? ufw : b === 'nftables' ? nft : b === 'firewalld' ? firewalld('runtime') : b === 'iptables' ? ipt('iptables filter') : none).use();
  listeners.use();
  if (!b) return { rules: null };
  return { rules: u.data ? inboundRules(b) : null, error: u.error };
}

/**
 * Whether the firewall filters right now, from its own status once loaded (the detect script only reads config files and
 * systemd, which can disagree: ufw.conf says ENABLED=yes in a container where nothing loaded the rules).
 */
export function useLiveActive(b: BackendId | null, fallback: boolean | undefined): boolean | undefined {
  const u = (b === 'ufw' ? ufw : b === 'firewalld' ? firewalld('runtime') : none).use();
  if (b === 'ufw' && u.data) return (u.data as { active: boolean }).active;
  if (b === 'firewalld' && u.data) return (u.data as { running: boolean }).running;
  return fallback;
}

/** Whether the default for incoming traffic lets everything in (then every port is open). */
export function policyOpen(b: BackendId): boolean | null {
  if (b === 'ufw') {
    const u = ufw.get().data;
    return u ? !u.active || u.defaults.incoming === 'allow' : null;
  }
  if (b === 'firewalld') {
    const f = firewalld('runtime').get().data;
    if (!f) return null;
    const z = f.zones.find((x) => x.isDefault);
    return !f.running || z?.target === 'ACCEPT';
  }
  if (b === 'nftables') {
    const tables = nft.get().data;
    if (!tables) return null;
    const inputs = tables.flatMap((tb) => tb.chains).filter((c) => c.hook === 'input');
    return inputs.every((c) => c.policy !== 'drop' && !c.rules.some((r) => (r.action === 'deny' || r.action === 'reject') && !r.port && isAny(r.source)));
  }
  const chains = ipt('iptables filter').get().data;
  if (!chains) return null;
  return chains.find((c) => c.name === 'INPUT')?.policy === 'ACCEPT' && !chains.some((c) => c.name.startsWith('ufw-'));
}

/** SSH from everywhere: open by a rule, closed (no rule), unfiltered (the firewall lets everything in), null while loading. */
export function useSshState(b: BackendId | null, port: number): 'open' | 'closed' | 'unfiltered' | null {
  const { rules } = useInbound(b);
  if (!b || !rules) return null;
  if (policyOpen(b)) return 'unfiltered';
  return sshOpen(rules, port) ? 'open' : 'closed';
}

/** The watchdog job instances of this user. */
export function useWatchdog(): { jobs: JobInstance[] | null; error?: string; reload(): void } {
  const [jobs, setJobs] = useState<JobInstance[] | null>(null);
  const [error, setError] = useState<string>();
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const api = getSdk().api.jobs;
    if (!api) return;
    api.list({ job: 'watchdog' }).then(
      (j) => {
        setJobs(j);
        setError(undefined);
      },
      (e) => setError(errorText(e)),
    );
  }, [tick]);
  return { jobs, error, reload: () => setTick((x) => x + 1) };
}
