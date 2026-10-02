/** What the plugin reads from the machine, cached, and what to do after a change. */
import { resource, resourceMap, run, CmdError } from './api';
import type { BackendId, Rule } from './model';
import { reachable } from './guard';
export { reachable };
import { parseFirewalldInfo, zoneRules } from './parse/firewalld';
import { parseIptList } from './parse/iptables';
import { parseDetect, parseF2b, parseListeners, pickBackend, sshPortFrom, type Detected } from './parse/misc';
import { parseNftRuleset } from './parse/nftables';
import { parseApps, parseUfwStatus } from './parse/ufw';
import { currentSettings, iptFiles, useSettings, type Settings } from './settings';

export const detect = resource(async () => parseDetect(await run('detect')));
export const listeners = resource(async () => parseListeners(await run('listening')));
export const ufw = resource(async () => parseUfwStatus(await run('ufw-status')));
export const ufwApps = resource(async () => parseApps(await run('ufw-apps')).sort());
export const firewalld = resourceMap(async (config) => parseFirewalldInfo(await run('fwd-info', [config])));
export const nft = resource(async () => parseNftRuleset(await run('nft-list')));
/** key: "iptables filter" or "ip6tables nat". */
export const ipt = resourceMap(async (key) => {
  const [bin, table] = key.split(' ');
  return parseIptList(await run('ipt-list', [bin, table]), table, bin === 'ip6tables');
});
export const f2b = resource(async () => parseF2b(await run('f2b-status')));

/** The firewall the Rules page works on: the setting, or the one detection picks. */
export function useBackend(): { backend: BackendId | null; detected?: Detected; loading: boolean; error?: unknown; settings: Settings } {
  const [settings] = useSettings();
  const d = detect.use();
  const picked = d.data ? pickBackend(d.data) : null;
  const backend = settings.backend !== 'auto' ? settings.backend : picked;
  return { backend, detected: d.data, loading: d.loading && !d.data, error: d.error, settings };
}

/** The SSH port the guard protects. */
export function useSshPort(): number {
  const [s] = useSettings();
  const l = listeners.get().data;
  return s.sshPort || (l ? sshPortFrom(l) : null) || 22;
}

/** Every rule of a backend that the guard should look at (incoming, current view). */
export function inboundRules(b: BackendId): Rule[] | null {
  if (b === 'ufw') return ufw.get().data?.rules ?? null;
  if (b === 'firewalld') {
    const info = firewalld('runtime').get().data;
    if (!info) return null;
    const zones = info.zones.filter((z) => z.active || z.isDefault);
    return zones.flatMap(zoneRules);
  }
  if (b === 'nftables') {
    const tables = nft.get().data;
    if (!tables) return null;
    return tables.flatMap((t) => reachable(t.chains, t.chains.filter((c) => c.hook === 'input').map((c) => c.name)));
  }
  const chains = ipt('iptables filter').get().data;
  return chains ? reachable(chains, ['INPUT']) : null;
}

/** After a change: save the rules where the system loads them at boot (when set), then reload what changed. */
export async function afterChange(b: BackendId, opts: { v6?: boolean } = {}): Promise<string[]> {
  const s = currentSettings();
  const saved: string[] = [];
  if (b === 'nftables' && s.nftSave) saved.push((await run('nft-save', [s.nftFile])).trim());
  if (b === 'iptables' && s.iptSave) {
    const [f4, f6] = iptFiles(s);
    saved.push((await run('ipt-save', [f4])).trim());
    if (opts.v6 !== false) saved.push((await run('ipt-save', [f6])).trim());
  }
  await refreshBackend(b);
  return saved.filter(Boolean);
}

export async function refreshBackend(b: BackendId): Promise<void> {
  if (b === 'ufw') await ufw.refresh();
  else if (b === 'firewalld') await Promise.all([firewalld('runtime').refresh(), firewalld('permanent').refresh()]);
  else if (b === 'nftables') await nft.refresh();
  else await Promise.all(['iptables filter', 'ip6tables filter'].map((k) => ipt(k).refresh()));
  void detect.refresh();
}

export { CmdError };
