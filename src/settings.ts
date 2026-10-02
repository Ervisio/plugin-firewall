/**
 * Plugin settings, one JSON file per user in ~/.config/ervisio/plugins/firewall (declared in manifest files.write).
 * A missing or unreadable file gives the defaults.
 */
import { useEffect, useSyncExternalStore } from 'react';
import type { FirewalldMode } from './backends/translate';
import type { BackendId } from './model';
import { getSdk } from './sdk';

export const CONFIG_DIR = '~/.config/ervisio/plugins/firewall';
const FILE = `${CONFIG_DIR}/settings.json`;

export type LogSource = 'journal' | '/var/log/ufw.log' | '/var/log/kern.log' | '/var/log/messages' | '/var/log/syslog' | '/var/log/firewalld';

export interface Settings {
  /** The firewall the Rules page manages; auto = the one that runs. */
  backend: 'auto' | BackendId;
  sshGuard: boolean;
  /** 0 = what sshd listens on, else 22. */
  sshPort: number;
  /** Type the firewall's name to turn it off or close the incoming policy. */
  typedConfirm: boolean;
  firewalldMode: FirewalldMode;
  nftSave: boolean;
  nftFile: '/etc/nftables.conf' | '/etc/sysconfig/nftables.conf';
  iptSave: boolean;
  /** debian: /etc/iptables/rules.v4 and .v6 (netfilter-persistent); rhel: /etc/sysconfig/iptables and ip6tables. */
  iptLayout: 'debian' | 'rhel';
  showV6: boolean;
  defaultComment: string;
  logSource: LogSource;
  logLines: number;
  hideNoise: boolean;
}

export const DEFAULTS: Settings = {
  backend: 'auto',
  sshGuard: true,
  sshPort: 0,
  typedConfirm: true,
  firewalldMode: 'both',
  nftSave: true,
  nftFile: '/etc/nftables.conf',
  iptSave: false,
  iptLayout: 'debian',
  showV6: true,
  defaultComment: 'Ervisio',
  logSource: 'journal',
  logLines: 1000,
  hideNoise: true,
};

let cache: Settings | undefined;
let loading = false;
const subs = new Set<() => void>();
const emit = () => subs.forEach((f) => f());

export async function loadSettings(): Promise<Settings> {
  try {
    const parsed = JSON.parse(await getSdk().files.read(FILE));
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return { ...DEFAULTS, ...parsed };
  } catch {
    /* missing or invalid: defaults */
  }
  return { ...DEFAULTS };
}

export async function saveSettings(s: Settings): Promise<void> {
  await getSdk().files.write(FILE, JSON.stringify(s, null, 2) + '\n');
  cache = s;
  emit();
}

/** The saved settings (defaults until the file is read) and whether the file was read. */
export function useSettings(): [Settings, boolean] {
  const v = useSyncExternalStore(
    (f) => {
      subs.add(f);
      return () => subs.delete(f);
    },
    () => cache,
  );
  useEffect(() => {
    if (cache || loading) return;
    loading = true;
    void loadSettings().then((s) => {
      cache = s;
      loading = false;
      emit();
    });
  }, []);
  return [v ?? DEFAULTS, v !== undefined];
}

export const currentSettings = (): Settings => cache ?? DEFAULTS;

export const iptFiles = (s: Settings): [string, string] =>
  s.iptLayout === 'rhel' ? ['/etc/sysconfig/iptables', '/etc/sysconfig/ip6tables'] : ['/etc/iptables/rules.v4', '/etc/iptables/rules.v6'];
