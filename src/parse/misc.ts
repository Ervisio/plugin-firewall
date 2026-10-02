/** Smaller outputs: the detect script, `ss -Htulnp`, fail2ban status, kernel log lines. */
import type { BackendId, Jail, Listener, LogEntry } from '../model.ts';
import { sections } from './ufw.ts';

/* ---------- detect ---------- */

export interface Detected {
  /** Program name → absolute path, for the programs found. */
  bins: Record<string, string>;
  versions: Record<string, string>;
  units: Record<string, { active: string; enabled: string }>;
  ufwEnabled: boolean;
  /** iptables variant: "nf_tables" or "legacy". */
  iptablesMode: string;
  /** The server's offset from UTC in minutes (syslog files carry no time zone). */
  tzMinutes?: number;
}

export function parseDetect(text: string): Detected {
  const d: Detected = { bins: {}, versions: {}, units: {}, ufwEnabled: false, iptablesMode: '' };
  for (const line of text.split('\n')) {
    const p = line.split('|');
    if (p[0] === 'bin' && p[2]) d.bins[p[1]] = p[2].trim();
    else if (p[0] === 'ver') d.versions[p[1]] = p.slice(2).join('|').trim();
    else if (p[0] === 'unit') d.units[p[1]] = { active: (p[2] ?? '').trim(), enabled: (p[3] ?? '').trim() };
    else if (p[0] === 'ufwconf') d.ufwEnabled = /ENABLED=yes/i.test(p[1] ?? '');
    else if (p[0] === 'tz') {
      const m = /^([+-])(\d{2})(\d{2})$/.exec((p[1] ?? '').trim());
      if (m) d.tzMinutes = (m[1] === '-' ? -1 : 1) * (Number(m[2]) * 60 + Number(m[3]));
    }
  }
  const iv = d.versions.iptables ?? '';
  d.iptablesMode = /nf_tables/.test(iv) ? 'nf_tables' : /legacy/.test(iv) ? 'legacy' : '';
  return d;
}

export const installed = (d: Detected, b: BackendId | 'fail2ban'): boolean =>
  !!d.bins[{ ufw: 'ufw', firewalld: 'firewall-cmd', nftables: 'nft', iptables: 'iptables', fail2ban: 'fail2ban-client' }[b]];

/** Which firewall the plugin opens when the setting is "auto": the one that is running, in order of how high-level it is. */
export function pickBackend(d: Detected): BackendId | null {
  if (installed(d, 'firewalld') && d.units.firewalld?.active === 'active') return 'firewalld';
  if (installed(d, 'ufw') && d.ufwEnabled) return 'ufw';
  if (installed(d, 'ufw')) return 'ufw';
  if (installed(d, 'firewalld')) return 'firewalld';
  if (installed(d, 'nftables')) return 'nftables';
  if (installed(d, 'iptables')) return 'iptables';
  return null;
}

/* ---------- listening sockets ---------- */

export function parseListeners(text: string): Listener[] {
  const out: Listener[] = [];
  const seen = new Set<string>();
  for (const line of text.split('\n')) {
    const t = line.trim().split(/\s+/);
    if (t.length < 5 || !/^(tcp|udp)$/.test(t[0])) continue;
    const local = t[4];
    const m = /^(.*):(\d+|\*)$/.exec(local);
    if (!m || m[2] === '*') continue;
    const address = m[1].replace(/^\[|\]$/g, '');
    const port = Number(m[2]);
    const proc = /users:\(\("([^"]+)",pid=(\d+)/.exec(line);
    const isLocal = /^(127\.|::1$|\[?::1\]?)/.test(address) || /%lo$/.test(address);
    const key = `${t[0]}-${address}-${port}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ proto: t[0] as 'tcp' | 'udp', address: address.replace(/%\S+$/, ''), port, process: proc?.[1] ?? '', pid: proc ? Number(proc[2]) : undefined, local: isLocal });
  }
  return out.sort((a, b) => a.port - b.port || a.proto.localeCompare(b.proto));
}

/** The SSH port: what sshd listens on, else 22. */
export function sshPortFrom(listeners: Listener[]): number | null {
  const s = listeners.find((l) => l.proto === 'tcp' && /^sshd/.test(l.process) && !l.local);
  return s ? s.port : null;
}

/* ---------- fail2ban ---------- */

export function parseF2b(text: string): { running: boolean; version: string; jails: Jail[] } {
  if (/^@@DOWN/m.test(text)) return { running: false, version: '', jails: [] };
  const version = /^@@VERSION\s*(.*)$/m.exec(text)?.[1].replace(/^Fail2Ban\s*v?/i, '') ?? '';
  const jails: Jail[] = [];
  const parts = text.split(/^@@JAIL\s+/m).slice(1);
  for (const p of parts) {
    const name = p.split('\n')[0].trim();
    const num = (k: string) => Number(new RegExp(`${k}:\\s*(\\d+)`).exec(p)?.[1] ?? 0);
    const list = /Banned IP list:[ \t]*(.*)$/m.exec(p)?.[1].trim() ?? '';
    const files = /File list:[ \t]*(.*)$/m.exec(p)?.[1].trim() ?? /Journal matches:[ \t]*(.*)$/m.exec(p)?.[1].trim() ?? '';
    jails.push({
      name,
      currentlyFailed: num('Currently failed'),
      totalFailed: num('Total failed'),
      currentlyBanned: num('Currently banned'),
      totalBanned: num('Total banned'),
      banned: list ? list.split(/\s+/) : [],
      files: files ? files.split(/\s+/) : [],
    });
  }
  return { running: true, version, jails };
}

/* ---------- kernel log lines ---------- */

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** `tz`: the server's UTC offset in minutes, for syslog times (they have none); without it the browser's zone is used. */
function parseTime(s: string, now: Date, tz?: number): number {
  if (/^\d{4}-\d{2}-\d{2}T/.test(s)) {
    // journalctl short-iso-precise: 2026-10-02T21:14:05.123456+0200 (no colon in the offset)
    const fixed = s.replace(/(\.\d{3})\d+/, '$1').replace(/([+-]\d{2})(\d{2})$/, '$1:$2');
    return Date.parse(fixed);
  }
  const m = /^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/.exec(s);
  if (m) {
    const mon = MONTHS.indexOf(m[1]);
    if (tz !== undefined) {
      const at = (y: number) => Date.UTC(y, mon, Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5])) - tz * 60000;
      const t = at(now.getUTCFullYear());
      return t > now.getTime() + 86400000 ? at(now.getUTCFullYear() - 1) : t;
    }
    let d = new Date(now.getFullYear(), mon, Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5]));
    if (d.getTime() > now.getTime() + 86400000) d = new Date(now.getFullYear() - 1, mon, Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5]));
    return d.getTime();
  }
  return NaN;
}

export function verdictOf(prefix: string): LogEntry['verdict'] {
  if (/BLOCK|DROP|REJECT|DENY|DENIED|INVALID/i.test(prefix)) return 'block';
  if (/ALLOW|ACCEPT/i.test(prefix)) return 'allow';
  if (/AUDIT/i.test(prefix)) return 'audit';
  if (/LIMIT/i.test(prefix)) return 'limit';
  return 'log';
}

/** One kernel line with IN= OUT= SRC= ..., from the journal or a syslog file. Null for other lines. */
export function parseLogLine(line: string, now = new Date(), tz?: number): LogEntry | null {
  const k = line.indexOf('IN=');
  if (k < 0 || !/\bSRC=/.test(line)) return null;
  // "<time> [host] kernel: [12345.678] PREFIX IN=..."
  const head = line.slice(0, k);
  const km = /^(\S+(?:\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})?)\s+(?:\S+\s+)?kernel:\s*(?:\[\s*\d+\.\d+\]\s*)?(.*)$/.exec(head);
  let time = NaN;
  let prefix = head.trim();
  if (km) {
    time = parseTime(km[1], now, tz);
    prefix = km[2].trim();
  }
  const f: Record<string, string> = {};
  const flags: string[] = [];
  for (const tok of line.slice(k).trim().split(/\s+/)) {
    const eq = tok.indexOf('=');
    if (eq > 0) f[tok.slice(0, eq)] = tok.slice(eq + 1);
    else if (/^[A-Z]{3}$/.test(tok)) flags.push(tok);
  }
  const n = (v?: string) => (v && /^\d+$/.test(v) ? Number(v) : undefined);
  return {
    time,
    prefix,
    verdict: verdictOf(prefix),
    in: f.IN ?? '',
    out: f.OUT ?? '',
    src: f.SRC ?? '',
    dst: f.DST ?? '',
    proto: (f.PROTO ?? '').toLowerCase(),
    spt: n(f.SPT),
    dpt: n(f.DPT),
    len: n(f.LEN),
    ttl: n(f.TTL ?? f.HOPLIMIT),
    flags,
    raw: line,
  };
}

/** Broadcast and multicast traffic: noisy and almost never what you look for. */
export function isNoise(e: LogEntry): boolean {
  return (
    e.dst === '255.255.255.255' ||
    /\.255$/.test(e.dst) ||
    /^2(2[4-9]|3\d)\./.test(e.dst) ||
    /^ff0/i.test(e.dst)
  );
}

export { sections };
