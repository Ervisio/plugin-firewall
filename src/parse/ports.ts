/**
 * Ports and addresses as the user types them, and as each firewall wants them.
 * The plugin's own form: "22", "80,443", "6000-6007" (a dash for ranges). ufw and iptables use ":" for ranges.
 */

export interface PortRange {
  from: number;
  to: number;
}

/** "22, 80-90" → [{22,22},{80,90}]; null when a part is not a port or a range. Empty input gives []. */
export function parsePorts(input: string): PortRange[] | null {
  const s = input.replace(/\s+/g, '');
  if (!s) return [];
  const out: PortRange[] = [];
  for (const part of s.split(',')) {
    const m = /^(\d{1,5})(?:[-:](\d{1,5}))?$/.exec(part);
    if (!m) return null;
    const from = Number(m[1]);
    const to = m[2] ? Number(m[2]) : from;
    if (from < 1 || to > 65535 || from > to) return null;
    out.push({ from, to });
  }
  return out.length > 15 ? null : out;
}

/** Normalised text: "22,80,6000-6007". */
export function portsText(r: PortRange[]): string {
  return r.map((x) => (x.from === x.to ? `${x.from}` : `${x.from}-${x.to}`)).join(',');
}

export const hasRange = (r: PortRange[]): boolean => r.some((x) => x.from !== x.to);

/** Does a port spec (as stored in Rule.port, any separator) cover `port`? An empty spec covers every port. */
export function coversPort(spec: string, port: number): boolean {
  if (!spec.trim()) return true;
  const r = parsePorts(spec.replace(/\s+/g, ''));
  if (!r) return false;
  return r.some((x) => port >= x.from && port <= x.to);
}

export const toUfwPorts = (r: PortRange[]): string => r.map((x) => (x.from === x.to ? `${x.from}` : `${x.from}:${x.to}`)).join(',');
export const toIptPorts = toUfwPorts;
/** nftables: "22" or "{ 22, 80, 6000-6007 }". */
export function toNftPorts(r: PortRange[]): string {
  const items = r.map((x) => (x.from === x.to ? `${x.from}` : `${x.from}-${x.to}`));
  return items.length === 1 ? items[0] : `{ ${items.join(', ')} }`;
}
/** firewalld takes one port or range per --add-port. */
export const toFirewalldPorts = (r: PortRange[]): string[] => r.map((x) => (x.from === x.to ? `${x.from}` : `${x.from}-${x.to}`));

const IP4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}(\/(3[0-2]|[12]?\d))?$/;
const IP6 = /^[0-9a-fA-F:]*:[0-9a-fA-F:.]*(\/(12[0-8]|1[01]\d|[1-9]?\d))?$/;

export const isIPv4 = (s: string): boolean => IP4.test(s);
export function isIPv6(s: string): boolean {
  if (!IP6.test(s)) return false;
  const addr = s.split('/')[0];
  const dbl = addr.split('::').length - 1;
  if (dbl > 1) return false;
  const groups = addr.split(':').filter((g) => g !== '');
  return groups.every((g) => /^[0-9a-fA-F]{1,4}$/.test(g) || IP4.test(g)) && (dbl === 1 ? groups.length < 8 : groups.length === 8);
}
export const isAddr = (s: string): boolean => isIPv4(s) || isIPv6(s);
/** "any", "", "anywhere", 0.0.0.0/0 and ::/0 all mean every address. */
export const isAny = (s: string): boolean => !s || /^(any|anywhere)$/i.test(s) || s === '0.0.0.0/0' || s === '::/0';
