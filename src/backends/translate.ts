/**
 * The "new rule" form → the manifest commands that create it, for each firewall. Pure: the views run the calls, the
 * tests check them. A spec the firewall cannot express throws a SpecError whose `key` is an i18n key.
 */
import type { Rule, RuleSpec } from '../model.ts';
import { hasRange, isAny, isIPv4, isIPv6, parsePorts, toFirewalldPorts, toIptPorts, toNftPorts, toUfwPorts, type PortRange } from '../parse/ports.ts';

export interface Call {
  command: string;
  args: string[];
}

export class SpecError extends Error {
  key: string;
  constructor(key: string) {
    super(key);
    this.key = key;
  }
}

const COMMENT_RE = /^[\p{L}\p{N}][\p{L}\p{N} _.,:/@()+-]{0,63}$/u;

/** Checks the parts every backend shares; returns the parsed ports. */
export function checkSpec(s: RuleSpec): PortRange[] {
  const ports = parsePorts(s.port);
  if (!ports) throw new SpecError('spec.badPort');
  for (const a of [s.source, s.dest]) if (!isAny(a) && !isIPv4(a) && !isIPv6(a)) throw new SpecError('spec.badAddr');
  if (s.comment && !COMMENT_RE.test(s.comment)) throw new SpecError('spec.badComment');
  if (s.iface && !/^[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,14}$/.test(s.iface)) throw new SpecError('spec.badIface');
  const fam = (a: string) => (isAny(a) ? '' : isIPv6(a) ? '6' : '4');
  if (fam(s.source) && fam(s.dest) && fam(s.source) !== fam(s.dest)) throw new SpecError('spec.mixedFamilies');
  return ports;
}

const addr = (a: string) => (isAny(a) ? 'any' : a.trim());
const protos = (p: RuleSpec['proto']): ('tcp' | 'udp')[] => (p === 'any' ? ['tcp', 'udp'] : [p]);

/* ---------- ufw ---------- */

export function ufwAdd(s: RuleSpec, defaultComment: string): Call[] {
  const ports = checkSpec(s);
  const comment = s.comment || defaultComment;
  const base = [s.action, s.direction];
  const src = addr(s.source);
  const dst = addr(s.dest);
  if (s.app) {
    if (s.iface || s.first) throw new SpecError('spec.ufwAppOptions');
    return [{ command: 'ufw-app', args: [...base, src, dst, s.app, comment] }];
  }
  if (s.first && s.iface) throw new SpecError('spec.ufwFirstIface');
  if (ports.length) {
    const p = toUfwPorts(ports);
    if (s.proto === 'any' && hasRange(ports) && !s.iface && !s.first) throw new SpecError('spec.rangeNeedsProto');
    if (s.iface) return protos(s.proto).map((pr) => ({ command: 'ufw-port-if', args: [...base, s.iface, pr, src, dst, p, comment] }));
    if (s.first) return protos(s.proto).map((pr) => ({ command: 'ufw-first-port', args: [...base, pr, src, dst, p, comment] }));
    if (s.proto === 'any') return [{ command: 'ufw-port-any', args: [...base, src, dst, p, comment] }];
    return [{ command: 'ufw-port', args: [...base, s.proto, src, dst, p, comment] }];
  }
  if (s.iface) return [{ command: 'ufw-host-if', args: [...base, s.iface, src, dst, comment] }];
  if (s.first) return [{ command: 'ufw-first-host', args: [...base, src, dst, comment] }];
  return [{ command: 'ufw-host', args: [...base, src, dst, comment] }];
}

export const ufwDelete = (r: Rule): Call => ({ command: 'ufw-delete', args: [r.ref!.num] });

/* ---------- firewalld ---------- */

export type FirewalldMode = 'both' | 'permanent' | 'runtime';
export const fwdModes = (m: FirewalldMode): string[] => (m === 'both' ? ['--quiet', '--permanent'] : m === 'permanent' ? ['--permanent'] : ['--quiet']);

/** One firewall-cmd option ("--add-port=80/tcp") → the command that accepts it. */
function fwdCommand(op: string): string {
  if (/^--(add|remove)-rich-rule=/.test(op)) return 'fwd-rich';
  if (/^--(add|remove)-forward-port=/.test(op)) return 'fwd-forward';
  return 'fwd-change';
}

export function fwdCalls(zone: string, ops: string[], mode: FirewalldMode): Call[] {
  const calls: Call[] = [];
  for (const m of fwdModes(mode)) for (const op of ops) calls.push({ command: fwdCommand(op), args: [m, zone, op] });
  if (mode === 'permanent') calls.push({ command: 'fwd-reload', args: [] });
  return calls;
}

/** The firewall-cmd options that create the rule (without zone and mode). */
export function fwdOps(s: RuleSpec): string[] {
  const ports = checkSpec(s);
  if (s.direction === 'out') throw new SpecError('spec.fwdNoOut');
  if (s.iface) throw new SpecError('spec.fwdNoIface');
  const anySrc = isAny(s.source);
  const anyDst = isAny(s.dest);
  if (s.app) {
    if (s.action !== 'allow' || !anySrc || !anyDst) return [`--add-rich-rule=${rich(s, [], s.app)}`];
    return [`--add-service=${s.app}`];
  }
  if (s.action === 'allow' && anySrc && anyDst && ports.length) {
    const out: string[] = [];
    for (const p of toFirewalldPorts(ports)) for (const pr of protos(s.proto)) out.push(`--add-port=${p}/${pr}`);
    return out;
  }
  if (!ports.length) return [`--add-rich-rule=${rich(s, [])}`];
  const out: string[] = [];
  for (const p of toFirewalldPorts(ports)) for (const pr of protos(s.proto)) out.push(`--add-rich-rule=${rich(s, [p, pr])}`);
  return out;
}

function rich(s: RuleSpec, port: string[], service?: string): string {
  const fam = !isAny(s.source) ? (isIPv6(s.source) ? 'ipv6' : 'ipv4') : !isAny(s.dest) ? (isIPv6(s.dest) ? 'ipv6' : 'ipv4') : '';
  const parts = ['rule'];
  if (fam) parts.push(`family="${fam}"`);
  if (!isAny(s.source)) parts.push(`source address="${s.source}"`);
  if (!isAny(s.dest)) parts.push(`destination address="${s.dest}"`);
  if (service) parts.push(`service name="${service}"`);
  if (port.length) parts.push(`port port="${port[0]}" protocol="${port[1]}"`);
  parts.push(s.action === 'allow' ? 'accept' : s.action === 'deny' ? 'drop' : s.action === 'reject' ? 'reject' : 'accept limit value="6/m"');
  return parts.join(' ');
}

/** Removing a row of the firewalld table. */
export function fwdRemoveOp(r: Rule): string {
  const { kind, value } = r.ref!;
  return kind === 'masquerade' ? '--remove-masquerade' : `--remove-${kind}=${value}`;
}

/* ---------- nftables ---------- */

export function nftExpr(s: RuleSpec, family: string): string {
  const ports = checkSpec(s);
  if (s.action === 'limit') throw new SpecError('spec.noLimit');
  if (s.app) throw new SpecError('spec.noApp');
  const parts: string[] = [];
  if (s.iface) parts.push(`${s.direction === 'out' ? 'oifname' : 'iifname'} "${s.iface}"`);
  for (const [side, a] of [['saddr', s.source], ['daddr', s.dest]] as const) {
    if (isAny(a)) continue;
    const v6 = isIPv6(a);
    if ((family === 'ip' && v6) || (family === 'ip6' && !v6)) throw new SpecError('spec.familyMismatch');
    parts.push(`${v6 ? 'ip6' : 'ip'} ${side} ${a}`);
  }
  if (ports.length) {
    const p = toNftPorts(ports);
    parts.push(s.proto === 'any' ? `meta l4proto { tcp, udp } th dport ${p}` : `${s.proto} dport ${p}`);
  } else if (s.proto !== 'any') parts.push(`meta l4proto ${s.proto}`);
  parts.push('counter');
  parts.push(s.action === 'allow' ? 'accept' : s.action === 'deny' ? 'drop' : 'reject');
  if (s.comment) parts.push(`comment "${s.comment}"`);
  return parts.join(' ');
}

export function nftAdd(s: RuleSpec): Call[] {
  const [family, table, chain] = (s.chain ?? '').split(' ');
  if (!family || !table || !chain) throw new SpecError('spec.noChain');
  return [{ command: 'nft-rule', args: [s.first ? 'insert' : 'add', family, table, chain, nftExpr(s, family)] }];
}

export const nftDelete = (r: Rule): Call => ({ command: 'nft-delete-rule', args: [r.ref!.family, r.ref!.table, r.ref!.chain, r.ref!.handle] });

/* ---------- iptables ---------- */

/** `count` is the number of rules already in the chain: a rule that does not go first is inserted after them. */
export function iptAdd(s: RuleSpec, count: number, defaultComment: string): Call[] {
  const ports = checkSpec(s);
  if (s.action === 'limit') throw new SpecError('spec.noLimit');
  if (s.app) throw new SpecError('spec.noApp');
  if (s.iface) throw new SpecError('spec.iptNoIface');
  const v6 = !!s.v6 || isIPv6(s.source) || isIPv6(s.dest);
  if (v6 && (isIPv4(s.source) || isIPv4(s.dest))) throw new SpecError('spec.mixedFamilies');
  const bin = v6 ? 'ip6tables' : 'iptables';
  const any = v6 ? '::/0' : '0.0.0.0/0';
  const src = isAny(s.source) ? any : s.source;
  const dst = isAny(s.dest) ? any : s.dest;
  const chain = s.chain || (s.direction === 'out' ? 'OUTPUT' : 'INPUT');
  const target = s.action === 'allow' ? 'ACCEPT' : s.action === 'deny' ? 'DROP' : 'REJECT';
  const comment = s.comment || defaultComment;
  const list = ports.length ? protos(s.proto) : [s.proto === 'any' ? 'all' : s.proto];
  return list.map((pr, i) => {
    const pos = String(s.first ? 1 + i : count + 1 + i);
    return ports.length
      ? { command: 'ipt-port', args: [bin, chain, pos, pr, src, dst, toIptPorts(ports), comment, target] }
      : { command: 'ipt-host', args: [bin, chain, pos, pr, src, dst, comment, target] };
  });
}

export const iptDelete = (r: Rule): Call => ({ command: 'ipt-delete', args: [r.ref!.bin, r.ref!.chain, r.ref!.num] });

/* ---------- fail2ban ---------- */

export const f2bCall = (jail: string, op: 'banip' | 'unbanip', ip: string): Call => ({ command: 'f2b-set', args: [jail, op, ip] });

/** Commands as a person would type them, for the preview in the rule dialog. */
export function preview(c: Call, argv: Record<string, string[]>): string {
  const tpl = argv[c.command];
  if (!tpl) return `${c.command} ${c.args.join(' ')}`;
  const filled = tpl.map((x) => x.replace(/\{(\d+)\}/g, (_, n) => c.args[Number(n)]));
  let words = filled;
  // The iptables wrapper and the scripts are an implementation detail: show the program the user knows.
  if (words[0] === 'sh' && words[1] === '-c' && /exec "\$0"/.test(words[2])) words = words.slice(3);
  return words.map((w) => (/^[\w@%+=:,./-]+$/.test(w) ? w : `'${w.replace(/'/g, `'\\''`)}'`)).join(' ');
}
