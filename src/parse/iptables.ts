/** `iptables -t <table> -L -n -v -x --line-numbers` (and ip6tables) → chains with policies and rules. */
import type { Action, Rule } from '../model.ts';

export interface IptChain {
  name: string;
  /** Built-in chains: ACCEPT / DROP. Custom chains: undefined. */
  policy?: string;
  references?: number;
  packets?: number;
  bytes?: number;
  rules: Rule[];
}

const TARGETS: Record<string, Action> = { ACCEPT: 'allow', DROP: 'deny', REJECT: 'reject', LOG: 'log' };
const PROTOS = /^(all|tcp|udp|icmp|ipv6-icmp|icmpv6|sctp|udplite|esp|ah|gre|\d+)$/;
/** iptables 1.8.10 and later print protocol numbers. */
const PROTO_NUM: Record<string, string> = { '0': 'any', '1': 'icmp', '6': 'tcp', '17': 'udp', '41': 'ipv6', '47': 'gre', '50': 'esp', '51': 'ah', '58': 'ipv6-icmp', '132': 'sctp', '136': 'udplite' };

export function ownerOfChain(name: string): string | undefined {
  if (name.startsWith('ufw-') || name.startsWith('ufw6-')) return 'ufw';
  if (name.startsWith('DOCKER')) return 'Docker';
  if (name.startsWith('f2b-')) return 'fail2ban';
  if (name.startsWith('KUBE-') || name.startsWith('cali-')) return 'Kubernetes';
  return undefined;
}

export function parseIptList(text: string, table: string, v6: boolean): IptChain[] {
  const chains: IptChain[] = [];
  let cur: IptChain | null = null;
  for (const raw of text.split('\n')) {
    const line = raw.trimEnd();
    if (!line.trim()) continue;
    let m = /^Chain (\S+) \((?:policy (\w+) (\d+) packets, (\d+) bytes|(\d+) references)\)/.exec(line);
    if (m) {
      cur = { name: m[1], policy: m[2], packets: m[3] ? Number(m[3]) : undefined, bytes: m[4] ? Number(m[4]) : undefined, references: m[5] ? Number(m[5]) : undefined, rules: [] };
      chains.push(cur);
      continue;
    }
    if (!cur || /^\s*num\s+pkts/.test(line)) continue;
    const t = line.trim().split(/\s+/);
    if (!/^\d+$/.test(t[0])) continue;
    const num = t[0];
    const packets = Number(t[1]);
    const bytes = Number(t[2]);
    let i = 3;
    let target = '';
    // A rule without a target (a pure counter) has the protocol in the target column.
    if (!PROTOS.test(t[i])) target = t[i++];
    const protoRaw = t[i++] ?? 'all';
    const proto = PROTO_NUM[protoRaw] ?? protoRaw;
    if (/^(--|-f|!f)$/.test(t[i] ?? '')) i++;
    const inIf = t[i++] ?? '*';
    const outIf = t[i++] ?? '*';
    const source = t[i++] ?? '';
    const dest = t[i++] ?? '';
    const extra = t.slice(i).join(' ');
    const dport = /\bdpts?:(\S+)/.exec(extra)?.[1] ?? /multiport dports (\S+)/.exec(extra)?.[1] ?? '';
    const comment = /\/\* (.*?) \*\//.exec(extra)?.[1];
    const builtinDir = cur.name === 'INPUT' ? 'in' : cur.name === 'OUTPUT' ? 'out' : cur.name === 'FORWARD' ? 'fwd' : '';
    const anyAddr = (a: string) => (a === '0.0.0.0/0' || a === '::/0' ? 'any' : a);
    cur.rules.push({
      key: `ipt-${v6 ? 6 : 4}-${table}-${cur.name}-${num}`,
      action: TARGETS[target] ?? 'other',
      target: TARGETS[target] ? undefined : target || undefined,
      direction: builtinDir,
      proto: proto === 'all' ? 'any' : proto,
      port: dport.replace(/:/g, '-'),
      source: anyAddr(source),
      dest: anyAddr(dest),
      iface: inIf !== '*' ? inIf : outIf !== '*' ? outIf : undefined,
      v6,
      comment,
      packets,
      bytes,
      text: [target || '(no target)', proto, inIf !== '*' ? `in ${inIf}` : '', outIf !== '*' ? `out ${outIf}` : '', source, '→', dest, extra].filter(Boolean).join(' '),
      where: `${cur.name} #${num}`,
      ref: { bin: v6 ? 'ip6tables' : 'iptables', table, chain: cur.name, num },
      managedBy: ownerOfChain(cur.name) ?? (target && ownerOfChain(target) ? ownerOfChain(target) : undefined),
    });
  }
  return chains;
}
