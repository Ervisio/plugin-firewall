/** `nft -a list ruleset` (text with "# handle N" comments) → tables, chains and rules. */
import type { Action, Rule } from '../model.ts';

export interface NftChain {
  family: string;
  table: string;
  name: string;
  handle: string;
  /** Base chains only. */
  type?: string;
  hook?: string;
  priority?: string;
  policy?: string;
  rules: Rule[];
}

export interface NftTable {
  family: string;
  name: string;
  handle: string;
  chains: NftChain[];
  /** Sets, maps and flowtables, by name: shown, not edited. */
  objects: string[];
  managedBy?: string;
}

/** Tables other tools write. Editing them works, but the tool may overwrite the change. */
export function tableOwner(family: string, name: string, chains: string[]): string | undefined {
  if (name === 'firewalld' || name.startsWith('firewalld')) return 'firewalld';
  if (chains.some((c) => c.startsWith('ufw-') || c.startsWith('ufw6-'))) return 'ufw';
  if (chains.some((c) => c.startsWith('DOCKER'))) return 'Docker';
  if (chains.some((c) => c.startsWith('KUBE-') || c.startsWith('cali-'))) return 'Kubernetes';
  if (name === 'fail2ban' || chains.some((c) => c.startsWith('f2b-'))) return 'fail2ban';
  void family;
  return undefined;
}

function summarise(text: string): Pick<Rule, 'action' | 'direction' | 'proto' | 'port' | 'source' | 'dest' | 'iface' | 'comment' | 'packets' | 'bytes' | 'target'> {
  const grab = (re: RegExp) => re.exec(text)?.[1];
  const verdict = /\b(accept|drop|reject|jump|goto|return|log|masquerade|snat|dnat|redirect)\b/.exec(text)?.[1];
  const action: Action = verdict === 'accept' ? 'allow' : verdict === 'drop' ? 'deny' : verdict === 'reject' ? 'reject' : verdict === 'log' ? 'log' : 'other';
  const set = (v?: string) => v?.replace(/^\{\s*|\s*\}$/g, '').replace(/\s+/g, '');
  const portRaw = grab(/\b(?:tcp|udp|th|sctp)\s+dport\s+(\{[^}]*\}|\S+)/);
  const proto = grab(/\b(tcp|udp|sctp|icmp|icmpv6)\b/) ?? (/meta l4proto \{ ?tcp, ?udp ?\}/.test(text) ? 'any' : 'any');
  const counter = /counter packets (\d+) bytes (\d+)/.exec(text);
  return {
    action,
    target: action === 'other' ? (/(?:jump|goto)\s+(\S+)/.exec(text)?.[1] ?? verdict) : undefined,
    direction: '',
    proto,
    port: set(portRaw) ?? '',
    source: set(grab(/\b(?:ip|ip6)\s+saddr\s+(!=\s*\S+|\{[^}]*\}|\S+)/)) ?? 'any',
    dest: set(grab(/\b(?:ip|ip6)\s+daddr\s+(!=\s*\S+|\{[^}]*\}|\S+)/)) ?? 'any',
    iface: grab(/\biifname\s+"?([^"\s]+)"?/) ?? grab(/\boifname\s+"?([^"\s]+)"?/),
    comment: grab(/comment\s+"([^"]*)"/),
    packets: counter ? Number(counter[1]) : undefined,
    bytes: counter ? Number(counter[2]) : undefined,
  };
}

export function parseNftRuleset(text: string): NftTable[] {
  const tables: NftTable[] = [];
  let table: NftTable | null = null;
  let chain: NftChain | null = null;
  let skipDepth = 0; // inside a set / map / flowtable body
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    if (skipDepth > 0) {
      skipDepth += (line.match(/\{/g) ?? []).length - (line.match(/\}/g) ?? []).length;
      continue;
    }
    let m = /^table\s+(\S+)\s+(\S+)\s+\{(?:\s*#\s*handle\s+(\d+))?/.exec(line);
    if (m) {
      table = { family: m[1], name: m[2], handle: m[3] ?? '', chains: [], objects: [] };
      tables.push(table);
      continue;
    }
    if (!table) continue;
    m = /^chain\s+(\S+)\s+\{(?:\s*#\s*handle\s+(\d+))?/.exec(line);
    if (m) {
      chain = { family: table.family, table: table.name, name: m[1], handle: m[2] ?? '', rules: [] };
      table.chains.push(chain);
      continue;
    }
    m = /^(set|map|flowtable|counter|quota|limit|ct helper|ct timeout|secmark|synproxy)\s+(\S+)\s+\{/.exec(line);
    if (m && !chain) {
      table.objects.push(`${m[1]} ${m[2]}`);
      skipDepth = (line.match(/\{/g) ?? []).length - (line.match(/\}/g) ?? []).length;
      continue;
    }
    if (line === '}') {
      if (chain) chain = null;
      else table = null;
      continue;
    }
    if (!chain) continue;
    m = /^type\s+(\S+)\s+hook\s+(\S+)(?:\s+device\s+\S+)?\s+priority\s+([^;]+);(?:\s*policy\s+(\w+);)?/.exec(line);
    if (m) {
      chain.type = m[1];
      chain.hook = m[2];
      chain.priority = m[3].trim();
      chain.policy = m[4] ?? 'accept';
      continue;
    }
    const h = /^(.*?)\s*#\s*handle\s+(\d+)$/.exec(line);
    const body = h ? h[1] : line;
    const handle = h?.[2];
    const sum = summarise(body);
    chain.rules.push({
      ...sum,
      direction: chain.hook === 'input' ? 'in' : chain.hook === 'output' ? 'out' : chain.hook === 'forward' ? 'fwd' : '',
      key: `nft-${table.family}-${table.name}-${chain.name}-${handle ?? chain.rules.length}`,
      text: body,
      where: `${table.family} ${table.name} ${chain.name}`,
      v6: table.family === 'ip6' || /\bip6\b/.test(body),
      ref: handle ? { family: table.family, table: table.name, chain: chain.name, handle } : undefined,
    });
  }
  for (const t of tables) {
    t.managedBy = tableOwner(t.family, t.name, t.chains.map((c) => c.name));
    if (t.managedBy) for (const c of t.chains) for (const r of c.rules) r.managedBy = t.managedBy;
  }
  return tables;
}
