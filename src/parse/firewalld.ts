/**
 * Output of the `fwd-info` script: sections @@STATE, @@VERSION, @@DEFAULT, @@ACTIVE, @@LOGDENIED, @@SERVICES, @@ZONES.
 */
import type { Rule } from '../model.ts';
import { sections } from './ufw.ts';

export interface Zone {
  name: string;
  active: boolean;
  isDefault: boolean;
  target: string;
  interfaces: string[];
  sources: string[];
  services: string[];
  ports: string[];
  protocols: string[];
  masquerade: boolean;
  forwardPorts: string[];
  sourcePorts: string[];
  icmpBlocks: string[];
  richRules: string[];
}

export interface FirewalldInfo {
  running: boolean;
  state: string;
  version: string;
  defaultZone: string;
  logDenied: string;
  services: string[];
  zones: Zone[];
}

const LIST_KEYS: Record<string, keyof Zone> = {
  interfaces: 'interfaces',
  sources: 'sources',
  services: 'services',
  ports: 'ports',
  protocols: 'protocols',
  'forward-ports': 'forwardPorts',
  'source-ports': 'sourcePorts',
  'icmp-blocks': 'icmpBlocks',
  'rich rules': 'richRules',
};

const emptyZone = (name: string, flags: string): Zone => ({
  name,
  active: /active/.test(flags),
  isDefault: /default/.test(flags),
  target: 'default',
  interfaces: [],
  sources: [],
  services: [],
  ports: [],
  protocols: [],
  masquerade: false,
  forwardPorts: [],
  sourcePorts: [],
  icmpBlocks: [],
  richRules: [],
});

/** `firewall-cmd --list-all-zones`. Multi-line values (rich rules, forward ports) are indented with a tab. */
export function parseZones(text: string): Zone[] {
  const zones: Zone[] = [];
  let z: Zone | null = null;
  let listKey: keyof Zone | null = null;
  for (const raw of text.split('\n')) {
    if (!raw.trim()) continue;
    const head = /^([A-Za-z0-9_-]+)(?:\s+\(([^)]*)\))?\s*$/.exec(raw);
    if (head && !/^\s/.test(raw)) {
      z = emptyZone(head[1], head[2] ?? '');
      zones.push(z);
      listKey = null;
      continue;
    }
    if (!z) continue;
    if (/^\t/.test(raw) || /^\s{4,}\S/.test(raw)) {
      // continuation of the last multi-line key
      if (listKey) (z[listKey] as string[]).push(raw.trim());
      continue;
    }
    const kv = /^\s+([a-z -]+):\s*(.*)$/.exec(raw);
    if (!kv) continue;
    const key = kv[1].trim();
    const val = kv[2].trim();
    listKey = null;
    if (key === 'target') z.target = val;
    else if (key === 'masquerade') z.masquerade = val === 'yes';
    else if (key in LIST_KEYS) {
      const k = LIST_KEYS[key];
      listKey = k;
      if (val) {
        // rich rules and forward ports are one per line; the rest are space separated
        if (k === 'richRules' || k === 'forwardPorts') (z[k] as string[]).push(val);
        else (z[k] as string[]).push(...val.split(/\s+/));
      }
    }
  }
  return zones;
}

export function parseFirewalldInfo(text: string): FirewalldInfo {
  const s = sections(text);
  const state = (s.STATE ?? '').trim();
  const zones = parseZones(s.ZONES ?? '');
  const defaultZone = (s.DEFAULT ?? '').trim().split('\n')[0];
  for (const z of zones) if (z.name === defaultZone) z.isDefault = true;
  // --get-active-zones: "public\n  interfaces: eth0"
  const activeNames = (s.ACTIVE ?? '').split('\n').filter((l) => /^\S/.test(l)).map((l) => l.trim().split(/\s/)[0]);
  for (const z of zones) if (activeNames.includes(z.name)) z.active = true;
  return {
    running: state === 'running',
    state,
    version: (s.VERSION ?? '').trim(),
    defaultZone,
    logDenied: (s.LOGDENIED ?? '').trim(),
    services: (s.SERVICES ?? '').trim().split(/\s+/).filter(Boolean),
    zones,
  };
}

/** Pieces of a rich rule worth showing in the table. */
export function richSummary(rule: string): Pick<Rule, 'action' | 'source' | 'dest' | 'port' | 'proto' | 'service'> {
  const attr = (re: RegExp) => re.exec(rule)?.[1];
  const action = /\b(accept)\b/.test(rule) ? 'allow' : /\breject\b/.test(rule) ? 'reject' : /\bdrop\b/.test(rule) ? 'deny' : /\blog\b/.test(rule) ? 'log' : 'other';
  const not = /source\s+NOT\s+address/.test(rule) ? '!' : '';
  return {
    action,
    source: attr(/source\s+(?:NOT\s+)?address="([^"]+)"/) ? not + attr(/source\s+(?:NOT\s+)?address="([^"]+)"/) : 'any',
    dest: attr(/destination\s+(?:NOT\s+)?address="([^"]+)"/) ?? 'any',
    port: attr(/port\s+port="([^"]+)"/) ?? '',
    proto: attr(/port\s+port="[^"]+"\s+protocol="([^"]+)"/) ?? attr(/protocol\s+value="([^"]+)"/) ?? 'any',
    service: attr(/service\s+name="([^"]+)"/),
  };
}

/** The rules of one zone as table rows. `ref.op` is the firewall-cmd option that removes it. */
export function zoneRules(z: Zone): Rule[] {
  const rows: Rule[] = [];
  const base = { direction: 'in' as const, dest: 'any', where: z.name };
  for (const s of z.services) rows.push({ ...base, key: `svc-${z.name}-${s}`, action: 'allow', proto: 'any', port: '', source: 'any', service: s, text: `service ${s}`, ref: { kind: 'service', value: s } });
  for (const p of z.ports) {
    const [port, proto] = p.split('/');
    rows.push({ ...base, key: `port-${z.name}-${p}`, action: 'allow', proto: proto ?? 'any', port, source: 'any', text: `port ${p}`, ref: { kind: 'port', value: p } });
  }
  for (const s of z.sources) rows.push({ ...base, key: `src-${z.name}-${s}`, action: z.target === 'ACCEPT' ? 'allow' : z.target === 'DROP' ? 'deny' : z.target === '%%REJECT%%' ? 'reject' : 'other', proto: 'any', port: '', source: s, text: `source ${s} (zone ${z.name})`, ref: { kind: 'source', value: s } });
  z.richRules.forEach((r, i) => rows.push({ ...base, ...richSummary(r), key: `rich-${z.name}-${i}`, text: r, ref: { kind: 'rich-rule', value: r } }));
  for (const f of z.forwardPorts) {
    const port = /port=([^:]+)/.exec(f)?.[1] ?? '';
    const proto = /proto=([^:]+)/.exec(f)?.[1] ?? 'any';
    rows.push({ ...base, key: `fwd-${z.name}-${f}`, action: 'other', proto, port, source: 'any', text: `forward ${f}`, ref: { kind: 'forward-port', value: f } });
  }
  return rows;
}

/** Well-known firewalld services and their ports, to tell whether a listening port is open. */
export const SERVICE_PORTS: Record<string, string[]> = {
  ssh: ['22/tcp'], http: ['80/tcp'], https: ['443/tcp'], 'http3': ['443/udp'], dns: ['53/tcp', '53/udp'], smtp: ['25/tcp'], smtps: ['465/tcp'],
  'smtp-submission': ['587/tcp'], imap: ['143/tcp'], imaps: ['993/tcp'], pop3: ['110/tcp'], pop3s: ['995/tcp'], ftp: ['21/tcp'],
  mysql: ['3306/tcp'], postgresql: ['5432/tcp'], redis: ['6379/tcp'], 'dhcpv6-client': ['546/udp'], cockpit: ['9090/tcp'],
  samba: ['139/tcp', '445/tcp', '137/udp', '138/udp'], nfs: ['2049/tcp'], ntp: ['123/udp'], openvpn: ['1194/udp'], wireguard: ['51820/udp'],
  mdns: ['5353/udp'], 'kube-apiserver': ['6443/tcp'], prometheus: ['9090/tcp'], 'docker-registry': ['5000/tcp'],
};
