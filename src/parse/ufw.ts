/**
 * Output of the `ufw-status` script (LC_ALL=C): sections @@VERSION, @@VERBOSE, @@NUMBERED, @@ADDED, @@CONF.
 */
import type { Action, Direction, Rule } from '../model.ts';
import { isAddr } from './ports.ts';

export interface UfwDefaults {
  incoming: string;
  outgoing: string;
  routed: string;
}

export interface UfwStatus {
  version: string;
  active: boolean;
  logging: string;
  defaults: UfwDefaults;
  ipv6: boolean;
  rules: Rule[];
  /** Rules saved while ufw is off (`ufw show added`), as commands. They cannot be deleted by number. */
  added: string[];
}

export function sections(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  let cur = '';
  for (const line of text.split('\n')) {
    const m = /^@@([A-Z]+)\s*(.*)$/.exec(line);
    if (m) {
      cur = m[1];
      out[cur] = m[2] ? m[2] + '\n' : '';
      continue;
    }
    if (cur) out[cur] += line + '\n';
  }
  return out;
}

const ACTIONS: Record<string, Action> = { ALLOW: 'allow', DENY: 'deny', REJECT: 'reject', LIMIT: 'limit' };

interface Side {
  addr: string;
  port: string;
  proto: string;
  app?: string;
  iface?: string;
  v6: boolean;
}

/** One column of `ufw status`: "Anywhere", "22/tcp", "10.0.0.5 443/tcp (v6)", "OpenSSH", "Anywhere on eth0". */
export function parseSide(raw: string): Side {
  let s = raw.trim();
  const v6 = /\(v6\)/.test(s);
  s = s.replace(/\s*\(v6\)/g, '').replace(/\s*\(out\)$/, '').trim();
  let iface: string | undefined;
  const on = /\s+on\s+(\S+)$/.exec(s);
  if (on) {
    iface = on[1];
    s = s.slice(0, on.index).trim();
  }
  const parts = s.split(/\s+/).filter(Boolean);
  let addr = 'any';
  if (parts[0] === 'Anywhere') parts.shift();
  else if (parts[0] && isAddr(parts[0])) addr = parts.shift()!;
  const rest = parts.join(' ');
  const pm = /^([\d,:]+)(?:\/(\w+))?$/.exec(rest);
  if (pm) return { addr, port: pm[1].replace(/:/g, '-'), proto: pm[2] ?? 'any', iface, v6 };
  return { addr, port: '', proto: 'any', app: rest || undefined, iface, v6 };
}

/** `ufw status numbered` → rules (only printed while ufw is active). */
export function parseNumbered(text: string): Rule[] {
  const rules: Rule[] = [];
  for (const line of text.split('\n')) {
    const m = /^\[\s*(\d+)\]\s+(.+?)\s+(ALLOW|DENY|REJECT|LIMIT)(?: (IN|OUT|FWD))?\s+(.*)$/.exec(line.trimEnd());
    if (!m) continue;
    const [, num, toRaw, act, dirRaw, fromAndComment] = m;
    let fromRaw = fromAndComment;
    let comment: string | undefined;
    const c = /\s+#\s?(.*)$/.exec(fromAndComment);
    if (c) {
      comment = c[1].trim();
      fromRaw = fromAndComment.slice(0, c.index);
    }
    const to = parseSide(toRaw);
    const from = parseSide(fromRaw);
    const direction: Direction = dirRaw === 'OUT' ? 'out' : dirRaw === 'FWD' ? 'fwd' : 'in';
    rules.push({
      key: `ufw-${num}`,
      action: ACTIONS[act],
      direction,
      proto: to.proto !== 'any' ? to.proto : from.proto,
      port: to.port,
      source: from.addr,
      dest: to.addr,
      iface: to.iface ?? from.iface,
      v6: to.v6 || from.v6,
      service: to.app,
      comment,
      text: line.replace(/^\[\s*\d+\]\s+/, '').trim(),
      where: `#${num}`,
      ref: { num },
    });
  }
  return rules;
}

/** `ufw status verbose` → state, logging and default policies. */
export function parseVerbose(text: string): { active: boolean; logging: string; defaults: UfwDefaults } {
  const active = /^Status:\s*active/m.test(text);
  const log = /^Logging:\s*(.+)$/m.exec(text);
  let logging = log ? log[1].trim() : 'off';
  const lv = /^on \((\w+)\)$/.exec(logging);
  if (lv) logging = lv[1];
  const defaults: UfwDefaults = { incoming: '', outgoing: '', routed: '' };
  const d = /^Default:\s*(.+)$/m.exec(text);
  if (d) {
    for (const part of d[1].split(',')) {
      const pm = /(\w+)\s+\((incoming|outgoing|routed)\)/.exec(part.trim());
      if (pm) defaults[pm[2] as keyof UfwDefaults] = pm[1];
    }
  }
  return { active, logging, defaults };
}

/** Parses the whole script output. */
export function parseUfwStatus(text: string): UfwStatus {
  const s = sections(text);
  const verbose = parseVerbose(s.VERBOSE ?? '');
  const conf = s.CONF ?? '';
  const added = (s.ADDED ?? '')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.startsWith('ufw '));
  const confLog = /^LOGLEVEL=(\w+)/m.exec(conf);
  // ufw prints the defaults only while active; /etc/default/ufw always has them.
  const policy = (k: string) => {
    const v = new RegExp(`^DEFAULT_${k}_POLICY="?(\\w+)"?`, 'm').exec(conf)?.[1];
    return v === 'ACCEPT' ? 'allow' : v === 'DROP' ? 'deny' : v === 'REJECT' ? 'reject' : '';
  };
  const defaults = verbose.active ? verbose.defaults : { incoming: policy('INPUT'), outgoing: policy('OUTPUT'), routed: policy('FORWARD') };
  return {
    version: (s.VERSION ?? '').trim().replace(/^ufw\s*/, ''),
    active: verbose.active,
    logging: verbose.active ? verbose.logging : confLog ? confLog[1] : verbose.logging,
    defaults,
    ipv6: !/^IPV6=no/m.test(conf),
    rules: verbose.active ? parseNumbered(s.NUMBERED ?? '') : [],
    added,
  };
}

/** A rule from `ufw show added` ("ufw allow from 10.0.0.0/8 to any port 22 proto tcp"), shown read-only while ufw is off. */
export function parseAddedRule(cmd: string, i: number): Rule {
  const words: string[] = cmd.replace(/^ufw\s+/, '').match(/'[^']*'|\S+/g) ?? [];
  const get = (k: string) => {
    const j = words.indexOf(k);
    return j >= 0 ? words[j + 1] : undefined;
  };
  const act = words.find((w) => /^(allow|deny|reject|limit)$/.test(w)) as Action | undefined;
  const commentRaw = get('comment');
  let port = get('port') ?? '';
  let proto = get('proto') ?? 'any';
  // Short form: "ufw allow 22/tcp"
  const short = words.find((w) => /^[\d,:]+(\/\w+)?$/.test(w));
  if (!port && short) {
    const [p, pr] = short.split('/');
    port = p;
    if (pr) proto = pr;
  }
  // Application profile, short form: "ufw allow OpenSSH" or "ufw allow 'Nginx Full'"
  let app = get('app');
  if (!app && !port) {
    const KEYWORDS = /^(allow|deny|reject|limit|in|out|on|from|to|port|proto|comment|log|log-all|route|insert|prepend)$/;
    const j = words.findIndex((w) => /^(allow|deny|reject|limit)$/.test(w));
    const next = j >= 0 ? words[j + 1] : undefined;
    if (next && !KEYWORDS.test(next)) app = next;
  }
  return {
    key: `ufw-added-${i}`,
    action: act ?? 'other',
    direction: words.includes('out') ? 'out' : 'in',
    proto,
    port: port.replace(/:/g, '-'),
    source: get('from') ?? 'any',
    dest: get('to') ?? 'any',
    iface: get('on'),
    service: app?.replace(/^'|'$/g, ''),
    comment: commentRaw?.replace(/^'|'$/g, ''),
    text: cmd,
  };
}

/** `ufw app list` → profile names. */
export function parseApps(text: string): string[] {
  return text
    .split('\n')
    .filter((l) => /^\s{2,}\S/.test(l))
    .map((l) => l.trim());
}
