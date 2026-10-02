/**
 * The SSH guard: refuses changes that would close the port you manage the server through. It reasons on the rules the
 * plugin shows, so it errs on the side of asking: a rule it cannot read never counts as keeping SSH open.
 */
import type { Rule, RuleSpec } from './model.ts';
import { SERVICE_PORTS } from './parse/firewalld.ts';
import { coversPort, isAny } from './parse/ports.ts';

/** Services and ufw application profiles that open the SSH port when it is 22. */
const SSH_NAMES = /^(ssh|openssh|openssh-server)$/i;

function servicePorts(name: string): number[] {
  if (SSH_NAMES.test(name)) return [22];
  return (SERVICE_PORTS[name] ?? []).filter((p) => p.endsWith('/tcp')).map((p) => Number(p.split('/')[0]));
}

/** Does this rule let new TCP connections to `port` in, from everywhere? */
export function opensPort(r: Rule, port: number): boolean {
  if (r.action !== 'allow' && r.action !== 'limit') return false;
  if (r.direction === 'out' || r.direction === 'fwd') return false;
  // Rules another tool wrote (ufw seen through iptables) count: they filter just the same.
  if (!isAny(r.source) || r.iface) return false;
  if (r.proto !== 'tcp' && r.proto !== 'any') return false;
  if (r.service && !r.port) return servicePorts(r.service).includes(port);
  // A rule with neither port nor service but with a condition we did not parse (ct state, iifname lo...) does not count.
  if (!r.port && /\b(ct ?state|state|iifname|established|related|lo\b)/i.test(r.text)) return false;
  return coversPort(r.port, port);
}

export const sshOpen = (rules: Rule[], port: number): boolean => rules.some((r) => opensPort(r, port));

/** A new deny/reject for everyone on the SSH port (or on every port). */
export function specClosesSsh(s: RuleSpec, port: number): boolean {
  if (s.action === 'allow' || s.action === 'limit' || s.direction !== 'in') return false;
  if (!isAny(s.source)) return false;
  if (s.proto === 'udp') return false;
  if (s.app) return servicePorts(s.app).includes(port);
  return coversPort(s.port, port);
}

/** Deleting `rule` would leave no rule that opens SSH. */
export function deleteClosesSsh(rule: Rule, rules: Rule[], port: number): boolean {
  if (!opensPort(rule, port)) return false;
  return !rules.some((r) => r.key !== rule.key && opensPort(r, port));
}

/** The rules of `start` and of every chain they jump to (ufw keeps its rules in ufw-user-input, reached from INPUT). */
export function reachable(chains: { name: string; rules: Rule[] }[], start: string[]): Rule[] {
  const byName = new Map(chains.map((c) => [c.name, c]));
  const seen = new Set<string>();
  const out: Rule[] = [];
  const queue = [...start];
  while (queue.length) {
    const name = queue.shift()!;
    if (seen.has(name)) continue;
    seen.add(name);
    for (const r of byName.get(name)?.rules ?? []) {
      out.push(r);
      if (r.target && byName.has(r.target)) queue.push(r.target);
    }
  }
  return out;
}
