import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import type { RuleSpec } from '../src/model.ts';
import { fwdCalls, fwdOps, iptAdd, nftAdd, preview, SpecError, ufwAdd } from '../src/backends/translate.ts';
import { deleteClosesSsh, opensPort, specClosesSsh, sshOpen } from '../src/guard.ts';
import { parseUfwStatus } from '../src/parse/ufw.ts';
import { parsePorts, coversPort, isIPv6 } from '../src/parse/ports.ts';

const manifest = JSON.parse(readFileSync(new URL('../plugin/manifest.json', import.meta.url), 'utf8'));
const cmds: Record<string, { argv: string[]; args?: { pattern: string; allowDash?: boolean; maxLen?: number }[] }> = Object.fromEntries(
  manifest.capabilities.commands.map((c: { name: string }) => [c.name, c]),
);
const argvMap = Object.fromEntries(Object.entries(cmds).map(([k, v]) => [k, v.argv]));

/** Every call must pass the daemon's argument checks. */
function assertAllowed(calls: { command: string; args: string[] }[]) {
  for (const c of calls) {
    const spec = cmds[c.command];
    assert.ok(spec, `no command ${c.command}`);
    assert.equal(c.args.length, spec.args?.length ?? 0, `${c.command}: argument count`);
    c.args.forEach((a, i) => {
      const s = spec.args![i];
      assert.ok(new RegExp(`^(?:${s.pattern})$`, 'u').test(a), `${c.command} arg ${i + 1} ${JSON.stringify(a)} vs ${s.pattern}`);
      assert.ok(s.allowDash || !a.startsWith('-'), `${c.command} arg ${i + 1} starts with -`);
    });
  }
}

const spec = (p: Partial<RuleSpec>): RuleSpec => ({ action: 'allow', direction: 'in', proto: 'tcp', port: '', source: '', dest: '', iface: '', comment: '', first: false, ...p });

test('ports and addresses', () => {
  assert.deepEqual(parsePorts('22, 80-90'), [{ from: 22, to: 22 }, { from: 80, to: 90 }]);
  assert.equal(parsePorts('70000'), null);
  assert.equal(parsePorts('90-80'), null);
  assert.equal(coversPort('80-90', 85), true);
  assert.equal(coversPort('', 22), true);
  assert.equal(isIPv6('2001:db8::/32'), true);
  assert.equal(isIPv6('1:2:3'), false);
});

test('ufw translation', () => {
  const a = ufwAdd(spec({ port: '22' }), 'Ervisio');
  assert.deepEqual(a, [{ command: 'ufw-port', args: ['allow', 'in', 'tcp', 'any', 'any', '22', 'Ervisio'] }]);
  assert.equal(preview(a[0], argvMap), 'ufw allow in proto tcp from any to any port 22 comment Ervisio');
  const b = ufwAdd(spec({ proto: 'any', port: '53', comment: 'DNS server' }), 'x');
  assert.equal(b[0].command, 'ufw-port-any');
  assert.throws(() => ufwAdd(spec({ proto: 'any', port: '6000-6007' }), 'x'), (e: SpecError) => e.key === 'spec.rangeNeedsProto');
  const c = ufwAdd(spec({ action: 'deny', source: '203.0.113.4', first: true }), 'x');
  assert.deepEqual(c[0], { command: 'ufw-first-host', args: ['deny', 'in', '203.0.113.4', 'any', 'x'] });
  const d = ufwAdd(spec({ proto: 'any', port: '6000-6007', iface: 'eth0' }), 'x');
  assert.deepEqual(d.map((x) => x.args[3]), ['tcp', 'udp']);
  assert.equal(d[0].args[6], '6000:6007');
  const e = ufwAdd(spec({ app: 'Nginx Full' }), 'x');
  assert.equal(e[0].command, 'ufw-app');
  assert.throws(() => ufwAdd(spec({ comment: 'bad"quote' }), 'x'), SpecError);
  assertAllowed([...a, ...b, ...c, ...d, ...e]);
});

test('firewalld translation', () => {
  assert.deepEqual(fwdOps(spec({ port: '80,443' })), ['--add-port=80/tcp', '--add-port=443/tcp']);
  assert.deepEqual(fwdOps(spec({ proto: 'any', port: '53' })), ['--add-port=53/tcp', '--add-port=53/udp']);
  assert.deepEqual(fwdOps(spec({ app: 'https' })), ['--add-service=https']);
  const r = fwdOps(spec({ action: 'reject', source: '203.0.113.0/24', port: '22' }));
  assert.deepEqual(r, ['--add-rich-rule=rule family="ipv4" source address="203.0.113.0/24" port port="22" protocol="tcp" reject']);
  const v6 = fwdOps(spec({ action: 'deny', source: '2001:db8::/32' }));
  assert.deepEqual(v6, ['--add-rich-rule=rule family="ipv6" source address="2001:db8::/32" drop']);
  assert.throws(() => fwdOps(spec({ direction: 'out', port: '1' })), SpecError);
  const calls = fwdCalls('public', [...r, '--add-port=8080/tcp'], 'both');
  assert.deepEqual(calls.map((c) => `${c.command} ${c.args[0]}`), ['fwd-rich --quiet', 'fwd-change --quiet', 'fwd-rich --permanent', 'fwd-change --permanent']);
  assert.equal(fwdCalls('public', ['--add-port=1/tcp'], 'permanent').at(-1)!.command, 'fwd-reload');
  assertAllowed(calls);
});

test('nftables translation', () => {
  const a = nftAdd(spec({ port: '22', comment: 'ssh', chain: 'inet filter input' }));
  assert.deepEqual(a[0].args, ['add', 'inet', 'filter', 'input', 'tcp dport 22 counter accept comment "ssh"']);
  const b = nftAdd(spec({ action: 'deny', proto: 'any', port: '80,6000-6007', source: '203.0.113.0/24', first: true, chain: 'inet filter input', iface: 'eth0' }));
  assert.equal(b[0].args[4], 'iifname "eth0" ip saddr 203.0.113.0/24 meta l4proto { tcp, udp } th dport { 80, 6000-6007 } counter drop');
  assert.equal(b[0].args[0], 'insert');
  assert.throws(() => nftAdd(spec({ source: '2001:db8::1', chain: 'ip filter input' })), SpecError);
  assertAllowed([...a, ...b]);
});

test('iptables translation', () => {
  const a = iptAdd(spec({ proto: 'any', port: '53' }), 4, 'Ervisio');
  assert.deepEqual(a.map((c) => [c.command, c.args[2], c.args[3]]), [['ipt-port', '5', 'tcp'], ['ipt-port', '6', 'udp']]);
  const b = iptAdd(spec({ action: 'deny', proto: 'any', source: '2001:db8::/32', first: true }), 9, 'x');
  assert.deepEqual(b[0].args, ['ip6tables', 'INPUT', '1', 'all', '2001:db8::/32', '::/0', 'x', 'DROP']);
  assert.equal(preview(b[0], argvMap), 'ip6tables -w -I INPUT 1 -p all -s 2001:db8::/32 -d ::/0 -m comment --comment x -j DROP');
  assertAllowed([...a, ...b]);
});

test('SSH guard', () => {
  const rules = parseUfwStatus(readFileSync(new URL('./fixtures/ufw-status.txt', import.meta.url), 'utf8')).rules;
  assert.equal(sshOpen(rules, 22), true);
  assert.equal(sshOpen(rules, 2222), false);
  const ssh = rules.find((r) => r.comment === 'SSH' && !r.v6)!;
  // The OpenSSH profile still opens 22, so deleting the port rule is fine.
  assert.equal(deleteClosesSsh(ssh, rules, 22), false);
  const onlySsh = rules.filter((r) => r.comment === 'SSH' && !r.v6);
  assert.equal(deleteClosesSsh(ssh, onlySsh, 22), true);
  assert.equal(specClosesSsh(spec({ action: 'deny', port: '22' }), 22), true);
  assert.equal(specClosesSsh(spec({ action: 'deny', port: '' }), 22), true);
  assert.equal(specClosesSsh(spec({ action: 'deny', port: '22', source: '203.0.113.4' }), 22), false);
  assert.equal(specClosesSsh(spec({ action: 'deny', port: '22', proto: 'udp' }), 22), false);
  assert.equal(opensPort({ key: 'x', action: 'allow', direction: 'in', proto: 'any', port: '', source: 'any', dest: 'any', text: 'iifname "lo" accept' }, 22), false);
});

test('SSH guard follows iptables jumps into the chains ufw writes', async () => {
  const { parseIptList } = await import('../src/parse/iptables.ts');
  const { reachable } = await import('../src/guard.ts');
  const chains = parseIptList(readFileSync(new URL('./fixtures/ipt4.txt', import.meta.url), 'utf8'), 'filter', false);
  const inbound = reachable(chains, ['INPUT']);
  assert.ok(inbound.some((r) => r.where?.startsWith('ufw-user-input')));
  assert.equal(sshOpen(inbound, 22), true);
  // ctstate RELATED,ESTABLISHED in ufw-before-input must not count as "every port open".
  assert.equal(sshOpen(inbound, 2222), false);
});
