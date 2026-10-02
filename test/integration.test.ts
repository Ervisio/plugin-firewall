/**
 * Runs the translated commands against real firewalls in Docker containers, through the manifest argv (as the daemon
 * would). Skipped unless FW_UBUNTU (ufw, nftables, iptables, fail2ban) and/or FW_FEDORA (firewalld) name containers:
 *
 *   FW_UBUNTU=fwtest FW_FEDORA=fwfed npm test
 *
 * See scripts/try.mjs for how to create them. The tests change the firewall of those containers.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import type { RuleSpec } from '../src/model.ts';
import { fwdCalls, fwdOps, fwdRemoveOp, iptAdd, iptDelete, nftAdd, nftDelete, ufwAdd, ufwDelete, type Call } from '../src/backends/translate.ts';
import { parseUfwStatus } from '../src/parse/ufw.ts';
import { parseNftRuleset } from '../src/parse/nftables.ts';
import { parseIptList } from '../src/parse/iptables.ts';
import { parseFirewalldInfo, zoneRules } from '../src/parse/firewalld.ts';
// @ts-expect-error plain JS helper
import { buildArgv } from '../scripts/try.mjs';

const UB = process.env.FW_UBUNTU;
const FED = process.env.FW_FEDORA;

function run(container: string, c: Call): string {
  const argv = buildArgv(c.command, c.args) as string[];
  const r = spawnSync('docker', ['exec', container, ...argv], { encoding: 'utf8' });
  assert.equal(r.status, 0, `${c.command} ${c.args.join(' ')}: ${r.stderr}`);
  return r.stdout;
}

const spec = (p: Partial<RuleSpec>): RuleSpec => ({ action: 'allow', direction: 'in', proto: 'tcp', port: '', source: '', dest: '', iface: '', comment: '', first: false, ...p });

test('ufw: add, read back, delete', { skip: !UB }, () => {
  run(UB!, { command: 'ufw-enable', args: [] });
  for (const c of ufwAdd(spec({ action: 'deny', proto: 'any', port: '7000-7010', iface: 'eth0', comment: 'it range' }), 'x')) run(UB!, c);
  for (const c of ufwAdd(spec({ action: 'reject', source: '192.0.2.99', first: true, comment: 'it first' }), 'x')) run(UB!, c);
  let st = parseUfwStatus(run(UB!, { command: 'ufw-status', args: [] }));
  const first = st.rules[0];
  assert.deepEqual([first.action, first.source, first.comment], ['reject', '192.0.2.99', 'it first']);
  const range = st.rules.filter((r) => r.comment === 'it range');
  assert.ok(range.length >= 2 && range.every((r) => r.port === '7000-7010' && r.iface === 'eth0'));
  // Delete from the bottom so the numbers above stay valid.
  for (const r of [...st.rules].reverse().filter((x) => x.comment?.startsWith('it '))) run(UB!, ufwDelete(r));
  st = parseUfwStatus(run(UB!, { command: 'ufw-status', args: [] }));
  assert.equal(st.rules.filter((r) => r.comment?.startsWith('it ')).length, 0);
});

test('nftables: add, insert, read back, delete', { skip: !UB }, () => {
  run(UB!, { command: 'nft-table', args: ['add', 'inet', 'ittest'] });
  run(UB!, { command: 'nft-base-chain', args: ['inet', 'ittest', 'input', 'filter', 'input', '10', 'accept'] });
  run(UB!, nftAdd(spec({ port: '2222', comment: 'it ssh', chain: 'inet ittest input' }))[0]);
  run(UB!, nftAdd(spec({ action: 'deny', proto: 'any', port: '80,8000-8100', source: '2001:db8::/32', first: true, chain: 'inet ittest input' }))[0]);
  const t = parseNftRuleset(run(UB!, { command: 'nft-list', args: [] })).find((x) => x.name === 'ittest')!;
  const rules = t.chains[0].rules;
  assert.equal(rules.length, 2);
  assert.deepEqual([rules[0].action, rules[0].source, rules[0].port], ['deny', '2001:db8::/32', '80,8000-8100']);
  assert.deepEqual([rules[1].port, rules[1].comment], ['2222', 'it ssh']);
  run(UB!, nftDelete(rules[0]));
  assert.equal(parseNftRuleset(run(UB!, { command: 'nft-list', args: [] })).find((x) => x.name === 'ittest')!.chains[0].rules.length, 1);
  run(UB!, { command: 'nft-table', args: ['delete', 'inet', 'ittest'] });
});

test('iptables: insert v4 and v6, read back, delete', { skip: !UB }, () => {
  const before = parseIptList(run(UB!, { command: 'ipt-list', args: ['iptables', 'filter'] }), 'filter', false).find((c) => c.name === 'OUTPUT')!.rules.length;
  for (const c of iptAdd(spec({ direction: 'out', proto: 'any', port: '853', dest: '9.9.9.9', comment: 'it dot' }), before, 'x')) run(UB!, c);
  const out = parseIptList(run(UB!, { command: 'ipt-list', args: ['iptables', 'filter'] }), 'filter', false).find((c) => c.name === 'OUTPUT')!.rules;
  const mine = out.filter((r) => r.comment === 'it dot');
  assert.deepEqual(mine.map((r) => `${r.proto} ${r.dest} ${r.port}`), ['tcp 9.9.9.9 853', 'udp 9.9.9.9 853']);
  for (const r of [...mine].reverse()) run(UB!, iptDelete(r));
  for (const c of iptAdd(spec({ action: 'reject', source: '2001:db8::7', first: true, comment: 'it v6' }), 0, 'x')) run(UB!, c);
  const in6 = parseIptList(run(UB!, { command: 'ipt-list', args: ['ip6tables', 'filter'] }), 'filter', true).find((c) => c.name === 'INPUT')!.rules;
  assert.equal(in6[0].comment, 'it v6');
  run(UB!, iptDelete(in6[0]));
});

test('firewalld: ports, rich rules, remove', { skip: !FED }, () => {
  const ops = [...fwdOps(spec({ proto: 'any', port: '9000-9001' })), ...fwdOps(spec({ action: 'reject', source: '198.51.100.0/24', port: '22' }))];
  for (const c of fwdCalls('public', ops, 'both')) run(FED!, c);
  for (const config of ['runtime', 'permanent']) {
    const z = parseFirewalldInfo(run(FED!, { command: 'fwd-info', args: [config] })).zones.find((x) => x.name === 'public')!;
    assert.ok(z.ports.includes('9000-9001/tcp') && z.ports.includes('9000-9001/udp'), config);
    assert.ok(z.richRules.some((r) => r.includes('198.51.100.0/24')), config);
  }
  const z = parseFirewalldInfo(run(FED!, { command: 'fwd-info', args: ['runtime'] })).zones.find((x) => x.name === 'public')!;
  const mine = zoneRules(z).filter((r) => r.text.includes('9000-9001') || r.text.includes('198.51.100.0/24'));
  for (const c of fwdCalls('public', mine.map(fwdRemoveOp), 'both')) run(FED!, c);
  const after = parseFirewalldInfo(run(FED!, { command: 'fwd-info', args: ['permanent'] })).zones.find((x) => x.name === 'public')!;
  assert.equal(after.ports.some((p) => p.startsWith('9000')), false);
});
