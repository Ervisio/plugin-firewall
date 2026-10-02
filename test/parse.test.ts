/** Parsers against real output captured from ufw 0.36.2, nftables 1.0.9, iptables 1.8.10, fail2ban 1.0.2 (Ubuntu 24.04). */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseAddedRule, parseSide, parseUfwStatus, sections } from '../src/parse/ufw.ts';
import { parseNftRuleset } from '../src/parse/nftables.ts';
import { parseIptList } from '../src/parse/iptables.ts';
import { isNoise, parseDetect, parseF2b, parseListeners, parseLogLine, pickBackend, sshPortFrom } from '../src/parse/misc.ts';

const fx = (name: string) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');

test('ufw: active status, numbered rules', () => {
  const s = parseUfwStatus(fx('ufw-status.txt'));
  assert.equal(s.active, true);
  assert.equal(s.version, '0.36.2');
  assert.equal(s.logging, 'medium');
  assert.deepEqual(s.defaults, { incoming: 'deny', outgoing: 'allow', routed: 'deny' });
  assert.equal(s.rules.length, 16);
  const [r1, r2, r3] = s.rules;
  assert.deepEqual([r1.action, r1.port, r1.proto, r1.source, r1.comment, r1.ref?.num], ['reject', '22', 'tcp', '198.51.100.8', 'reject ssh', '1']);
  assert.deepEqual([r2.action, r2.port, r2.source, r2.dest], ['deny', '', '198.51.100.7', 'any']);
  assert.equal(r3.comment, 'SSH');
  const range = s.rules[4];
  assert.deepEqual([range.port, range.proto, range.source], ['6000-6007', 'tcp', '10.0.0.0/8']);
  const ifRule = s.rules[7];
  assert.deepEqual([ifRule.dest, ifRule.port, ifRule.iface, ifRule.action, ifRule.comment], ['192.168.1.10', '443', 'eth0', 'allow', 'https eth0']);
  const app = s.rules[8];
  assert.equal(app.service, 'OpenSSH');
  const out = s.rules[9];
  assert.deepEqual([out.direction, out.dest, out.port, out.proto, out.source, out.comment], ['out', '8.8.8.8', '53', 'udp', 'any', 'out dns']);
  assert.equal(s.rules[10].comment, 'Città web');
  assert.equal(s.rules[10].port, '80,443');
  assert.equal(s.rules[15].v6, true);
  assert.equal(s.added.length, 11);
});

test('ufw: inactive status keeps the saved rules as commands', () => {
  const s = parseUfwStatus(fx('ufw-inactive.txt'));
  assert.equal(s.active, false);
  assert.equal(s.rules.length, 0);
  assert.ok(s.added.length >= 10);
  const r = parseAddedRule("ufw allow from 10.0.0.0/8 to any port 6000:6007 proto tcp comment 'X11 range'", 0);
  assert.deepEqual([r.action, r.source, r.port, r.proto, r.comment], ['allow', '10.0.0.0/8', '6000-6007', 'tcp', 'X11 range']);
  assert.deepEqual(s.defaults, { incoming: 'deny', outgoing: 'allow', routed: 'deny' });
  assert.equal(parseAddedRule("ufw allow OpenSSH comment 'app profile'", 2).service, 'OpenSSH');
  assert.equal(parseAddedRule("ufw allow 'Nginx Full'", 3).service, 'Nginx Full');
  assert.equal(parseAddedRule('ufw deny from 198.51.100.7', 4).service, undefined);
  const short = parseAddedRule("ufw allow 22/tcp comment 'SSH'", 1);
  assert.deepEqual([short.port, short.proto], ['22', 'tcp']);
});

test('ufw: columns', () => {
  assert.deepEqual(parseSide('Anywhere (v6) on eth0'), { addr: 'any', port: '', proto: 'any', app: undefined, iface: 'eth0', v6: true });
  assert.equal(parseSide('OpenSSH (v6)').app, 'OpenSSH');
  assert.equal(sections('@@A x\nline\n@@B\n').A, 'x\nline\n');
});

test('nftables: tables, base chains, handles and owners', () => {
  const tables = parseNftRuleset(fx('nft.txt'));
  const t = tables.find((x) => x.name === 'filter2')!;
  assert.equal(t.family, 'inet');
  assert.equal(t.managedBy, undefined);
  const input = t.chains.find((c) => c.name === 'input')!;
  assert.deepEqual([input.type, input.hook, input.priority, input.policy], ['filter', 'input', 'filter', 'drop']);
  assert.equal(input.rules.length, 5);
  assert.deepEqual(input.rules.map((r) => r.ref?.handle), ['6', '3', '5', '8', '10']);
  const [lo, ssh, drop, dns, rej] = input.rules;
  assert.equal(lo.iface, 'lo');
  assert.deepEqual([ssh.action, ssh.port, ssh.proto, ssh.comment, ssh.direction], ['allow', '22', 'tcp', 'ssh', 'in']);
  assert.deepEqual([drop.action, drop.source, drop.port, drop.packets], ['deny', '203.0.113.0/24', '80,443,6000-6007', 0]);
  assert.equal(dns.port, '53');
  assert.deepEqual([rej.action, rej.source], ['reject', '2001:db8::/32']);
  assert.equal(t.chains.find((c) => c.name === 'blocklist')!.rules.length, 0);
  const ufwTable = tables.find((x) => x.family === 'ip' && x.name === 'filter')!;
  assert.equal(ufwTable.managedBy, 'ufw');
});

test('iptables: numeric protocols, multiport, comments, owners', () => {
  const v4 = parseIptList(fx('ipt4.txt'), 'filter', false);
  const input = v4.find((c) => c.name === 'INPUT')!;
  assert.equal(input.policy, 'DROP');
  const [a, b, c] = input.rules;
  assert.deepEqual([a.action, a.proto, a.port, a.comment, a.ref?.num], ['allow', 'tcp', '22,80-90', 'web e ssh', '1']);
  assert.deepEqual([b.action, b.proto, b.source], ['deny', 'any', '203.0.113.9']);
  assert.equal(c.managedBy, 'ufw');
  assert.deepEqual([c.action, c.target], ['other', 'ufw-before-logging-input']);
  const v6 = parseIptList(fx('ipt6.txt'), 'filter', true);
  const in6 = v6.find((x) => x.name === 'INPUT')!.rules;
  assert.deepEqual([in6[0].proto, in6[0].source, in6[0].port, in6[0].ref?.bin], ['udp', '2001:db8::/32', '53', 'ip6tables']);
  assert.equal(in6[1].proto, 'ipv6-icmp');
  assert.ok(v4.some((ch) => ch.name.startsWith('ufw-') && ch.references !== undefined));
});

test('detect', () => {
  const d = parseDetect('bin|ufw|/usr/sbin/ufw\nbin|firewall-cmd|\nbin|nft|/usr/sbin/nft\nbin|iptables|/usr/sbin/iptables\nver|iptables|iptables v1.8.10 (nf_tables)\nunit|ufw|active|enabled\nunit|firewalld||not-found\nufwconf|ENABLED=yes\n');
  assert.equal(d.iptablesMode, 'nf_tables');
  assert.equal(d.ufwEnabled, true);
  assert.equal(d.bins['firewall-cmd'], undefined);
  assert.equal(pickBackend(d), 'ufw');
  assert.equal(pickBackend(parseDetect('bin|firewall-cmd|/usr/bin/firewall-cmd\nbin|ufw|/usr/sbin/ufw\nunit|firewalld|active|enabled\n')), 'firewalld');
  assert.equal(pickBackend(parseDetect('bin|nft|/usr/sbin/nft\n')), 'nftables');
});

test('listeners', () => {
  const l = parseListeners(fx('ss.txt'));
  assert.deepEqual(l.map((x) => `${x.proto}/${x.port}/${x.process}/${x.local}`), ['tcp/22/sshd/false', 'tcp/22/sshd/false', 'udp/5353/python3/true', 'tcp/8080/python3/false']);
  assert.equal(sshPortFrom(l), 22);
});

test('fail2ban', () => {
  const f = parseF2b(fx('f2b.txt'));
  assert.equal(f.running, true);
  assert.equal(f.version, '1.0.2');
  assert.equal(f.jails.length, 2);
  const sshd = f.jails.find((j) => j.name === 'sshd')!;
  assert.deepEqual(sshd.banned, ['192.0.2.50', '2001:db8::5']);
  assert.equal(sshd.currentlyBanned, 2);
  assert.deepEqual(sshd.files, ['/var/log/auth.log']);
  assert.deepEqual(f.jails.find((j) => j.name === 'recidive')!.banned, []);
  assert.equal(parseF2b('@@DOWN\n').running, false);
});

test('kernel log lines from the journal and from syslog files', () => {
  const j = parseLogLine('2026-10-02T21:14:05.123456+0200 web1 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=52:54:00:12:34:56:52:54:00:65:43:21:08:00 SRC=203.0.113.4 DST=10.0.0.2 LEN=40 TOS=0x00 PREC=0x00 TTL=244 ID=54321 PROTO=TCP SPT=43210 DPT=23 WINDOW=1024 RES=0x00 SYN URGP=0')!;
  assert.equal(j.verdict, 'block');
  assert.equal(j.prefix, '[UFW BLOCK]');
  assert.deepEqual([j.in, j.src, j.dst, j.proto, j.spt, j.dpt, j.ttl], ['eth0', '203.0.113.4', '10.0.0.2', 'tcp', 43210, 23, 244]);
  assert.deepEqual(j.flags, ['SYN']);
  assert.equal(new Date(j.time).toISOString(), '2026-10-02T19:14:05.123Z');
  const f = parseLogLine('Oct  2 21:14:05 web1 kernel: [123456.789012] [UFW ALLOW] IN=eth0 OUT= SRC=198.51.100.9 DST=10.0.0.2 LEN=60 PROTO=TCP SPT=5000 DPT=22', new Date(2026, 9, 3))!;
  assert.equal(f.verdict, 'allow');
  assert.equal(new Date(f.time).getDate(), 2);
  // Server at UTC+05:30, browser anywhere: the syslog time is the server's.
  const tzLine = parseLogLine('Oct  2 21:14:05 web1 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.9 DST=10.0.0.2 PROTO=TCP DPT=22', new Date(Date.UTC(2026, 9, 3)), 330)!;
  assert.equal(new Date(tzLine.time).toISOString(), '2026-10-02T15:44:05.000Z');
  assert.equal(parseDetect('tz|+0530').tzMinutes, 330);
  assert.equal(parseDetect('tz|-0700').tzMinutes, -420);
  const fw = parseLogLine('2026-10-02T21:14:05.000000+0000 kernel: filter_IN_public_REJECT: IN=ens3 OUT= SRC=192.0.2.1 DST=192.0.2.10 PROTO=UDP SPT=5353 DPT=5353 LEN=100')!;
  assert.deepEqual([fw.prefix, fw.verdict, fw.proto, fw.dpt], ['filter_IN_public_REJECT:', 'block', 'udp', 5353]);
  const v6 = parseLogLine('2026-10-02T21:14:05.000000+0000 host kernel: nft-drop: IN=eth0 OUT= SRC=2001:db8::1 DST=ff02::1 LEN=72 HOPLIMIT=255 PROTO=ICMPv6 TYPE=134')!;
  assert.equal(v6.ttl, 255);
  assert.equal(isNoise(v6), true);
  assert.equal(parseLogLine('2026-10-02T21:14:05+0000 host kernel: eth0: link up'), null);
});

test('firewalld: zones, rich rules, forward ports, services', async () => {
  const { parseFirewalldInfo, zoneRules } = await import('../src/parse/firewalld.ts');
  const f = parseFirewalldInfo(fx('firewalld.txt'));
  assert.equal(f.running, true);
  assert.equal(f.version, '2.3.2');
  assert.equal(f.defaultZone, 'public');
  assert.equal(f.logDenied, 'unicast');
  assert.ok(f.services.includes('ssh') && f.services.length > 100);
  const pub = f.zones.find((z) => z.name === 'public')!;
  assert.equal(pub.isDefault, true);
  assert.equal(pub.active, true);
  assert.deepEqual(pub.services, ['dhcpv6-client', 'http', 'mdns', 'ssh']);
  assert.deepEqual(pub.ports, ['8080/tcp', '6000-6007/udp']);
  assert.deepEqual(pub.sources, ['10.1.0.0/16']);
  assert.equal(pub.masquerade, true);
  assert.deepEqual(pub.forwardPorts, ['port=80:proto=tcp:toport=8080:toaddr=']);
  assert.equal(pub.richRules.length, 1);
  const rows = zoneRules(pub);
  const rich = rows.find((r) => r.ref?.kind === 'rich-rule')!;
  assert.deepEqual([rich.action, rich.source, rich.port, rich.proto], ['reject', '203.0.113.4', '22', 'tcp']);
  assert.equal(rows.find((r) => r.ref?.value === '6000-6007/udp')!.port, '6000-6007');
  assert.equal(f.zones.find((z) => z.name === 'trusted')!.target, 'ACCEPT');
});
