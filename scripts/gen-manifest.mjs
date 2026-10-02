#!/usr/bin/env node
/**
 * Writes plugin/manifest.json. The manifest is the file that ships; this script exists so the command variants, their
 * argument patterns and the small shell scripts are written once and stay consistent.
 *
 *   node scripts/gen-manifest.mjs          # rewrite plugin/manifest.json
 *   node scripts/gen-manifest.mjs --check  # exit 1 when the file is out of date
 *
 * Rules of the Ervisio daemon (server/internal/modules/plugins/manifest.go) that shape this file: at most 64 commands,
 * 16 args per command, every pattern at most 256 characters and matched against the whole value, values starting with
 * "-" refused unless allowDash. No command goes through a shell with user input: the `sh -c` scripts below are fixed
 * text and only read their positional parameters, which the daemon validated against an enumerated pattern.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const file = join(root, 'plugin', 'manifest.json');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));

/* ---------- argument patterns (each matches the whole value) ---------- */

const IP4 = '[0-9]{1,3}(\\.[0-9]{1,3}){3}(/[0-9]{1,2})?';
const IP6 = '[0-9a-fA-F:]*:[0-9a-fA-F:.]*(/[0-9]{1,3})?';
export const P = {
  ufwAction: { pattern: 'allow|deny|reject|limit', maxLen: 6 },
  dir: { pattern: 'in|out', maxLen: 3 },
  proto: { pattern: 'tcp|udp', maxLen: 3 },
  addr: { pattern: `any|${IP4}|${IP6}`, maxLen: 49 },
  ufwPort: { pattern: '[0-9]{1,5}(:[0-9]{1,5})?(,[0-9]{1,5}(:[0-9]{1,5})?){0,14}', maxLen: 120 },
  iface: { pattern: '[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,14}', maxLen: 15 },
  comment: { pattern: '[\\p{L}\\p{N}][\\p{L}\\p{N} _.,:/@()+-]{0,63}', maxLen: 256 },
  app: { pattern: '[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,63}', maxLen: 64 },
  ruleNum: { pattern: '[1-9][0-9]{0,3}', maxLen: 4 },
  zone: { pattern: '[A-Za-z0-9][A-Za-z0-9_-]{0,31}', maxLen: 32 },
  nftFamily: { pattern: 'ip|ip6|inet|arp|bridge|netdev', maxLen: 6 },
  nftName: { pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,63}', maxLen: 64 },
  nftExpr: { pattern: '[A-Za-z0-9][A-Za-z0-9 .:/,{}_"@!=<>*+-]{0,399}', maxLen: 400 },
  handle: { pattern: '[0-9]{1,9}', maxLen: 9 },
  iptBin: { pattern: 'iptables|ip6tables', maxLen: 9 },
  iptChain: { pattern: '[A-Za-z][A-Za-z0-9_-]{0,28}', maxLen: 29 },
  iptPos: { pattern: '[1-9][0-9]{0,4}', maxLen: 5 },
  iptPorts: { pattern: '[0-9]{1,5}(:[0-9]{1,5})?(,[0-9]{1,5}(:[0-9]{1,5})?){0,14}', maxLen: 120 },
  iptTarget: { pattern: 'ACCEPT|DROP|REJECT|LOG|RETURN', maxLen: 6 },
  jail: { pattern: '[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', maxLen: 64 },
  ip: { pattern: `${IP4}|${IP6}`, maxLen: 49 },
  lines: { pattern: '[1-9][0-9]{0,4}', maxLen: 5 },
  since: { pattern: '-[0-9]{1,4}(min|h|d)|today|yesterday|[0-9]{4}-[0-9]{2}-[0-9]{2}( [0-9]{2}:[0-9]{2}(:[0-9]{2})?)?', maxLen: 19, allowDash: true },
  logFile: { pattern: '/var/log/(ufw\\.log|kern\\.log|messages|syslog|firewalld|fail2ban\\.log)(\\.1)?', maxLen: 40 },
  backend: { pattern: 'ufw|firewalld|nftables|iptables|fail2ban', maxLen: 9 },
};

/** Commands are written with named slots ({action}); this turns them into the daemon's {N} slots and args list. */
function cmd(name, description, tokens, specs, extra = {}) {
  const order = [];
  const argv = tokens.map((tok) =>
    tok.replace(/\{([a-zA-Z][a-zA-Z0-9]*)\}/g, (_, n) => {
      if (!(n in specs)) throw new Error(`${name}: no spec for {${n}}`);
      if (!order.includes(n)) order.push(n);
      return `{${order.indexOf(n)}}`;
    }),
  );
  for (const n of Object.keys(specs)) if (!order.includes(n)) throw new Error(`${name}: {${n}} is never used`);
  const c = { name, description, argv };
  if (order.length) c.args = order.map((n) => ({ ...specs[n] }));
  return { ...c, ...extra };
}

const ADMIN = { admin: true };
const ADM_LOG = { admin: true, adminUnlessGroup: 'adm' };

/* ---------- fixed scripts ---------- */

const DETECT = [
  'for c in ufw firewall-cmd nft iptables ip6tables fail2ban-client ss; do p=$(command -v "$c" 2>/dev/null) || p=; echo "bin|$c|$p"; done',
  'iptables --version 2>/dev/null | head -1 | sed "s/^/ver|iptables|/"',
  'nft --version 2>/dev/null | head -1 | sed "s/^/ver|nft|/"',
  'firewall-cmd --version 2>/dev/null | head -1 | sed "s/^/ver|firewalld|/"',
  'fail2ban-client --version 2>/dev/null | head -1 | sed "s/^/ver|fail2ban|/"',
  'for u in ufw firewalld nftables fail2ban netfilter-persistent iptables; do echo "unit|$u|$(systemctl is-active "$u" 2>/dev/null)|$(systemctl is-enabled "$u" 2>/dev/null)"; done',
  '[ -r /etc/ufw/ufw.conf ] && grep -E "^ENABLED=" /etc/ufw/ufw.conf | sed "s/^/ufwconf|/"',
  'echo "tz|$(date +%z)"',
  'exit 0',
].join('\n');

const UFW_STATUS = [
  'export LC_ALL=C',
  'echo @@VERSION; ufw version 2>/dev/null | head -1',
  'echo @@VERBOSE; ufw status verbose',
  'echo @@NUMBERED; ufw status numbered',
  'echo @@ADDED; ufw show added',
  'echo @@CONF; grep -hE "^(ENABLED|LOGLEVEL|IPV6|DEFAULT_(INPUT|OUTPUT|FORWARD)_POLICY)=" /etc/ufw/ufw.conf /etc/default/ufw 2>/dev/null',
  'exit 0',
].join('\n');

const FWD_INFO = [
  'P=; [ "$1" = permanent ] && P=--permanent',
  'echo @@STATE; firewall-cmd --state 2>&1',
  'echo @@VERSION; firewall-cmd --version 2>&1',
  'echo @@DEFAULT; firewall-cmd --get-default-zone 2>&1',
  'echo @@ACTIVE; firewall-cmd --get-active-zones 2>&1',
  'echo @@LOGDENIED; firewall-cmd --get-log-denied 2>&1',
  'echo @@SERVICES; firewall-cmd $P --get-services 2>&1',
  'echo @@ZONES; firewall-cmd $P --list-all-zones 2>&1',
  'exit 0',
].join('\n');

const NFT_SAVE = [
  'f="$1"; t="$f.ervisio-tmp"',
  "{ echo '#!/usr/sbin/nft -f'; echo 'flush ruleset'; echo; nft list ruleset; } > \"$t\" || { rm -f \"$t\"; exit 1; }",
  'chmod 0644 "$t"',
  '[ -e "$f" ] && cp -p "$f" "$f.bak"',
  'mv "$t" "$f" && echo "$f"',
].join('\n');

const IPT_SAVE = [
  'f="$1"',
  'case "$f" in *v6|*ip6tables) b=ip6tables-save;; *) b=iptables-save;; esac',
  'mkdir -p "$(dirname "$f")" || exit 1',
  '"$b" > "$f.ervisio-tmp" || { rm -f "$f.ervisio-tmp"; exit 1; }',
  '[ -e "$f" ] && cp -p "$f" "$f.bak"',
  'mv "$f.ervisio-tmp" "$f" && echo "$f"',
].join('\n');

const F2B_STATUS = [
  'fail2ban-client ping >/dev/null 2>&1 || { echo @@DOWN; exit 0; }',
  'echo "@@VERSION $(fail2ban-client --version 2>/dev/null | head -1)"',
  'jails=$(fail2ban-client status | sed -n "s/.*Jail list:[[:space:]]*//p" | tr "," " ")',
  'for j in $jails; do echo "@@JAIL $j"; fail2ban-client status "$j"; done',
  'exit 0',
].join('\n');

/** Prints "active" or "inactive" and always exits 0, so a job step can compare it with the last run. */
const STATE = [
  'case "$1" in',
  "  ufw) LC_ALL=C ufw status | head -1 | grep -q 'Status: active' && s=active || s=inactive;;",
  '  firewalld) firewall-cmd --state >/dev/null 2>&1 && s=active || s=inactive;;',
  "  nftables) nft list ruleset 2>/dev/null | grep -q 'hook input' && s=active || s=inactive;;",
  "  iptables) [ \"$(iptables -S INPUT 2>/dev/null | wc -l)\" -gt 1 ] || iptables -S INPUT 2>/dev/null | grep -q '^-P INPUT DROP' && s=active || s=inactive;;",
  '  fail2ban) fail2ban-client ping >/dev/null 2>&1 && s=active || s=inactive;;',
  'esac',
  'echo "$s"',
].join('\n');

const GREP = { pattern: '--grep=IN=\\.\\*OUT=|--no-hostname', maxLen: 16, allowDash: true };

/* ---------- commands ---------- */

const ufwRule = (prefix, tail) => ['ufw', ...prefix, '{action}', '{dir}', ...tail, 'comment', '{comment}'];
const FROM_TO = ['from', '{src}', 'to', '{dst}'];
const U = { action: P.ufwAction, dir: P.dir, src: P.addr, dst: P.addr, comment: P.comment };

const commands = [
  /* Detection and state, no administrator rights */
  cmd('detect', 'Find which firewalls are installed and running', ['sh', '-c', DETECT], {}),
  cmd('listening', 'List the ports that programs listen on (ss)', ['ss', '-Htulnp'], {}, ADMIN),
  cmd('state', 'Tell whether a firewall is active (used by the watchdog job)', ['sh', '-c', STATE, 'sh', '{backend}'], { backend: P.backend }, ADMIN),

  /* ufw */
  cmd('ufw-status', 'Read ufw status, rules and settings', ['sh', '-c', UFW_STATUS], {}, ADMIN),
  cmd('ufw-enable', 'Turn ufw on', ['ufw', '--force', 'enable'], {}, ADMIN),
  cmd('ufw-disable', 'Turn ufw off', ['ufw', 'disable'], {}, ADMIN),
  cmd('ufw-reload', 'Reload ufw', ['ufw', 'reload'], {}, ADMIN),
  cmd('ufw-default', 'Set a default ufw policy', ['ufw', 'default', '{policy}', '{chain}'], { policy: { pattern: 'allow|deny|reject', maxLen: 6 }, chain: { pattern: 'incoming|outgoing|routed', maxLen: 8 } }, ADMIN),
  cmd('ufw-logging', 'Set the ufw log level', ['ufw', 'logging', '{level}'], { level: { pattern: 'off|on|low|medium|high|full', maxLen: 6 } }, ADMIN),
  cmd('ufw-delete', 'Delete a ufw rule by number', ['ufw', '--force', 'delete', '{num}'], { num: P.ruleNum }, ADMIN),
  cmd('ufw-apps', 'List ufw application profiles', ['ufw', 'app', 'list'], {}, ADMIN),
  cmd('ufw-port', 'Add a ufw rule for a port and protocol', ufwRule([], ['proto', '{proto}', ...FROM_TO, 'port', '{port}']), { ...U, proto: P.proto, port: P.ufwPort }, ADMIN),
  cmd('ufw-port-any', 'Add a ufw rule for a port, TCP and UDP', ufwRule([], [...FROM_TO, 'port', '{port}']), { ...U, port: P.ufwPort }, ADMIN),
  cmd('ufw-host', 'Add a ufw rule for addresses only', ufwRule([], FROM_TO), U, ADMIN),
  cmd('ufw-app', 'Add a ufw rule for an application profile', ufwRule([], [...FROM_TO, 'app', '{app}']), { ...U, app: P.app }, ADMIN),
  cmd('ufw-port-if', 'Add a ufw rule for a port on one interface', ufwRule([], ['on', '{iface}', 'proto', '{proto}', ...FROM_TO, 'port', '{port}']), { ...U, iface: P.iface, proto: P.proto, port: P.ufwPort }, ADMIN),
  cmd('ufw-host-if', 'Add a ufw rule for addresses on one interface', ufwRule([], ['on', '{iface}', ...FROM_TO]), { ...U, iface: P.iface }, ADMIN),
  cmd('ufw-first-host', 'Add a ufw rule for addresses before all others', ufwRule(['prepend'], FROM_TO), U, ADMIN),
  cmd('ufw-first-port', 'Add a ufw rule for a port before all others', ufwRule(['prepend'], ['proto', '{proto}', ...FROM_TO, 'port', '{port}']), { ...U, proto: P.proto, port: P.ufwPort }, ADMIN),

  /* firewalld: {mode} is --permanent or --quiet (runtime) */
  cmd('fwd-info', 'Read firewalld state, zones and services', ['sh', '-c', FWD_INFO, 'sh', '{config}'], { config: { pattern: 'runtime|permanent', maxLen: 9 } }, ADMIN),
  cmd('fwd-change', 'Add or remove a service, port, source, interface or masquerading in a firewalld zone', ['firewall-cmd', '{mode}', '--zone={zone}', '{op}'], {
    mode: { pattern: '--permanent|--quiet', maxLen: 11, allowDash: true },
    zone: P.zone,
    op: { pattern: '--(add|remove)-(service=[a-zA-Z0-9][a-zA-Z0-9_.+-]{0,63}|port=[0-9]{1,5}(-[0-9]{1,5})?/(tcp|udp|sctp|dccp)|source=[0-9a-fA-F.:/]{2,49}|interface=[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,14}|masquerade)', maxLen: 96, allowDash: true },
  }, ADMIN),
  cmd('fwd-rich', 'Add or remove a firewalld rich rule', ['firewall-cmd', '{mode}', '--zone={zone}', '{op}'], {
    mode: { pattern: '--permanent|--quiet', maxLen: 11, allowDash: true },
    zone: P.zone,
    op: { pattern: '--(add|remove)-rich-rule=rule [A-Za-z0-9 ="./:_,-]{1,480}', maxLen: 520, allowDash: true },
  }, ADMIN),
  cmd('fwd-forward', 'Add or remove a firewalld port forward', ['firewall-cmd', '{mode}', '--zone={zone}', '{op}'], {
    mode: { pattern: '--permanent|--quiet', maxLen: 11, allowDash: true },
    zone: P.zone,
    op: { pattern: '--(add|remove)-forward-port=port=[0-9]{1,5}(-[0-9]{1,5})?:proto=(tcp|udp|sctp|dccp)(:toport=[0-9]{1,5}(-[0-9]{1,5})?)?(:toaddr=[0-9a-fA-F.:]{2,39})?', maxLen: 120, allowDash: true },
  }, ADMIN),
  cmd('fwd-default-zone', 'Set the firewalld default zone', ['firewall-cmd', '--set-default-zone={zone}'], { zone: P.zone }, ADMIN),
  cmd('fwd-reload', 'Reload firewalld', ['firewall-cmd', '--reload'], {}, ADMIN),
  cmd('fwd-persist', 'Save the firewalld runtime configuration as permanent', ['firewall-cmd', '--runtime-to-permanent'], {}, ADMIN),
  cmd('fwd-log-denied', 'Set which denied packets firewalld logs', ['firewall-cmd', '--set-log-denied={level}'], { level: { pattern: 'all|unicast|broadcast|multicast|off', maxLen: 9 } }, ADMIN),

  /* nftables */
  cmd('nft-list', 'Read the nftables ruleset with rule handles', ['nft', '-a', 'list', 'ruleset'], {}, ADMIN),
  cmd('nft-rule', 'Add or insert an nftables rule', ['nft', '{op}', 'rule', '{family}', '{table}', '{chain}', '{expr}'], { op: { pattern: 'add|insert', maxLen: 6 }, family: P.nftFamily, table: P.nftName, chain: P.nftName, expr: P.nftExpr }, ADMIN),
  cmd('nft-delete-rule', 'Delete an nftables rule by handle', ['nft', 'delete', 'rule', '{family}', '{table}', '{chain}', 'handle', '{handle}'], { family: P.nftFamily, table: P.nftName, chain: P.nftName, handle: P.handle }, ADMIN),
  cmd('nft-table', 'Add, flush or delete an nftables table', ['nft', '{op}', 'table', '{family}', '{table}'], { op: { pattern: 'add|flush|delete', maxLen: 6 }, family: P.nftFamily, table: P.nftName }, ADMIN),
  cmd('nft-chain', 'Add, flush or delete a regular nftables chain', ['nft', '{op}', 'chain', '{family}', '{table}', '{chain}'], { op: { pattern: 'add|flush|delete', maxLen: 6 }, family: P.nftFamily, table: P.nftName, chain: P.nftName }, ADMIN),
  cmd('nft-base-chain', 'Add an nftables base chain attached to a hook', ['nft', 'add', 'chain', '{family}', '{table}', '{chain}', '{', 'type', '{type}', 'hook', '{hook}', 'priority', '{priority}', ';', 'policy', '{policy}', ';', '}'], {
    family: P.nftFamily, table: P.nftName, chain: P.nftName,
    type: { pattern: 'filter|nat|route', maxLen: 6 },
    hook: { pattern: 'prerouting|input|forward|output|postrouting|ingress', maxLen: 11 },
    priority: { pattern: '-?[0-9]{1,4}|raw|mangle|dstnat|filter|security|srcnat', maxLen: 8, allowDash: true },
    policy: { pattern: 'accept|drop', maxLen: 6 },
  }, ADMIN),
  cmd('nft-policy', 'Set the policy of an nftables base chain', ['nft', 'chain', '{family}', '{table}', '{chain}', '{', 'policy', '{policy}', ';', '}'], { family: P.nftFamily, table: P.nftName, chain: P.nftName, policy: { pattern: 'accept|drop', maxLen: 6 } }, ADMIN),
  cmd('nft-save', 'Save the nftables ruleset to the file loaded at boot (keeps a .bak copy)', ['sh', '-c', NFT_SAVE, 'sh', '{file}'], { file: { pattern: '/etc/nftables\\.conf|/etc/sysconfig/nftables\\.conf', maxLen: 32 } }, ADMIN),

  /* iptables / ip6tables, through `sh -c 'exec "$0" "$@"'` so one command covers both programs */
  cmd('ipt-list', 'Read an iptables table with rule numbers and counters', ['sh', '-c', 'exec "$0" -w -t "$1" -L -n -v -x --line-numbers', '{bin}', '{table}'], { bin: P.iptBin, table: { pattern: 'filter|nat|mangle|raw', maxLen: 6 } }, ADMIN),
  cmd('ipt-port', 'Insert an iptables rule for ports', ['sh', '-c', 'exec "$0" "$@"', '{bin}', '-w', '-I', '{chain}', '{pos}', '-p', '{proto}', '-s', '{src}', '-d', '{dst}', '-m', 'multiport', '--dports', '{ports}', '-m', 'comment', '--comment', '{comment}', '-j', '{target}'], {
    bin: P.iptBin, chain: P.iptChain, pos: P.iptPos, proto: P.proto, src: P.ip, dst: P.ip, ports: P.iptPorts, comment: P.comment, target: P.iptTarget,
  }, ADMIN),
  cmd('ipt-host', 'Insert an iptables rule for addresses and a protocol', ['sh', '-c', 'exec "$0" "$@"', '{bin}', '-w', '-I', '{chain}', '{pos}', '-p', '{proto}', '-s', '{src}', '-d', '{dst}', '-m', 'comment', '--comment', '{comment}', '-j', '{target}'], {
    bin: P.iptBin, chain: P.iptChain, pos: P.iptPos, proto: { pattern: 'tcp|udp|icmp|ipv6-icmp|all', maxLen: 9 }, src: P.ip, dst: P.ip, comment: P.comment, target: P.iptTarget,
  }, ADMIN),
  cmd('ipt-delete', 'Delete an iptables rule by number', ['sh', '-c', 'exec "$0" -w -D "$1" "$2"', '{bin}', '{chain}', '{pos}'], { bin: P.iptBin, chain: P.iptChain, pos: P.iptPos }, ADMIN),
  cmd('ipt-policy', 'Set the policy of a built-in iptables chain', ['sh', '-c', 'exec "$0" -w -P "$1" "$2"', '{bin}', '{chain}', '{policy}'], { bin: P.iptBin, chain: { pattern: 'INPUT|FORWARD|OUTPUT', maxLen: 7 }, policy: { pattern: 'ACCEPT|DROP', maxLen: 6 } }, ADMIN),
  cmd('ipt-save', 'Save iptables rules to the file loaded at boot (keeps a .bak copy)', ['sh', '-c', IPT_SAVE, 'sh', '{file}'], { file: { pattern: '/etc/iptables/rules\\.v[46]|/etc/sysconfig/ip6?tables', maxLen: 24 } }, ADMIN),

  /* fail2ban */
  cmd('f2b-status', 'Read fail2ban jails and banned addresses', ['sh', '-c', F2B_STATUS], {}, ADMIN),
  cmd('f2b-set', 'Ban or unban an address in a fail2ban jail', ['fail2ban-client', 'set', '{jail}', '{op}', '{ip}'], { jail: P.jail, op: { pattern: 'banip|unbanip', maxLen: 7 }, ip: P.ip }, ADMIN),

  /* Logs: the kernel log, where every firewall writes the packets it logs */
  cmd('log-journal', 'Read firewall lines from the kernel journal', ['journalctl', '-k', '--no-pager', '-o', 'short-iso-precise', '--since={since}', '-n', '{lines}', '{grep}'], { since: P.since, lines: P.lines, grep: GREP }, { ...ADM_LOG, timeoutSec: 60 }),
  cmd('log-journal-follow', 'Follow firewall lines in the kernel journal', ['journalctl', '-k', '-f', '-n', '0', '--no-pager', '-o', 'short-iso-precise', '{grep}'], { grep: GREP }, { ...ADM_LOG, timeoutSec: 600 }),
  cmd('log-file', 'Read the last lines of a firewall log file', ['tail', '-n', '{lines}', '{file}'], { lines: P.lines, file: P.logFile }, { ...ADM_LOG, timeoutSec: 60 }),
  cmd('log-file-follow', 'Follow a firewall log file', ['tail', '-n', '0', '-F', '{file}'], { file: P.logFile }, { ...ADM_LOG, timeoutSec: 600 }),
];

const manifest = {
  id: 'firewall',
  name: 'Firewall',
  version: pkg.version,
  author: 'Ervisio team',
  homepage: 'https://github.com/Ervisio/plugin-firewall',
  description: 'Manage ufw, firewalld, nftables and iptables from Ervisio: rules, zones, default policies, firewall logs and fail2ban bans, with a guard that keeps SSH open.',
  icon: 'shield',
  color: 'usr',
  entry: 'index.js',
  minCore: '0.5.0',
  capabilities: {
    commands,
    files: { write: [{ path: '~/.config/ervisio/plugins/firewall', create: true }] },
    notify: true,
    jobs: [
      {
        name: 'watchdog',
        description: 'Check that a firewall is running and send a notification when its state changes.',
        timeoutSec: 60,
        params: [{ name: 'backend', pattern: P.backend.pattern, maxLen: 9, description: 'ufw, firewalld, nftables, iptables or fail2ban' }],
        steps: [
          { id: 'check', command: 'state', args: ['{param.backend}'] },
          { id: 'tell', if: { step: 'check', when: 'changed' }, notify: { title: 'Firewall {param.backend}: {step.check.stdout}', body: 'The {param.backend} firewall is now {step.check.stdout} on this server.', level: 'warn', link: '/p/firewall/firewall' } },
        ],
      },
    ],
  },
  contributes: {
    pages: [{ id: 'firewall', title: 'Firewall', icon: 'shield' }],
    widgets: [{ id: 'status', title: 'Firewall', icon: 'shield' }],
    snippets: [
      { name: 'ufw status', command: 'sudo ufw status verbose' },
      { name: 'firewalld zones', command: 'sudo firewall-cmd --list-all-zones' },
      { name: 'nftables ruleset', command: 'sudo nft -a list ruleset' },
      { name: 'Firewall log (live)', command: "sudo journalctl -k -f --grep='IN=.*OUT='" },
    ],
  },
};

// Checks the daemon would make, so a mistake shows here and not at load time.
if (commands.length > 64) throw new Error(`${commands.length} commands, the daemon allows 64`);
for (const c of commands) {
  if ((c.args ?? []).length > 16) throw new Error(`${c.name}: more than 16 args`);
  for (const a of c.args ?? []) if (a.pattern.length > 256) throw new Error(`${c.name}: pattern longer than 256`);
  if (!/^[a-zA-Z][a-zA-Z0-9_-]{0,31}$/.test(c.name)) throw new Error(`${c.name}: bad name`);
}
if (new Set(commands.map((c) => c.name)).size !== commands.length) throw new Error('duplicate command name');

const text = JSON.stringify(manifest, null, 2) + '\n';
if (process.argv.includes('--check')) {
  let cur = '';
  try {
    cur = readFileSync(file, 'utf8');
  } catch {
    /* missing */
  }
  if (cur !== text) {
    console.error('plugin/manifest.json is out of date: run `npm run manifest`');
    process.exit(1);
  }
} else {
  writeFileSync(file, text);
  console.log(`plugin/manifest.json: ${commands.length} commands`);
}
