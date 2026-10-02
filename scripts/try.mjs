#!/usr/bin/env node
/**
 * Runs a manifest command the way the Ervisio daemon does (argv with the {N} slots filled, each argument checked against
 * its pattern, no shell), inside a Docker container. For testing against real firewalls without a server:
 *
 *   docker run -d --privileged --name fwtest ubuntu:24.04 sleep infinity
 *   docker exec fwtest bash -c 'apt-get update && apt-get install -y ufw nftables iptables fail2ban iproute2'
 *   node scripts/try.mjs fwtest ufw-port allow in tcp any any 443 "web server"
 *
 * Prints stdout, stderr and the exit code.
 */
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const manifest = JSON.parse(readFileSync(join(root, 'plugin', 'manifest.json'), 'utf8'));

/** Fills the argv of `name` with `args` after the daemon's checks; throws when an argument is refused. */
export function buildArgv(name, args) {
  const c = manifest.capabilities.commands.find((x) => x.name === name);
  if (!c) throw new Error(`no command ${name}`);
  const specs = c.args ?? [];
  if (args.length !== specs.length) throw new Error(`${name} takes ${specs.length} arguments, got ${args.length}`);
  args.forEach((a, i) => {
    const s = specs[i];
    if (a.length > (s.maxLen || 256)) throw new Error(`argument ${i + 1} too long`);
    if (a.startsWith('-') && !s.allowDash) throw new Error(`argument ${i + 1} starts with "-"`);
    if (!new RegExp(`^(?:${s.pattern})$`, 'u').test(a)) throw new Error(`argument ${i + 1} (${JSON.stringify(a)}) does not match ${s.pattern}`);
  });
  return c.argv.map((item) => item.replace(/\{(\d+)\}/g, (_, n) => args[Number(n)]));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const [container, name, ...args] = process.argv.slice(2);
  if (!container || !name) {
    console.error('usage: node scripts/try.mjs <container> <command> [args...]');
    process.exit(2);
  }
  const argv = buildArgv(name, args);
  const r = spawnSync('docker', ['exec', container, ...argv], { encoding: 'utf8' });
  process.stdout.write(r.stdout ?? '');
  if (r.stderr) process.stderr.write(`--- stderr\n${r.stderr}`);
  console.log(`--- exit ${r.status}`);
}
