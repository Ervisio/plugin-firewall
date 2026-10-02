/** Types shared by the parsers, the backends and the views. No SDK or React here: tests import this file directly. */

export type BackendId = 'ufw' | 'firewalld' | 'nftables' | 'iptables';
export const BACKENDS: BackendId[] = ['ufw', 'firewalld', 'nftables', 'iptables'];

export type Action = 'allow' | 'deny' | 'reject' | 'limit' | 'log' | 'other';
export type Direction = 'in' | 'out' | 'fwd' | '';

/** One rule, whatever firewall it comes from, as the Rules table shows it. */
export interface Rule {
  /** Unique in a listing (React key). */
  key: string;
  action: Action;
  direction: Direction;
  /** tcp, udp, icmp... or "any". */
  proto: string;
  /** Destination ports as the user writes them: "22", "80,443", "6000-6007". Empty means every port. */
  port: string;
  /** "any" or an address / network. */
  source: string;
  dest: string;
  iface?: string;
  v6?: boolean;
  /** ufw application profile, firewalld service. */
  service?: string;
  comment?: string;
  /** The rule as the firewall writes it. */
  text: string;
  /** Zone (firewalld), table/chain (nftables), chain (iptables). */
  where?: string;
  /** Packets / bytes counters when the firewall reports them. */
  packets?: number;
  bytes?: number;
  /** What the backend needs to delete it. Absent when the rule cannot be deleted from here. */
  ref?: Record<string, string>;
  /** For action "other": the chain it jumps to or the target it uses (masquerade, DNAT...). */
  target?: string;
  /** Another tool manages this rule (Docker, firewalld, ufw seen through nftables...). */
  managedBy?: string;
}

/** The normalised "new rule" form, translated by each backend. */
export interface RuleSpec {
  action: 'allow' | 'deny' | 'reject' | 'limit';
  direction: 'in' | 'out';
  /** tcp, udp or any. */
  proto: 'tcp' | 'udp' | 'any';
  /** "22", "80,443", "6000-6007"; empty = every port. */
  port: string;
  source: string;
  dest: string;
  iface: string;
  comment: string;
  /** Put the rule before the others (ufw prepend, iptables position 1, nft insert). */
  first: boolean;
  /** ufw application profile instead of a port. */
  app?: string;
  /** firewalld zone. */
  zone?: string;
  /** nftables target chain "family table chain". */
  chain?: string;
  /** iptables: IPv6 (ip6tables). */
  v6?: boolean;
}

export interface Listener {
  proto: 'tcp' | 'udp';
  address: string;
  port: number;
  process: string;
  pid?: number;
  /** Bound to loopback only: not reachable from outside whatever the firewall says. */
  local: boolean;
}

export interface LogEntry {
  /** Milliseconds since the epoch; NaN when the line has no readable time. */
  time: number;
  /** The text before IN=: "[UFW BLOCK]", "filter_IN_public_REJECT:", ... */
  prefix: string;
  verdict: 'block' | 'allow' | 'audit' | 'limit' | 'log';
  in: string;
  out: string;
  src: string;
  dst: string;
  proto: string;
  spt?: number;
  dpt?: number;
  len?: number;
  ttl?: number;
  flags: string[];
  raw: string;
}

export interface Jail {
  name: string;
  currentlyFailed: number;
  totalFailed: number;
  currentlyBanned: number;
  totalBanned: number;
  banned: string[];
  files: string[];
}
