/** State of each firewall from the detect script alone (no administrator rights needed). */
import type { BackendId } from '../model';
import { installed, type Detected } from '../parse/misc';

export function backendActive(d: Detected, b: BackendId | 'fail2ban'): boolean {
  if (b === 'ufw') return d.ufwEnabled;
  if (b === 'firewalld') return d.units.firewalld?.active === 'active';
  if (b === 'nftables') return d.units.nftables?.active === 'active';
  if (b === 'fail2ban') return d.units.fail2ban?.active === 'active';
  return installed(d, 'iptables');
}

export function backendVersion(d: Detected, b: BackendId | 'fail2ban'): string {
  const v = b === 'nftables' ? d.versions.nft : b === 'firewalld' ? d.versions.firewalld : b === 'fail2ban' ? d.versions.fail2ban : b === 'iptables' ? d.versions.iptables : '';
  return (v ?? '').replace(/^(nftables|iptables|Fail2Ban)\s+v?/i, '').replace(/\s*\(.*$/, '');
}
