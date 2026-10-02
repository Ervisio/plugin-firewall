/** Small building blocks shared by the views. Styles in styles.css (fw- prefix). */
import type { ReactNode } from 'react';
import { errorText } from '../api';
import { t } from '../i18n';
import type { Action, Rule } from '../model';
import { Badge, Button, Checkbox, Icon, type Tone } from '../kit';
import { getSdk } from '../sdk';

/** Icons the app kit does not have. */
export function registerIcons(): void {
  const reg = getSdk().ui.registerIcon as ((name: string, svg: string) => void) | undefined;
  if (!reg) return;
  reg('ban', '<circle cx="12" cy="12" r="8.5"/><path d="M6 6l12 12"/>');
  reg('flame', '<path d="M12 3c1 3.5 5 5.5 5 10a5 5 0 0 1-10 0c0-2.5 1.5-4 2.5-5 .3 1.6 1.2 2.6 2.2 3 .2-3-.7-5.5.3-8z"/>');
  reg('ports', '<rect x="3" y="7" width="18" height="10" rx="2"/><path d="M7 11v2M11 11v2M15 11v2"/>');
}

export function PageHeader({ icon, title, subtitle, actions }: { icon: string; title: ReactNode; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="fw-ph">
      <span className="fw-ph-ic"><Icon name={icon} /></span>
      <div className="fw-ph-tx">
        <h1>{title}</h1>
        {subtitle && <p>{subtitle}</p>}
      </div>
      {actions && <div className="fw-ph-act">{actions}</div>}
    </header>
  );
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?(): void }) {
  return (
    <div className="fw-err" role="alert">
      <Icon name="alert" />
      <div>
        <b>{t('err.title')}</b>
        <p className="fw-mono">{errorText(error)}</p>
      </div>
      {onRetry && <Button variant="secondary" size="sm" icon="refresh" onClick={onRetry}>{t('common.retry')}</Button>}
    </div>
  );
}

export function Hint({ tone = 'info', icon = 'info', children, action }: { tone?: 'info' | 'warn' | 'err' | 'ok'; icon?: string; children: ReactNode; action?: ReactNode }) {
  return (
    <div className={`fw-hint fw-hint--${tone}`}>
      <Icon name={icon} />
      <div className="fw-hint-tx">{children}</div>
      {action}
    </div>
  );
}

const ACTION_TONE: Record<Action, Tone> = { allow: 'ok', limit: 'info', deny: 'err', reject: 'warn', log: 'neutral', other: 'neutral' };
export const ActionBadge = ({ action }: { action: Action }) => <Badge tone={ACTION_TONE[action]}>{t(`action.${action}`)}</Badge>;

/** "22/tcp", "80,443/tcp", "OpenSSH", "any". */
export function portLabel(r: Rule): string {
  if (r.service && !r.port) return r.service;
  if (!r.port) return r.proto === 'any' ? t('common.allPorts') : `${t('common.allPorts')} (${r.proto})`;
  return r.proto === 'any' ? r.port : `${r.port}/${r.proto}`;
}

export const addrLabel = (a: string): string => (a === 'any' || !a ? t('common.anywhere') : a);

export interface DataColumn<T> {
  key: string;
  header?: ReactNode;
  render(row: T): ReactNode;
  align?: 'left' | 'right';
  width?: number | string;
  hideBelow?: 'sm' | 'md';
}

/** Table in Ervisio's style: each row is a tinted rounded bar, no divider lines. */
export function DataTable<T>({ columns, rows, rowKey, rowClass, empty, selectable, selected, onSelectedChange }: {
  columns: DataColumn<T>[];
  rows: T[];
  rowKey(row: T): string;
  rowClass?(row: T): string | undefined;
  empty?: ReactNode;
  selectable?: boolean;
  selected?: ReadonlySet<string>;
  onSelectedChange?(keys: Set<string>): void;
}) {
  if (!rows.length && empty) return <>{empty}</>;
  const sel = selected ?? new Set<string>();
  const cls = (c: DataColumn<T>) => [c.align === 'right' ? 'fw-num' : '', c.hideBelow ? `fw-hide-${c.hideBelow}` : ''].filter(Boolean).join(' ');
  const toggle = (k: string, on: boolean) => {
    const n = new Set(sel);
    if (on) n.add(k);
    else n.delete(k);
    onSelectedChange?.(n);
  };
  return (
    <div className="fw-tablewrap">
      <table className="fw-table">
        <thead>
          <tr>
            {selectable && <th className="fw-cb"><Checkbox checked={rows.length > 0 && rows.every((r) => sel.has(rowKey(r)))} onChange={(on) => onSelectedChange?.(on ? new Set(rows.map(rowKey)) : new Set())} aria-label={t('common.selectAll')} /></th>}
            {columns.map((c) => <th key={c.key} className={cls(c)} style={{ width: c.width }}>{c.header}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const k = rowKey(r);
            return (
              <tr key={k} className={[sel.has(k) ? 'fw-sel' : '', rowClass?.(r) ?? ''].filter(Boolean).join(' ')}>
                {selectable && <td className="fw-cb"><Checkbox checked={sel.has(k)} onChange={(on) => toggle(k, on)} aria-label={t('common.select')} /></td>}
                {columns.map((c) => <td key={c.key} className={cls(c)}>{c.render(r)}</td>)}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function Section({ id, icon, title, action, children }: { id?: string; icon: string; title: ReactNode; action?: ReactNode; children: ReactNode }) {
  return (
    <section className="fw-sec" id={id}>
      <div className="fw-sec-h">
        <Icon name={icon} />
        <h2>{title}</h2>
        {action && <div className="fw-sec-act">{action}</div>}
      </div>
      {children}
    </section>
  );
}

/** A settings row: label and description on the left, control on the right (design 001, variant A). */
export function Row({ label, desc, children, htmlFor }: { label: ReactNode; desc?: ReactNode; children?: ReactNode; htmlFor?: string }) {
  return (
    <div className="fw-row">
      <div className="fw-row-tx">
        {htmlFor ? <label htmlFor={htmlFor}><b>{label}</b></label> : <b>{label}</b>}
        {desc && <p>{desc}</p>}
      </div>
      {children && <div className="fw-row-ctl">{children}</div>}
    </div>
  );
}

export function fmtBytes(n?: number): string {
  if (n === undefined) return '';
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v < 10 && i ? v.toFixed(1) : Math.round(v)} ${u[i]}`;
}

export const fmtCount = (n?: number): string => (n === undefined ? '' : n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e4 ? `${Math.round(n / 1e3)}k` : String(n));
