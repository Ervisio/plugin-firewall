/** Overview widget. Reads only the detect script, which needs no administrator rights: the dashboard never asks to unlock. */
import { detect, useBackend } from '../data';
import { t } from '../i18n';
import { Button, Skeleton } from '../kit';
import { BACKENDS } from '../model';
import { installed } from '../parse/misc';
import { getSdk } from '../sdk';
import { backendActive } from './status';

export function StatusWidget() {
  const { backend, detected } = useBackend();
  const d = detect.use();
  if (!detected) return d.error ? <p className="fw-muted">{t('err.title')}</p> : <Skeleton height={64} />;
  const on = backend ? backendActive(detected, backend) : false;
  const others = [...BACKENDS, 'fail2ban' as const].filter((b) => b !== backend && installed(detected, b));
  return (
    <div className="fw-widget hue-usr">
      <div className={`fw-widget-main fw-widget-main--${on ? 'ok' : 'warn'}`}>
        <span className={`fw-dot fw-dot--${on ? 'ok' : 'warn'}`} />
        <div>
          <b>{backend ? t(`backend.${backend}`) : t('status.none')}</b>
          <span>{backend ? (on ? t('widget.on') : t('widget.off')) : t('widget.noneText')}</span>
        </div>
      </div>
      {others.length > 0 && (
        <ul className="fw-widget-list">
          {others.map((b) => <li key={b}><span className={`fw-dot fw-dot--${backendActive(detected, b) ? 'ok' : 'off'}`} />{t(`backend.${b}`)}</li>)}
        </ul>
      )}
      <Button size="sm" variant="secondary" onClick={() => getSdk().open('firewall')}>{t('widget.open')}</Button>
    </div>
  );
}
