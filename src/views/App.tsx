import { detect, useBackend } from '../data';
import { t } from '../i18n';
import { Icon, Skeleton } from '../kit';
import { installed } from '../parse/misc';
import { go, useRuleDialog, useView, type View } from '../nav';
import { ActivityPage } from './ActivityPage';
import { BansPage } from './BansPage';
import { LogsPage } from './LogsPage';
import { OverviewPage } from './OverviewPage';
import { RuleDialog } from './RuleDialog';
import { RulesPage } from './RulesPage';
import { SettingsPage } from './SettingsPage';
import { useLiveActive } from './hooks';
import { backendActive, backendVersion } from './status';

const NAV: { id: View; icon: string }[] = [
  { id: 'overview', icon: 'shield' },
  { id: 'rules', icon: 'list' },
  { id: 'logs', icon: 'logs' },
  { id: 'bans', icon: 'ban' },
  { id: 'activity', icon: 'clock' },
  { id: 'settings', icon: 'cog' },
];

const PAGES: Record<View, () => JSX.Element> = {
  overview: OverviewPage,
  rules: RulesPage,
  logs: LogsPage,
  bans: BansPage,
  activity: ActivityPage,
  settings: SettingsPage,
};

/** The page: inner sidebar and the current view. */
export function App() {
  const view = useView();
  const dialog = useRuleDialog();
  const { backend, detected } = useBackend();
  const d = detect.use();
  const Page = PAGES[view];
  const nav = NAV.filter((n) => n.id !== 'bans' || !detected || installed(detected, 'fail2ban'));
  const active = useLiveActive(backend, detected && backend ? backendActive(detected, backend) : undefined);
  return (
    <div className="fw-root hue-usr">
      <div className="fw-shell">
        <nav className="fw-nav" aria-label={t('nav.aria')}>
          {nav.map((n) => (
            <button key={n.id} type="button" className="fw-nav-it" aria-current={view === n.id ? 'page' : undefined} onClick={() => go(n.id)}>
              <Icon name={n.icon} />
              {t(`nav.${n.id}`)}
            </button>
          ))}
          <div className="fw-nav-ft">
            {!d.data && d.loading ? <Skeleton width={120} height={12} /> : backend && detected ? (
              <>
                <span className={`fw-dot fw-dot--${active ? 'ok' : 'warn'}`} />
                <span>{t(`backend.${backend}`)} {backendVersion(detected, backend)} {active ? t('status.active') : t('status.inactive')}</span>
              </>
            ) : <span>{t('status.none')}</span>}
          </div>
        </nav>
        <main className="fw-main">
          <Page />
        </main>
      </div>
      {dialog && <RuleDialog prefill={dialog} />}
    </div>
  );
}
