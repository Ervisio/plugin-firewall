/** The plugin's CSS as one <style>, injected once. Theme variables only; class names start with fw-. */
import css from './styles.css?inline';

export function injectStyles(): void {
  if (document.getElementById('fw-styles')) return;
  const el = document.createElement('style');
  el.id = 'fw-styles';
  el.textContent = css;
  document.head.appendChild(el);
}
