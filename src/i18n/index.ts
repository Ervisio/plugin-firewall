/** Strings: en.ts and it.ts hold the same keys (a test checks it). `t` falls back to English, then to the key. */
import { getSdk } from '../sdk';
import en from './en';
import it from './it';

export function registerAllStrings(): void {
  getSdk().registerStrings({ en, it });
}

export const t = (key: string, vars?: Record<string, string | number>): string => getSdk().t(key, vars);

/** `<key>.one` when n is 1 and that key exists. */
export const tn = (key: string, vars: Record<string, string | number> & { n: number }): string => {
  if (vars.n === 1) {
    const one = t(`${key}.one`, vars);
    if (one !== `${key}.one`) return one;
  }
  return t(key, vars);
};
