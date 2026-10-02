import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import en from '../src/i18n/en.ts';
import it from '../src/i18n/it.ts';

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? files(p) : /\.tsx?$/.test(f) ? [p] : [];
  });
}

test('en and it have the same keys', () => {
  assert.deepEqual(Object.keys(it).sort(), Object.keys(en).sort());
});

test('every literal key in the code exists', () => {
  const src = new URL('../src', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
  const missing = new Set<string>();
  for (const f of files(src)) {
    const text = readFileSync(f, 'utf8');
    for (const m of text.matchAll(/\btn?\('([a-zA-Z0-9_.-]+)'/g)) if (!(m[1] in en)) missing.add(m[1]);
    for (const m of text.matchAll(/'(spec\.[a-zA-Z]+)'/g)) if (!(m[1] in en)) missing.add(m[1]);
  }
  assert.deepEqual([...missing], []);
});

test('placeholders match between languages', () => {
  const vars = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(',');
  for (const k of Object.keys(en)) assert.equal(vars(it[k]), vars(en[k]), k);
});
