import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseClientHello } from '../src/clienthello.ts';
import { ConnectionHistory } from '../src/history.ts';
import { assess } from '../src/assess.ts';
import { ja4 } from '../src/fingerprints.ts';
import { buildHello, shuffle } from './helpers.ts';

// A Chromium-shaped hello (GREASE + ALPS) so the cross-connection rules apply.
const CHROME_EXTS = [0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0010, 0x0012, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d, 0x0033, 0x44cd, 0xff01, 0xfe0d];
const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36';
const G = [0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa];
const g3 = (): [number, number, number] => [G[(Math.random() * 16) | 0], G[(Math.random() * 16) | 0], G[(Math.random() * 16) | 0]];

function verdicts(hellos: Buffer[]) {
  const hist = new ConnectionHistory();
  return hellos.map((b) => {
    const h = parseClientHello(b);
    return assess(h, UA, undefined, undefined, hist.observe(`1.2.3.4|${ja4(h).ja4}`, h));
  });
}

test('real-Chrome behaviour (fresh permutation + fresh GREASE each time) stays consistent', () => {
  const rs = verdicts(Array.from({ length: 8 }, () => buildHello(shuffle(CHROME_EXTS), 'h2', g3())));
  assert.ok(rs.every((r) => !r.reasons.some((x) => /extension order|GREASE values/.test(x))));
  assert.match(rs.at(-1)!.notes.join(' '), /8 distinct extension orders/);
});

test('fixed-profile impersonator (same bytes every time) is flagged on the 3rd handshake', () => {
  const fixed = buildHello(CHROME_EXTS, 'h2', [0x1a1a, 0x2a2a, 0x3a3a]);
  const rs = verdicts([fixed, fixed, fixed, fixed]);
  assert.ok(!rs[1].reasons.some((x) => /extension order/.test(x)));
  assert.ok(rs[2].reasons.some((x) => /identical extension order on all 3/.test(x)));
  assert.equal(rs[2].verdict, 'MISMATCH');
  assert.ok(rs[3].reasons.some((x) => /same GREASE values on all 4/.test(x)));
});

test('impersonator that shuffles but cycles through a small pool is still caught', () => {
  const pool = [shuffle(CHROME_EXTS), shuffle(CHROME_EXTS)];
  const rs = verdicts(Array.from({ length: 6 }, (_, i) => buildHello(pool[i % 2], 'h2', g3())));
  assert.ok(rs[5].reasons.some((x) => /order repeated \(2 distinct in 6\)/.test(x)));
});
