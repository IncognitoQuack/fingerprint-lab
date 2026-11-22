// Mutation fuzzing: an edge parser sees hostile bytes all day. It must reject cleanly, never hang,
// never throw anything but a normal Error, and never let a bad datagram poison a collector.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { extractClientHello, parseClientHello, NotTlsError } from '../src/clienthello.ts';
import { ja3, ja4 } from '../src/fingerprints.ts';
import { decryptInitials, encryptInitial, cryptoFrame, QuicCollector, transportParams } from '../src/quic.ts';
import { H2Tap } from '../src/h2.ts';
import { buildHello, FOXIO_EXTS } from './helpers.ts';

const N = Number(process.env.FUZZ_N ?? 20000);

function mutate(b: Buffer): Buffer {
  const m = Buffer.from(b);
  const ops = 1 + crypto.randomInt(4);
  for (let k = 0; k < ops; k++) {
    const r = crypto.randomInt(10);
    const i = crypto.randomInt(m.length);
    if (r < 6) m[i] = crypto.randomInt(256);           // byte flip
    else if (r < 8) m[i] = [0x00, 0xff, 0x7f, 0x80][crypto.randomInt(4)]; // boundary values in length fields
    else return m.subarray(0, i);                       // truncation
  }
  return m;
}

test(`ClientHello parser + JA3/JA4: ${N} mutated inputs`, () => {
  const seed = buildHello(FOXIO_EXTS);
  const rec = Buffer.concat([Buffer.from([22, 3, 1, seed.length >> 8, seed.length & 0xff]), seed]);
  let parsed = 0, rejected = 0, incomplete = 0;
  for (let n = 0; n < N; n++) {
    const input = mutate(n % 2 ? seed : rec);
    try {
      const h = n % 2 ? parseClientHello(input) : (() => { const g = extractClientHello(input); return g ? parseClientHello(g.handshake) : null; })();
      if (h) { ja3(h); ja4(h); transportParams(h); parsed++; } else incomplete++; // "need more bytes" is a valid answer
    } catch (e) {
      assert.ok(e instanceof Error && (e instanceof NotTlsError || /truncated|not a ClientHello|out of range/.test(e.message)), `unexpected: ${e}`);
      rejected++;
    }
  }
  assert.equal(parsed + rejected + incomplete, N);
  assert.ok(parsed > 0 && rejected > 0, 'the mutator exercises both paths');
});

test(`QUIC Initial decryptor: ${N / 4} mutated datagrams never poison a collector`, () => {
  const dcid = crypto.randomBytes(8);
  const good = encryptInitial(dcid, crypto.randomBytes(8), 0, cryptoFrame(0, buildHello(FOXIO_EXTS, 'h3')));
  const col = new QuicCollector();
  for (let n = 0; n < N / 4; n++) {
    try { decryptInitials(mutate(good)); } catch (e) { assert.ok(e instanceof Error); }
    col.feed(mutate(good), `peer${n}`); // must not throw
  }
  assert.ok(col.feed(good, 'clean-peer'), 'collector still works after the barrage');
});

test(`HTTP/2 tap: ${N / 4} random byte streams`, () => {
  const preface = Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');
  for (let n = 0; n < N / 4; n++) {
    const tap = new H2Tap();
    tap.feed(Buffer.concat([preface, crypto.randomBytes(crypto.randomInt(200))]));
  }
});
