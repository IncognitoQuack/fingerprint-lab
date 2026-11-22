// Throughput of the hot paths, single core. Usage: node scripts/bench.ts
import crypto from 'node:crypto';
import os from 'node:os';
import { parseClientHello } from '../src/clienthello.ts';
import { ja3, ja4 } from '../src/fingerprints.ts';
import { decryptInitials, encryptInitial, cryptoFrame } from '../src/quic.ts';
import { buildHello, FOXIO_EXTS } from '../test/helpers.ts';

function bench(name: string, fn: () => void, ms = 1500) {
  for (let i = 0; i < 2000; i++) fn(); // warm up the JIT
  let n = 0;
  const t0 = performance.now();
  while (performance.now() - t0 < ms) { for (let i = 0; i < 500; i++) fn(); n += 500; }
  const dt = (performance.now() - t0) / 1000;
  console.log(`${name.padEnd(46)} ${Math.round(n / dt).toLocaleString('en-US').padStart(10)} /s   ${((dt / n) * 1e6).toFixed(2).padStart(6)} µs/op`);
}

const hello = buildHello(FOXIO_EXTS);
const parsed = parseClientHello(hello);
const dcid = crypto.randomBytes(8);
const initial = encryptInitial(dcid, crypto.randomBytes(8), 0, Buffer.concat([cryptoFrame(0, buildHello(FOXIO_EXTS, 'h3')), Buffer.alloc(900)]));

console.log(`${os.cpus()[0].model}, Node ${process.version}\n`);
bench('parse ClientHello', () => parseClientHello(hello));
bench('JA4 (from parsed)', () => ja4(parsed));
bench('JA3 (from parsed)', () => ja3(parsed));
bench('parse + JA4 + JA3', () => { const h = parseClientHello(hello); ja4(h); ja3(h); });
bench(`QUIC Initial: derive keys + unprotect + open (${initial.length} B)`, () => decryptInitials(initial));
