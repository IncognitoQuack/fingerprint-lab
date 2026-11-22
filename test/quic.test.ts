import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { initialKeys, headerProtectionMask, readVarint, readVarintBig, writeVarint, isTpGrease, decryptInitials, encryptInitial, cryptoFrame, QuicCollector, transportParams } from '../src/quic.ts';
import { ja4 } from '../src/fingerprints.ts';
import { buildHello, shuffle } from './helpers.ts';

const DCID = Buffer.from('8394c8f03e515708', 'hex');

test('RFC 9001 Appendix A.1: Initial secrets and keys (client and server)', () => {
  const c = initialKeys(DCID, 'client');
  assert.equal(c.secret.toString('hex'), 'c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea');
  assert.equal(c.key.toString('hex'), '1f369613dd76d5467730efcbe3b1a22d');
  assert.equal(c.iv.toString('hex'), 'fa044b2f42a3fd3b46fb255c');
  assert.equal(c.hp.toString('hex'), '9f50449e04a0e810283a1e9933adedd2');
  const s = initialKeys(DCID, 'server');
  assert.equal(s.key.toString('hex'), 'cf3a5331653c364c88f0f379b6067e37');
  assert.equal(s.iv.toString('hex'), '0ac1493ca1905853b0bba03e');
  assert.equal(s.hp.toString('hex'), 'c206b8d9b9f0f37644430b490eeaa314');
});

test('RFC 9001 Appendix A.2: header protection mask', () => {
  const mask = headerProtectionMask(initialKeys(DCID).hp, Buffer.from('d1b1c98dd7689fb8ec11d242b123dc9b', 'hex'));
  assert.equal(mask.toString('hex'), '437b9aec36');
});

test('RFC 9000 Appendix A.1 varint examples', () => {
  assert.equal(readVarint(Buffer.from('25', 'hex'), 0)[0], 37);
  assert.equal(readVarint(Buffer.from('7bbd', 'hex'), 0)[0], 15293);
  assert.equal(readVarint(Buffer.from('9d7f3e7d', 'hex'), 0)[0], 494878333);
  assert.equal(readVarintBig(Buffer.from('c2197c5eff14e88c', 'hex'), 0)[0], 151288809941952652n);
  for (const v of [0, 63, 64, 16383, 16384, 2 ** 30 - 1, 2 ** 30]) assert.equal(readVarint(writeVarint(v), 0)[0], v);
  assert.ok(isTpGrease(27n) && isTpGrease(27n + 31n * 1000000000000n) && !isTpGrease(28n));
});

test('Chrome-style chaos protection: ClientHello cut, shuffled across 2 Initials, PING/PADDING interleaved', () => {
  const hello = buildHello([0x0000, 0x0010, 0x000a, 0x000b, 0x000d, 0x002b], 'h3');
  const cuts = [0, 40, 97, 130, 171, 190, 220, hello.length];
  const pieces = shuffle(cuts.slice(0, -1).map((o, i) => cryptoFrame(o, hello.subarray(o, cuts[i + 1]))));
  const noise = () => (crypto.randomInt(2) ? Buffer.from([0x01]) : Buffer.alloc(1 + crypto.randomInt(20)));
  const half = Math.ceil(pieces.length / 2);
  const scid = crypto.randomBytes(8);
  const d1 = encryptInitial(DCID, scid, 1, Buffer.concat(pieces.slice(0, half).flatMap((p) => [noise(), p])));
  const d2 = encryptInitial(DCID, scid, 2, Buffer.concat(pieces.slice(half).flatMap((p) => [p, noise()])));

  const pk = decryptInitials(d1);
  assert.equal(pk.length, 1);
  assert.equal(pk[0].packetNumber, 1);

  const col = new QuicCollector();
  const a = col.feed(d2, 'peer');
  const b = col.feed(d1, 'peer');
  const got = a ?? b;
  assert.ok(got && !(a && b), 'exactly one completion');
  assert.equal(got.hello.sni, 'example.com');
  assert.equal(ja4(got.hello, 'q').ja4.slice(0, 10), 'q13d1506h3');
});

test('coalesced packets decrypt; a flipped bit fails authentication', () => {
  const pkt = encryptInitial(DCID, Buffer.alloc(0), 0, cryptoFrame(0, buildHello([0x0000], 'h3')));
  assert.equal(decryptInitials(Buffer.concat([pkt, pkt])).length, 2);
  const bad = Buffer.from(pkt);
  bad[bad.length - 1] ^= 1;
  assert.throws(() => decryptInitials(bad));
});

test('transport parameters, including a 62-bit id that a JS number would corrupt', () => {
  const big = 151288809941952652n;
  const tp = Buffer.concat([
    writeVarint(0x04), writeVarint(4), writeVarint(15728640),
    Buffer.from('c2197c5eff14e88c', 'hex'), writeVarint(2), Buffer.from('abcd', 'hex'),
    writeVarint(0x3128), writeVarint(4), Buffer.from('ORIG'),
  ]);
  const ps = transportParams({ extensions: [{ type: 0x0039, data: tp }] } as any);
  assert.equal(ps[0].name, 'initial_max_data');
  assert.equal(ps[0].value, 15728640);
  assert.equal(ps[1].id, `0x${big.toString(16)}`);
  assert.equal(ps[1].name, isTpGrease(big) ? 'GREASE' : 'unknown');
  assert.equal(ps[2].value, 'ORIG');
});
