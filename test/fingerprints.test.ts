import { test } from 'node:test';
import assert from 'node:assert/strict';
import tls from 'node:tls';
import http2 from 'node:http2';
import { ja3Hash, ja4Hash, ja4, ja3String } from '../src/fingerprints.ts';
import { isGrease, parseClientHello, type ClientHello } from '../src/clienthello.ts';
import { H2Tap, akamai } from '../src/h2.ts';
import { assess } from '../src/assess.ts';
import { startServer } from '../src/server.ts';
import { buildHello, FOXIO_EXTS } from './helpers.ts';

// Reference vectors published by the authors.
test('JA3 hash matches the Salesforce README example', () => {
  assert.equal(ja3Hash('769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0'), 'ada70206e40642a3e4461f35503241d5');
});

test('JA4 b/c hashes match the FoxIO spec example', () => {
  assert.equal(ja4Hash('002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9'), '8daaf6152771');
  assert.equal(ja4Hash('0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601'), 'e5627efa2ab1');
});

test('full JA4 from raw bytes equals t13d1516h2_8daaf6152771_e5627efa2ab1; GREASE ignored', () => {
  const h = parseClientHello(buildHello(FOXIO_EXTS));
  assert.equal(h.sni, 'example.com');
  assert.deepEqual(h.alpn, ['h2', 'http/1.1']);
  assert.equal(ja4(h).ja4, 't13d1516h2_8daaf6152771_e5627efa2ab1');
});

test('shuffling extensions changes JA3 but not JA4 (why JA4 survives Chrome 110+)', () => {
  const a = parseClientHello(buildHello(FOXIO_EXTS));
  const b = parseClientHello(buildHello([...FOXIO_EXTS].reverse()));
  assert.notEqual(ja3String(a), ja3String(b));
  assert.equal(ja4(a).ja4, ja4(b).ja4);
});

test('GREASE detection', () => {
  for (const g of [0x0a0a, 0x1a1a, 0xfafa]) assert.ok(isGrease(g));
  for (const v of [0x0a0b, 0x1301, 0x0000]) assert.ok(!isGrease(v));
});

test('ClientHello split across several TLS records is reassembled', async () => {
  const { extractClientHello } = await import('../src/clienthello.ts');
  const hs = buildHello(FOXIO_EXTS);
  const recs = [hs.subarray(0, 50), hs.subarray(50, 51), hs.subarray(51)].map((f) => Buffer.concat([Buffer.from([22, 3, 1, f.length >> 8, f.length & 0xff]), f]));
  const all = Buffer.concat(recs);
  assert.equal(extractClientHello(all.subarray(0, all.length - 1)), null);
  assert.deepEqual(extractClientHello(all)!.handshake, hs);
});

test('Akamai HTTP/2 string from raw frames arriving in 7-byte chunks', () => {
  const tap = new H2Tap();
  const frame = (type: number, flags: number, stream: number, payload: Buffer) => {
    const h = Buffer.alloc(9); h.writeUIntBE(payload.length, 0, 3); h[3] = type; h[4] = flags; h.writeUInt32BE(stream, 5);
    return Buffer.concat([h, payload]);
  };
  const settings = Buffer.alloc(24);
  [[1, 65536], [2, 0], [4, 6291456], [6, 262144]].forEach(([k, v], i) => { settings.writeUInt16BE(k, i * 6); settings.writeUInt32BE(v, i * 6 + 2); });
  const wu = Buffer.alloc(4); wu.writeUInt32BE(15663105);
  const wire = Buffer.concat([Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'), frame(4, 0, 0, settings), frame(8, 0, 0, wu), frame(1, 4, 1, Buffer.alloc(3))]);
  for (let i = 0; i < wire.length; i += 7) tap.feed(wire.subarray(i, i + 7));
  assert.equal(akamai(tap.frames, 'm,a,s,p'), '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p');
});

test('a script claiming to be Chrome is flagged', () => {
  const h: ClientHello = parseClientHello(buildHello([0x0000, 0x0010, 0x000a, 0x000b, 0x000d, 0x002b]));
  h.ciphers = h.ciphers.filter((c) => !isGrease(c));
  h.extensions = h.extensions.filter((e) => !isGrease(e.type));
  const r = assess(h, 'Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36');
  assert.equal(r.verdict, 'MISMATCH');
});

test('live server: node TLS client over h1 and h2', async () => {
  process.env.CAPTURES = '/dev/null';
  const lab = await startServer(0, '127.0.0.1', true);
  try {
    const h1 = await new Promise<any>((resolve, reject) => {
      const s = tls.connect({ port: lab.port, host: '127.0.0.1', servername: 'localhost', rejectUnauthorized: false, ALPNProtocols: ['http/1.1'] }, () => {
        s.write('GET /?client=test HTTP/1.1\r\nHost: localhost\r\nUser-Agent: test-agent/1\r\nX-B: 1\r\nX-A: 2\r\n\r\n');
      });
      let data = '';
      s.on('data', (c) => (data += c)).on('end', () => resolve(JSON.parse(data.slice(data.indexOf('\r\n\r\n') + 4)))).on('error', reject);
    });
    assert.equal(h1.tls.sni, 'localhost');
    assert.deepEqual(h1.http.header_order, ['Host', 'User-Agent', 'X-B', 'X-A']);
    assert.match(h1.tls.ja4, /^t13d\d{4}h1_[0-9a-f]{12}_[0-9a-f]{12}$/);

    const h2 = await new Promise<any>((resolve, reject) => {
      const c = http2.connect(`https://localhost:${lab.port}`, { rejectUnauthorized: false });
      const req = c.request({ ':path': '/?client=test-h2', 'user-agent': 'test-agent/2', accept: 'text/html' });
      let data = '';
      req.on('response', (h) => assert.match(String(h['alt-svc']), /h3=/));
      req.on('data', (d) => (data += d)).on('end', () => { c.close(); resolve(data); }).on('error', reject);
    });
    assert.match(h2, /<title>fingerprint-lab<\/title>/);
    assert.match(h2, /HTTP\/2 \(Akamai\)/);
  } finally {
    await lab.close();
  }
});
