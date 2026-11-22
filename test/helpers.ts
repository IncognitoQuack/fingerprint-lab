// Builds ClientHello handshake messages byte by byte (FoxIO's JA4 example cipher list, GREASE included).

function ext(type: number, body: Buffer) {
  const h = Buffer.alloc(4); h.writeUInt16BE(type, 0); h.writeUInt16BE(body.length, 2);
  return Buffer.concat([h, body]);
}
export const u16s = (xs: number[]) => { const b = Buffer.alloc(xs.length * 2); xs.forEach((x, i) => b.writeUInt16BE(x, i * 2)); return b; };
export const len16 = (b: Buffer) => { const h = Buffer.alloc(2); h.writeUInt16BE(b.length); return Buffer.concat([h, b]); };
export const len8 = (b: Buffer) => Buffer.concat([Buffer.from([b.length]), b]);

export const FOXIO_EXTS = [0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0010, 0x0012, 0x0015, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d, 0x0033, 0x4469, 0xff01];

export function buildHello(order: number[], alpn = 'h2', grease: [number, number, number] = [0x1a1a, 0x0a0a, 0x4a4a]): Buffer {
  const ciphers = [grease[0], 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035];
  const sig = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601];
  const alpns = alpn === 'h2' ? ['h2', 'http/1.1'] : [alpn];
  const bodies: Record<number, Buffer> = {
    0x0000: len16(Buffer.concat([Buffer.from([0]), len16(Buffer.from('example.com'))])),
    0x0010: len16(Buffer.concat(alpns.map((a) => len8(Buffer.from(a))))),
    0x000a: len16(u16s([0x2a2a, 0x001d, 0x0017, 0x0018])),
    0x000b: len8(Buffer.from([0])),
    0x000d: len16(u16s(sig)),
    0x002b: len8(u16s([0x3a3a, 0x0304, 0x0303])),
  };
  const exts = [ext(grease[1], Buffer.alloc(0))];
  for (const t of order) exts.push(ext(t, bodies[t] ?? Buffer.alloc(0)));
  exts.push(ext(grease[2], Buffer.from([0])));
  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]), Buffer.alloc(32), len8(Buffer.alloc(32)),
    len16(u16s(ciphers)), len8(Buffer.from([0])), len16(Buffer.concat(exts)),
  ]);
  const hs = Buffer.alloc(4); hs[0] = 1; hs.writeUIntBE(body.length, 1, 3);
  return Buffer.concat([hs, body]);
}

export const shuffle = <T>(xs: T[], rnd = Math.random): T[] => {
  const a = [...xs];
  for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; }
  return a;
};
