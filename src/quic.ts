// Passive QUIC (HTTP/3) ClientHello extraction, RFC 9000 + RFC 9001, no dependencies.
//
// QUIC encrypts even its first packet. The Initial keys are derived from the client's
// Destination Connection ID with a public salt, so any observer can remove the protection:
//   initial_secret = HKDF-Extract(salt_v1, DCID)
//   client_secret  = HKDF-Expand-Label(initial_secret, "client in", "", 32)
//   key/iv/hp      = HKDF-Expand-Label(client_secret, "quic key"/"quic iv"/"quic hp", ...)
// then: remove header protection (AES-128-ECB mask) -> recover packet number -> AES-128-GCM open
// -> walk frames -> reassemble CRYPTO frames by offset -> TLS ClientHello.
import crypto from 'node:crypto';
import { parseClientHello, type ClientHello } from './clienthello.ts';

const SALT_V1 = Buffer.from('38762cf7f55934b34d179ae6a4c80cadccbb7f0a', 'hex');
const QUIC_V1 = 0x00000001;

const hmac = (key: Buffer, data: Buffer) => crypto.createHmac('sha256', key).update(data).digest();
export const hkdfExtract = (salt: Buffer, ikm: Buffer) => hmac(salt, ikm);

export function hkdfExpandLabel(secret: Buffer, label: string, length: number, context = Buffer.alloc(0)): Buffer {
  const full = Buffer.from(`tls13 ${label}`, 'ascii');
  const info = Buffer.concat([Buffer.from([length >> 8, length & 0xff, full.length]), full, Buffer.from([context.length]), context]);
  const blocks: Buffer[] = [];
  let prev = Buffer.alloc(0);
  for (let i = 1; Buffer.concat(blocks).length < length; i++) {
    prev = hmac(secret, Buffer.concat([prev, info, Buffer.from([i])]));
    blocks.push(prev);
  }
  return Buffer.concat(blocks).subarray(0, length);
}

export interface InitialKeys { secret: Buffer; key: Buffer; iv: Buffer; hp: Buffer }

export function initialKeys(dcid: Buffer, side: 'client' | 'server' = 'client'): InitialKeys {
  const initial = hkdfExtract(SALT_V1, dcid);
  const secret = hkdfExpandLabel(initial, side === 'client' ? 'client in' : 'server in', 32);
  return {
    secret,
    key: hkdfExpandLabel(secret, 'quic key', 16),
    iv: hkdfExpandLabel(secret, 'quic iv', 12),
    hp: hkdfExpandLabel(secret, 'quic hp', 16),
  };
}

export function headerProtectionMask(hp: Buffer, sample: Buffer): Buffer {
  const c = crypto.createCipheriv('aes-128-ecb', hp, null);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(sample), c.final()]).subarray(0, 5);
}

/** RFC 9000 §16 variable-length integer. */
export function readVarint(b: Buffer, off: number): [value: number, next: number] {
  if (off >= b.length) throw new Error('varint out of range');
  const len = 1 << (b[off] >> 6);
  if (off + len > b.length) throw new Error('varint truncated');
  let v = b[off] & 0x3f;
  for (let i = 1; i < len; i++) v = v * 256 + b[off + i];
  return [v, off + len];
}

export interface FrameInfo { type: string; offset?: number; length?: number }
export interface InitialPacket {
  version: number;
  dcid: Buffer;
  scid: Buffer;
  tokenLength: number;
  packetNumber: number;
  payloadLength: number;
  frames: FrameInfo[];
  crypto: Array<{ offset: number; data: Buffer }>;
}

/**
 * Decrypts every QUIC v1 Initial packet in a UDP datagram (packets may be coalesced).
 * `dcidOverride` lets a collector keep using the client's *original* DCID for key derivation.
 */
export function decryptInitials(dgram: Buffer, dcidOverride?: Buffer): InitialPacket[] {
  const out: InitialPacket[] = [];
  let off = 0;
  while (off < dgram.length) {
    const start = off;
    const first = dgram[off];
    if (!(first & 0x80)) break; // short header: 1-RTT, nothing for us
    if (off + 7 > dgram.length) break;
    const version = dgram.readUInt32BE(off + 1);
    off += 5;
    const dcid = dgram.subarray(off + 1, off + 1 + dgram[off]); off += 1 + dcid.length;
    const scid = dgram.subarray(off + 1, off + 1 + dgram[off]); off += 1 + scid.length;
    const type = (first & 0x30) >> 4;
    if (version !== QUIC_V1) break; // version negotiation / v2 / drafts: not handled
    let tokenLength = 0;
    if (type === 0) { [tokenLength, off] = readVarint(dgram, off); off += tokenLength; }
    let length: number;
    [length, off] = readVarint(dgram, off);
    const pnOffset = off;
    const end = pnOffset + length;
    if (end > dgram.length) break;
    if (type !== 0) { off = end; continue; } // 0-RTT / Handshake / Retry: skip by length

    const keys = initialKeys(dcidOverride ?? dcid);
    const mask = headerProtectionMask(keys.hp, dgram.subarray(pnOffset + 4, pnOffset + 20));
    const header = Buffer.from(dgram.subarray(start, pnOffset + 4)); // copy: we unmask in place
    header[0] ^= mask[0] & 0x0f;
    const pnLen = (header[0] & 0x03) + 1;
    let pn = 0;
    for (let i = 0; i < pnLen; i++) {
      header[pnOffset - start + i] ^= mask[1 + i];
      pn = pn * 256 + header[pnOffset - start + i];
    }
    const aad = header.subarray(0, pnOffset - start + pnLen);
    const nonce = Buffer.from(keys.iv);
    for (let i = 0; i < 8; i++) nonce[11 - i] ^= Math.floor(pn / 2 ** (8 * i)) & 0xff;
    const ct = dgram.subarray(pnOffset + pnLen, end - 16);
    const tag = dgram.subarray(end - 16, end);
    const d = crypto.createDecipheriv('aes-128-gcm', keys.key, nonce);
    d.setAAD(aad);
    d.setAuthTag(tag);
    const plain = Buffer.concat([d.update(ct), d.final()]); // throws if keys or packet are wrong

    const pkt: InitialPacket = { version, dcid, scid, tokenLength, packetNumber: pn, payloadLength: plain.length, frames: [], crypto: [] };
    walkFrames(plain, pkt);
    out.push(pkt);
    off = end;
  }
  return out;
}

function walkFrames(p: Buffer, pkt: InitialPacket) {
  let i = 0;
  while (i < p.length) {
    const t = p[i];
    if (t === 0x00) { // PADDING: collapse runs
      let j = i; while (j < p.length && p[j] === 0) j++;
      pkt.frames.push({ type: 'PADDING', length: j - i }); i = j; continue;
    }
    if (t === 0x01) { pkt.frames.push({ type: 'PING' }); i++; continue; }
    if (t === 0x06) {
      let o: number, l: number;
      [o, i] = readVarint(p, i + 1);
      [l, i] = readVarint(p, i);
      pkt.crypto.push({ offset: o, data: p.subarray(i, i + l) });
      pkt.frames.push({ type: 'CRYPTO', offset: o, length: l });
      i += l; continue;
    }
    if (t === 0x02 || t === 0x03) { // ACK
      let n: number, v: number;
      [, i] = readVarint(p, i + 1); [, i] = readVarint(p, i); [n, i] = readVarint(p, i); [, i] = readVarint(p, i);
      for (let k = 0; k < n; k++) { [v, i] = readVarint(p, i); [v, i] = readVarint(p, i); }
      if (t === 0x03) for (let k = 0; k < 3; k++) [v, i] = readVarint(p, i);
      pkt.frames.push({ type: 'ACK' }); continue;
    }
    pkt.frames.push({ type: `0x${t.toString(16)}` }); // anything else in a client Initial is unusual: stop
    break;
  }
}

export const TRANSPORT_PARAM_NAMES: Record<number, string> = {
  0x00: 'original_destination_connection_id', 0x01: 'max_idle_timeout', 0x02: 'stateless_reset_token',
  0x03: 'max_udp_payload_size', 0x04: 'initial_max_data', 0x05: 'initial_max_stream_data_bidi_local',
  0x06: 'initial_max_stream_data_bidi_remote', 0x07: 'initial_max_stream_data_uni', 0x08: 'initial_max_streams_bidi',
  0x09: 'initial_max_streams_uni', 0x0a: 'ack_delay_exponent', 0x0b: 'max_ack_delay', 0x0c: 'disable_active_migration',
  0x0e: 'active_connection_id_limit', 0x0f: 'initial_source_connection_id', 0x10: 'retry_source_connection_id',
  0x11: 'version_information', 0x20: 'max_datagram_frame_size', 0x2ab2: 'grease_quic_bit',
  0x3128: 'google_connection_options', 0x4752: 'google_version', 0xff73db: 'version_information(draft)',
};
const INT_PARAMS = new Set([0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x20]);

/** Exact varint as BigInt: 8-byte values (e.g. GREASE transport-parameter IDs) exceed 2^53. */
export function readVarintBig(b: Buffer, off: number): [value: bigint, next: number] {
  if (off >= b.length) throw new Error('varint out of range');
  const len = 1 << (b[off] >> 6);
  if (off + len > b.length) throw new Error('varint truncated');
  let v = BigInt(b[off] & 0x3f);
  for (let i = 1; i < len; i++) v = (v << 8n) | BigInt(b[off + i]);
  return [v, off + len];
}

/** Transport parameter IDs of the form 31*N+27 are reserved GREASE (RFC 9000 §18.1). */
export const isTpGrease = (id: bigint) => id >= 27n && (id - 27n) % 31n === 0n;

export function transportParams(h: ClientHello): Array<{ id: string; name: string; value?: number | string }> {
  const ext = h.extensions.find((e) => e.type === 0x0039);
  if (!ext) return [];
  const out: Array<{ id: string; name: string; value?: number | string }> = [];
  let i = 0;
  try {
    while (i < ext.data.length) {
      let big: bigint, len: number;
      [big, i] = readVarintBig(ext.data, i);
      [len, i] = readVarint(ext.data, i);
      const v = ext.data.subarray(i, i + len);
      i += len;
      const id = big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : -1;
      const grease = isTpGrease(big);
      const name = grease ? 'GREASE' : TRANSPORT_PARAM_NAMES[id] ?? 'unknown';
      let value: number | string | undefined;
      if (INT_PARAMS.has(id) && v.length) value = readVarint(v, 0)[0];
      else if (id === 0x3128) value = v.toString('latin1');
      else if (v.length && !grease) value = v.toString('hex');
      out.push({ id: `0x${big.toString(16)}`, name, value });
    }
  } catch { /* truncated parameter list: keep what we have */ }
  return out;
}

/** Per-connection reassembly of CRYPTO data across Initial packets until the ClientHello is whole. */
export class QuicCollector {
  private conns = new Map<string, { dcid: Buffer; chunks: Map<number, Buffer>; packets: InitialPacket[]; done: boolean; first: number }>();

  feed(dgram: Buffer, peer: string): { hello: ClientHello; packets: InitialPacket[]; dcid: Buffer } | null {
    if (dgram.length < 7 || !(dgram[0] & 0x80)) return null;
    const dcid = dgram.subarray(6, 6 + dgram[5]);
    const key = `${peer}|${dcid.toString('hex')}`;
    let c = this.conns.get(key);
    if (!c) {
      c = { dcid: Buffer.from(dcid), chunks: new Map(), packets: [], done: false, first: Date.now() };
      this.conns.set(key, c);
      if (this.conns.size > 1000) this.conns.delete(this.conns.keys().next().value!);
    }
    if (c.done) return null;
    let pkts: InitialPacket[];
    try { pkts = decryptInitials(dgram, c.dcid); } catch { return null; }
    for (const p of pkts) {
      c.packets.push(p);
      for (const ch of p.crypto) if (!c.chunks.has(ch.offset)) c.chunks.set(ch.offset, Buffer.from(ch.data));
    }
    // stitch contiguous bytes from offset 0
    const sorted = [...c.chunks.entries()].sort((a, b) => a[0] - b[0]);
    const parts: Buffer[] = [];
    let at = 0;
    for (const [o, d] of sorted) {
      if (o > at) break;
      if (o + d.length > at) { parts.push(d.subarray(at - o)); at = o + d.length; }
    }
    const stream = Buffer.concat(parts);
    if (stream.length < 4 || stream[0] !== 1) return null;
    const need = 4 + stream.readUIntBE(1, 3);
    if (stream.length < need) return null;
    c.done = true;
    // QUIC carries raw handshake messages (no TLS record layer), so the handshake parser applies directly.
    return { hello: parseClientHello(stream.subarray(0, need)), packets: c.packets, dcid: c.dcid };
  }
}

// ---------- encoder (used by tests, fuzzing and the benchmark) ----------

export function writeVarint(v: number): Buffer {
  if (v < 0x40) return Buffer.from([v]);
  if (v < 0x4000) return Buffer.from([0x40 | (v >> 8), v & 0xff]);
  if (v < 0x40000000) { const b = Buffer.alloc(4); b.writeUInt32BE(v); b[0] |= 0x80; return b; }
  const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(v)); b[0] |= 0xc0; return b;
}

export const cryptoFrame = (offset: number, data: Buffer) => Buffer.concat([Buffer.from([0x06]), writeVarint(offset), writeVarint(data.length), data]);

/** Builds a protected client Initial packet exactly as RFC 9001 §5 specifies. */
export function encryptInitial(dcid: Buffer, scid: Buffer, pn: number, frames: Buffer, pnLen = 2): Buffer {
  const keys = initialKeys(dcid);
  const pnBytes = Buffer.alloc(pnLen);
  pnBytes.writeUIntBE(pn, 0, pnLen);
  const length = pnLen + frames.length + 16;
  const header = Buffer.concat([
    Buffer.from([0xc0 | (pnLen - 1)]), Buffer.from([0, 0, 0, 1]),
    Buffer.from([dcid.length]), dcid, Buffer.from([scid.length]), scid,
    writeVarint(0), Buffer.from([0x40 | (length >> 8), length & 0xff]), pnBytes,
  ]);
  const nonce = Buffer.from(keys.iv);
  for (let i = 0; i < 8; i++) nonce[11 - i] ^= Math.floor(pn / 2 ** (8 * i)) & 0xff;
  const c = crypto.createCipheriv('aes-128-gcm', keys.key, nonce);
  c.setAAD(header);
  const ct = Buffer.concat([c.update(frames), c.final(), c.getAuthTag()]);
  const pkt = Buffer.concat([header, ct]);
  const pnOffset = header.length - pnLen;
  const mask = headerProtectionMask(keys.hp, pkt.subarray(pnOffset + 4, pnOffset + 20));
  pkt[0] ^= mask[0] & 0x0f;
  for (let i = 0; i < pnLen; i++) pkt[pnOffset + i] ^= mask[1 + i];
  return pkt;
}
