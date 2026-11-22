// Parses a raw TLS ClientHello (as it arrives on the wire, before any TLS library sees it).

export interface Extension {
  type: number;
  data: Buffer;
}

export interface ClientHello {
  recordVersion: number;
  legacyVersion: number;
  sessionIdLength: number;
  ciphers: number[];
  compression: number[];
  extensions: Extension[];
  sni?: string;
  alpn: string[];
  groups: number[];
  pointFormats: number[];
  sigAlgs: number[];
  supportedVersions: number[];
  keyShareGroups: number[];
}

/** RFC 8701 GREASE values: 0x0a0a, 0x1a1a, ... 0xfafa. */
export const isGrease = (v: number): boolean =>
  (v & 0x0f0f) === 0x0a0a && v >> 8 === (v & 0xff);

export class NotTlsError extends Error {}

/**
 * Reassembles the ClientHello handshake message from one or more TLS records.
 * Returns null when more bytes are needed.
 */
export function extractClientHello(buf: Buffer): { handshake: Buffer; recordVersion: number } | null {
  let off = 0;
  const parts: Buffer[] = [];
  let have = 0;
  let recordVersion = 0;
  while (off + 5 <= buf.length) {
    const type = buf[off];
    if (type !== 22) throw new NotTlsError(`record type ${type} is not a handshake`);
    if (!recordVersion) recordVersion = buf.readUInt16BE(off + 1);
    const len = buf.readUInt16BE(off + 3);
    if (off + 5 + len > buf.length) return null;
    parts.push(buf.subarray(off + 5, off + 5 + len));
    have += len;
    off += 5 + len;
    const hs = Buffer.concat(parts, have);
    if (hs.length >= 1 && hs[0] !== 1) throw new NotTlsError('first handshake message is not a ClientHello');
    if (hs.length >= 4) {
      const need = 4 + hs.readUIntBE(1, 3);
      if (hs.length >= need) return { handshake: hs.subarray(0, need), recordVersion };
    }
  }
  return null;
}

class Reader {
  buf: Buffer;
  off = 0;
  constructor(buf: Buffer) {
    this.buf = buf;
  }
  need(n: number) {
    if (this.off + n > this.buf.length) throw new Error(`truncated: need ${n} at ${this.off}/${this.buf.length}`);
  }
  u8() { this.need(1); return this.buf[this.off++]; }
  u16() { this.need(2); const v = this.buf.readUInt16BE(this.off); this.off += 2; return v; }
  u24() { this.need(3); const v = this.buf.readUIntBE(this.off, 3); this.off += 3; return v; }
  bytes(n: number) { this.need(n); const b = this.buf.subarray(this.off, this.off + n); this.off += n; return b; }
  get done() { return this.off >= this.buf.length; }
}

const u16list = (b: Buffer): number[] => {
  const out: number[] = [];
  for (let i = 0; i + 1 < b.length; i += 2) out.push(b.readUInt16BE(i));
  return out;
};

export function parseClientHello(handshake: Buffer, recordVersion = 0): ClientHello {
  const r = new Reader(handshake);
  if (r.u8() !== 1) throw new Error('not a ClientHello');
  const bodyLen = r.u24();
  const body = new Reader(r.bytes(bodyLen));

  const legacyVersion = body.u16();
  body.bytes(32); // random
  const sessionIdLength = body.u8();
  body.bytes(sessionIdLength);
  const ciphers = u16list(body.bytes(body.u16()));
  const compression = [...body.bytes(body.u8())];

  const hello: ClientHello = {
    recordVersion, legacyVersion, sessionIdLength, ciphers, compression,
    extensions: [], alpn: [], groups: [], pointFormats: [], sigAlgs: [],
    supportedVersions: [], keyShareGroups: [],
  };
  if (body.done) return hello;

  const ext = new Reader(body.bytes(body.u16()));
  while (!ext.done) {
    const type = ext.u16();
    const data = ext.bytes(ext.u16());
    hello.extensions.push({ type, data });
    const d = new Reader(data);
    try {
      switch (type) {
        case 0x0000: { // server_name
          const list = new Reader(d.bytes(d.u16()));
          while (!list.done) {
            const nameType = list.u8();
            const name = list.bytes(list.u16());
            if (nameType === 0) hello.sni = name.toString('ascii');
          }
          break;
        }
        case 0x0010: { // ALPN
          const list = new Reader(d.bytes(d.u16()));
          while (!list.done) hello.alpn.push(list.bytes(list.u8()).toString('latin1'));
          break;
        }
        case 0x000a: hello.groups = u16list(d.bytes(d.u16())); break;
        case 0x000b: hello.pointFormats = [...d.bytes(d.u8())]; break;
        case 0x000d: hello.sigAlgs = u16list(d.bytes(d.u16())); break;
        case 0x002b: hello.supportedVersions = u16list(d.bytes(d.u8())); break;
        case 0x0033: { // key_share
          const list = new Reader(d.bytes(d.u16()));
          while (!list.done) {
            hello.keyShareGroups.push(list.u16());
            list.bytes(list.u16());
          }
          break;
        }
      }
    } catch {
      // A malformed extension body is itself a signal; keep the raw bytes and move on.
    }
  }
  return hello;
}

export const EXTENSION_NAMES: Record<number, string> = {
  0x0000: 'server_name', 0x0005: 'status_request', 0x000a: 'supported_groups',
  0x000b: 'ec_point_formats', 0x000d: 'signature_algorithms', 0x000f: 'heartbeat',
  0x0010: 'alpn', 0x0012: 'signed_cert_timestamp', 0x0015: 'padding',
  0x0016: 'encrypt_then_mac', 0x0017: 'extended_master_secret', 0x001b: 'compress_certificate',
  0x001c: 'record_size_limit', 0x0022: 'delegated_credentials', 0x0023: 'session_ticket',
  0x0029: 'pre_shared_key', 0x002a: 'early_data', 0x002b: 'supported_versions',
  0x002d: 'psk_key_exchange_modes', 0x0031: 'post_handshake_auth', 0x0032: 'signature_algorithms_cert',
  0x0033: 'key_share', 0x0039: 'quic_transport_parameters', 0x3374: 'next_protocol_negotiation', 0x4469: 'application_settings(old)',
  0x44cd: 'application_settings', 0xfe0d: 'encrypted_client_hello', 0xff01: 'renegotiation_info',
};

export const GROUP_NAMES: Record<number, string> = {
  0x0017: 'secp256r1', 0x0018: 'secp384r1', 0x0019: 'secp521r1', 0x001d: 'x25519',
  0x001e: 'x448', 0x0100: 'ffdhe2048', 0x0101: 'ffdhe3072', 0x0102: 'ffdhe4096',
  0x0103: 'ffdhe6144', 0x0104: 'ffdhe8192', 0x11ec: 'X25519MLKEM768', 0x6399: 'X25519Kyber768Draft00',
  0x11eb: 'SecP256r1MLKEM768', 0x11ed: 'SecP384r1MLKEM1024', 0x0200: 'MLKEM512', 0x0201: 'MLKEM768', 0x0202: 'MLKEM1024',
};

export const nameOf = (table: Record<number, string>, v: number): string =>
  isGrease(v) ? 'GREASE' : table[v] ?? `0x${v.toString(16).padStart(4, '0')}`;
