// JA3 (Salesforce, 2017) and JA4 (FoxIO, 2023) TLS client fingerprints.
import { createHash } from 'node:crypto';
import { isGrease, type ClientHello } from './clienthello.ts';

const md5 = (s: string) => createHash('md5').update(s).digest('hex');
const sha12 = (s: string) => createHash('sha256').update(s).digest('hex').slice(0, 12);
const noGrease = (xs: number[]) => xs.filter((v) => !isGrease(v));
const hex4 = (v: number) => v.toString(16).padStart(4, '0');

/** JA3 string: version,ciphers,extensions,groups,point_formats (GREASE removed, wire order kept). */
export function ja3String(h: ClientHello, sortExtensions = false): string {
  let exts = noGrease(h.extensions.map((e) => e.type));
  if (sortExtensions) exts = [...exts].sort((a, b) => a - b);
  return [
    h.legacyVersion,
    noGrease(h.ciphers).join('-'),
    exts.join('-'),
    noGrease(h.groups).join('-'),
    h.pointFormats.join('-'),
  ].join(',');
}

export const ja3 = (h: ClientHello) => md5(ja3String(h));
/** JA3N: JA3 with extensions sorted, which survives Chrome's per-connection extension shuffle. */
export const ja3n = (h: ClientHello) => md5(ja3String(h, true));

const VERSIONS: Record<number, string> = {
  0x0304: '13', 0x0303: '12', 0x0302: '11', 0x0301: '10', 0x0300: 's3', 0x0002: 's2',
  0xfeff: 'd1', 0xfefd: 'd2', 0xfefc: 'd3',
};

const isAlnum = (c: number) => (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a);

function alpnCode(first: string | undefined): string {
  if (!first) return '00';
  const b = Buffer.from(first, 'latin1');
  if (isAlnum(b[0]) && isAlnum(b[b.length - 1])) return String.fromCharCode(b[0], b[b.length - 1]);
  const hx = b.toString('hex');
  return hx[0] + hx[hx.length - 1];
}

export interface Ja4 {
  ja4: string;
  /** Raw (unhashed) form, readable: ja4_a_ciphers_extensions_sigalgs */
  ja4_r: string;
  /** Like ja4_r but in wire order (ja4_o): exposes extension-order randomisation. */
  ja4_ro: string;
}

export function ja4(h: ClientHello, transport: 't' | 'q' | 'd' = 't'): Ja4 {
  const versions = noGrease(h.supportedVersions);
  const top = versions.length ? Math.max(...versions) : h.legacyVersion;
  const ver = VERSIONS[top] ?? '00';
  const sni = h.extensions.some((e) => e.type === 0x0000) ? 'd' : 'i';
  const ciphers = noGrease(h.ciphers);
  const exts = noGrease(h.extensions.map((e) => e.type));
  const two = (n: number) => String(Math.min(n, 99)).padStart(2, '0');
  const a = `${transport}${ver}${sni}${two(ciphers.length)}${two(exts.length)}${alpnCode(h.alpn[0])}`;

  const sortedCiphers = [...ciphers].sort((x, y) => x - y).map(hex4).join(',');
  const extForC = exts.filter((e) => e !== 0x0000 && e !== 0x0010);
  const sortedExts = [...extForC].sort((x, y) => x - y).map(hex4).join(',');
  const sig = noGrease(h.sigAlgs).map(hex4).join(',');
  const cRaw = sig ? `${sortedExts}_${sig}` : sortedExts;

  const b = ciphers.length ? sha12(sortedCiphers) : '000000000000';
  const c = extForC.length ? sha12(cRaw) : '000000000000';
  const wireExts = exts.map(hex4).join(',');
  return {
    ja4: `${a}_${b}_${c}`,
    ja4_r: `${a}_${sortedCiphers}_${cRaw}`,
    ja4_ro: `${a}_${ciphers.map(hex4).join(',')}_${sig ? `${wireExts}_${sig}` : wireExts}`,
  };
}

/** Exposed for tests: the hashing step of JA4 b/c on raw strings. */
export const ja4Hash = sha12;
export const ja3Hash = md5;
