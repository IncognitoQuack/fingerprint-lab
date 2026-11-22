// A deliberately small "anti-bot" consistency check: does what the client SAYS it is
// (User-Agent) match what its TLS and HTTP/2 stacks SHOW it is?
// Real vendors combine hundreds of signals; these few are the ones that catch most scripts.
import { isGrease, type ClientHello } from './clienthello.ts';
import type { H2Frames } from './h2.ts';
import { historySignals, type HistoryStats } from './history.ts';

export type Family = 'chromium' | 'firefox' | 'safari' | 'curl' | 'python' | 'node' | 'go' | 'openssl' | 'unknown';

export function claimedFamily(ua: string | undefined): Family {
  if (!ua) return 'unknown';
  if (/curl\//i.test(ua)) return 'curl';
  if (/python|aiohttp|httpx|requests/i.test(ua)) return 'python';
  if (/node|undici|axios/i.test(ua)) return 'node';
  if (/Go-http-client/i.test(ua)) return 'go';
  if (/Firefox\//.test(ua)) return 'firefox';
  if (/(Chrome|Chromium|CriOS|Edg)\//.test(ua)) return 'chromium';
  if (/Safari\//.test(ua) && /Version\//.test(ua)) return 'safari';
  return 'unknown';
}

const has = (h: ClientHello, t: number) => h.extensions.some((e) => e.type === t);

/** What the TLS ClientHello alone suggests. */
export function tlsFamily(h: ClientHello): { family: Family | 'browser-like' | 'library'; why: string[] } {
  const why: string[] = [];
  const grease = h.ciphers.some(isGrease) || h.extensions.some((e) => isGrease(e.type));
  if (grease) why.push('sends GREASE values (BoringSSL / Apple stacks do; OpenSSL, Go, rustls do not)');
  const alps = has(h, 0x44cd) || has(h, 0x4469);
  if (alps) why.push('sends application_settings (ALPS): Chromium-only extension');
  if (has(h, 0x001b)) why.push('offers certificate compression');
  if (has(h, 0xfe0d)) why.push('sends an ECH extension (GREASE ECH in Chromium/Firefox)');
  if (has(h, 0x001c)) why.push('sends record_size_limit (Firefox/NSS habit)');
  if (has(h, 0x0022)) why.push('sends delegated_credentials (Firefox/NSS habit)');
  if (h.keyShareGroups.includes(0x11ec)) why.push('offers post-quantum X25519MLKEM768 key share');
  if (h.alpn.length === 0) why.push('no ALPN at all (browsers always send h2,http/1.1)');

  if (grease && alps) return { family: 'chromium', why };
  if (!grease && has(h, 0x001c) && has(h, 0x0022)) return { family: 'firefox', why };
  if (grease) return { family: 'browser-like', why };
  return { family: 'library', why };
}

const CHROME_H2_SETTINGS = '1:65536;2:0;4:6291456;6:262144';
const CHROME_H2_WINDOW = 15663105;

export function h2Family(f: H2Frames | undefined, pseudo: string | undefined): { family: Family | 'other'; why: string[] } | undefined {
  if (!f) return undefined;
  const s = f.settings.map(([k, v]) => `${k}:${v}`).join(';');
  const why = [`SETTINGS ${s || '(none)'}, WINDOW_UPDATE ${f.windowUpdate ?? 'none'}, pseudo-headers ${pseudo}`];
  if (s === CHROME_H2_SETTINGS && f.windowUpdate === CHROME_H2_WINDOW && pseudo === 'm,a,s,p') return { family: 'chromium', why };
  if (pseudo === 'm,p,a,s') return { family: 'firefox', why };
  if (pseudo === 'm,s,p,a') return { family: 'safari', why };
  return { family: 'other', why };
}

export interface Assessment {
  claimed: Family;
  tls: ReturnType<typeof tlsFamily>;
  h2?: ReturnType<typeof h2Family>;
  verdict: 'consistent' | 'MISMATCH' | 'undetermined';
  reasons: string[];
  /** observations that do not change the verdict */
  notes: string[];
  history?: HistoryStats;
}

const BROWSERS: Family[] = ['chromium', 'firefox', 'safari'];

export function assess(h: ClientHello, ua: string | undefined, h2?: H2Frames, pseudo?: string, hist?: HistoryStats): Assessment {
  const claimed = claimedFamily(ua);
  const tls = tlsFamily(h);
  const h2f = h2Family(h2, pseudo);
  const reasons: string[] = [];
  let verdict: Assessment['verdict'] = 'undetermined';

  if (BROWSERS.includes(claimed)) {
    if (tls.family === 'library') reasons.push(`User-Agent claims ${claimed}, but the ClientHello is a plain TLS library's`);
    else if (tls.family !== claimed && tls.family !== 'browser-like') reasons.push(`User-Agent claims ${claimed}, TLS looks like ${tls.family}`);
    if (claimed === 'chromium' && tls.family === 'browser-like') reasons.push('GREASE but no ALPS: not a current Chromium build');
    if (h2f && h2f.family !== claimed) reasons.push(`HTTP/2 frames look like ${h2f.family}, not ${claimed}`);
    if (!h2f && h.alpn.includes('h2')) reasons.push('a browser would have negotiated HTTP/2 here');
    verdict = reasons.length ? 'MISMATCH' : 'consistent';
  } else if (claimed !== 'unknown') {
    verdict = tls.family === 'chromium' ? 'MISMATCH' : 'consistent';
    if (verdict === 'MISMATCH') reasons.push(`says ${claimed} but has a Chromium ClientHello (impersonation library?)`);
    else reasons.push(`honest non-browser client (${claimed})`);
  }
  const histReasons = historySignals(hist, tls.family === 'chromium');
  if (histReasons.length) { reasons.push(...histReasons); verdict = 'MISMATCH'; }
  const notes: string[] = [];
  if (ua && /HeadlessChrome/.test(ua)) notes.push('User-Agent admits HeadlessChrome: the network layer is genuine, the browser layer would give it away');
  if (hist && hist.n >= 2 && hist.distinctOrders === hist.n && tls.family === 'chromium') notes.push(`${hist.n} handshakes, ${hist.n} distinct extension orders: consistent with real Chrome`);
  return { claimed, tls, h2: h2f, verdict, reasons, notes, history: hist };
}
