// Cross-connection signals. A single ClientHello can be copied byte for byte (uTLS, curl-impersonate);
// the *distribution* of ClientHellos over several connections is much harder to fake.
//
// Real Chrome (>=110) draws a fresh extension permutation and fresh GREASE values on every handshake.
// A fixed-profile impersonator replays one order and often one set of GREASE values.
import { isGrease, type ClientHello } from './clienthello.ts';

export interface HistoryStats {
  /** handshakes seen for this (peer, JA4) */
  n: number;
  distinctOrders: number;
  distinctGrease: number;
  /** log2 of the number of distinct orders: bits of order entropy observed */
  orderBits: number;
}

export class ConnectionHistory {
  private seen = new Map<string, { n: number; orders: Set<string>; grease: Set<string> }>();
  private max: number;
  constructor(max = 10000) { this.max = max; }

  observe(key: string, h: ClientHello): HistoryStats {
    let e = this.seen.get(key);
    if (!e) {
      e = { n: 0, orders: new Set(), grease: new Set() };
      this.seen.set(key, e);
      if (this.seen.size > this.max) this.seen.delete(this.seen.keys().next().value!);
    }
    e.n++;
    e.orders.add(h.extensions.map((x) => (isGrease(x.type) ? 'G' : x.type)).join(','));
    const g = [...h.ciphers, ...h.extensions.map((x) => x.type), ...h.groups].filter(isGrease).map((v) => v.toString(16)).join(',');
    e.grease.add(g);
    return { n: e.n, distinctOrders: e.orders.size, distinctGrease: e.grease.size, orderBits: Math.log2(e.orders.size) };
  }
}

/**
 * Chrome permutes ~15 extensions (15! ≈ 1.3e12 orders), so a repeat is essentially impossible.
 * With GREASE drawn from 16 values per slot, several identical GREASE sets in a row are also unlikely.
 */
export function historySignals(s: HistoryStats | undefined, looksLikeChromium: boolean): string[] {
  if (!s || !looksLikeChromium) return [];
  const out: string[] = [];
  if (s.n >= 3 && s.distinctOrders === 1)
    out.push(`identical extension order on all ${s.n} handshakes: Chrome >=110 permutes every time; fixed-profile impersonator`);
  else if (s.n >= 3 && s.distinctOrders < s.n)
    out.push(`extension order repeated (${s.distinctOrders} distinct in ${s.n}): a random permutation of ~15 items should never repeat`);
  if (s.n >= 4 && s.distinctGrease === 1) out.push(`same GREASE values on all ${s.n} handshakes: Chrome draws them per connection`);
  return out;
}
