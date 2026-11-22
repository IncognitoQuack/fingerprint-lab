// Server-rendered dashboard for browser visitors (Accept: text/html). No JS, no external assets.

const esc = (s: unknown) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

function ja4Parts(j: string) {
  const [a, b, c] = j.split('_');
  if (!a || a.length < 10) return '';
  const cells = [
    ['proto', a[0] === 't' ? 'TCP' : a[0] === 'q' ? 'QUIC' : a[0]],
    ['TLS', a.slice(1, 3)],
    ['SNI', a[3] === 'd' ? 'domain' : 'IP/none'],
    ['ciphers', a.slice(4, 6)],
    ['exts', a.slice(6, 8)],
    ['ALPN', a.slice(8, 10)],
    ['cipher hash', b],
    ['ext+sigalg hash', c],
  ];
  return `<div class="parts">${cells.map(([k, v]) => `<div><span>${esc(k)}</span><b>${esc(v)}</b></div>`).join('')}</div>`;
}

function chips(xs: string[]) {
  return `<div class="chips">${xs.map((x) => `<span class="chip${x === 'GREASE' ? ' g' : ''}">${esc(x)}</span>`).join('')}</div>`;
}

export function renderDashboard(c: any, quic?: any): string {
  const v = c.assessment.verdict;
  const ak = c.http.akamai_h2 ? c.http.akamai_h2.split('|') : null;
  const list = (xs: string[]) => (xs.length ? `<ul>${xs.map((r) => `<li>${esc(r)}</li>`).join('')}</ul>` : '<p class="muted">none</p>');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>fingerprint-lab</title><style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#14161a;--mut:#667085;--line:#e4e7ec;--acc:#2f6fed;--ok:#12805c;--bad:#c4320a;--g:#f4ebff;--gfg:#6941c6}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--card:#161b22;--fg:#e6edf3;--mut:#8b949e;--line:#30363d;--acc:#58a6ff;--ok:#3fb950;--bad:#ff7b72;--g:#2d2250;--gfg:#c9b6ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:980px;margin:0 auto;padding:28px 16px 60px}h1{font-size:22px;margin:0 0 4px}h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);margin:0 0 10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px;margin:14px 0}
.verdict{display:inline-block;padding:4px 12px;border-radius:999px;font-weight:600;font-size:13px}
.consistent{background:color-mix(in srgb,var(--ok) 15%,transparent);color:var(--ok)}.MISMATCH{background:color-mix(in srgb,var(--bad) 15%,transparent);color:var(--bad)}.undetermined{background:var(--line);color:var(--mut)}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;word-break:break-all}.big{font-size:18px;font-weight:600}
.parts{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:8px;margin-top:12px}.parts div{border:1px solid var(--line);border-radius:8px;padding:6px 8px}
.parts span{display:block;font-size:11px;color:var(--mut)}.parts b{font-family:ui-monospace,Menlo,monospace;font-size:13px;overflow-wrap:anywhere}
.chips{display:flex;flex-wrap:wrap;gap:6px}.chip{border:1px solid var(--line);border-radius:6px;padding:2px 7px;font:12px ui-monospace,Menlo,monospace}.chip.g{background:var(--g);color:var(--gfg);border-color:transparent}
.muted{color:var(--mut)}ul{margin:6px 0 0;padding-left:20px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}@media(max-width:720px){.grid{grid-template-columns:1fr}}
details summary{cursor:pointer;color:var(--acc)}pre{overflow:auto;font-size:12px;background:var(--bg);padding:12px;border-radius:8px}
</style></head><body><main>
<h1>What the edge sees</h1>
<p class="muted">${esc(c.negotiated.protocol)} · ${esc(c.negotiated.cipher)} · ALPN ${esc(c.negotiated.alpn ?? 'none')} · ${esc(c.http.version)}</p>
<div class="card"><h2>Verdict</h2><span class="verdict ${esc(v)}">${esc(v)}</span>
<span class="muted"> &nbsp;User-Agent claims <b>${esc(c.assessment.claimed)}</b>; TLS stack looks like <b>${esc(c.assessment.tls.family)}</b>${c.assessment.h2 ? `; HTTP/2 looks like <b>${esc(c.assessment.h2.family)}</b>` : ''}</span>
${c.assessment.reasons.length ? list(c.assessment.reasons) : ''}${c.assessment.notes.length ? `<p class="muted">${c.assessment.notes.map(esc).join('<br>')}</p>` : ''}</div>
<div class="card"><h2>JA4 (TLS over TCP)</h2><div class="mono big">${esc(c.tls.ja4)}</div>${ja4Parts(c.tls.ja4)}
<p class="muted" style="margin-top:12px">JA3 <code>${esc(c.tls.ja3)}</code> · JA3N <code>${esc(c.tls.ja3n)}</code> · ${esc(c.tls.distinct_ja3_seen_for_this_ja4)} distinct JA3 seen for this JA4 so far</p></div>
<div class="grid">
<div class="card"><h2>Extensions, wire order</h2>${chips(c.tls.extensions)}<p class="muted">Reload in a new window: Chrome reorders these on every handshake.</p></div>
<div class="card"><h2>Key exchange</h2><p>Groups</p>${chips(c.tls.groups)}<p>Key shares</p>${chips(c.tls.key_shares)}</div>
</div>
${ak ? `<div class="card"><h2>HTTP/2 (Akamai)</h2><div class="mono">${esc(c.http.akamai_h2)}</div>
<div class="parts"><div><span>SETTINGS</span><b>${esc(ak[0] || '(empty)')}</b></div><div><span>WINDOW_UPDATE</span><b>${esc(ak[1])}</b></div><div><span>PRIORITY</span><b>${esc(ak[2])}</b></div><div><span>pseudo-headers</span><b>${esc(ak[3])}</b></div></div>
<p class="muted" style="margin-top:12px">Header order</p>${chips(c.http.header_order)}</div>` : `<div class="card"><h2>HTTP/1.1 header order</h2>${chips(c.http.header_order)}</div>`}
<div class="card"><h2>HTTP/3 (QUIC)</h2>${quic ? `<div class="mono big">${esc(quic.tls.ja4)}</div>${ja4Parts(quic.tls.ja4)}
<p class="muted">${esc(quic.quic.initial_packets)} Initial packets, ${esc(quic.quic.crypto_frames)} CRYPTO frames reassembled · ${esc(quic.at)}</p>` :
`<p class="muted">No QUIC handshake from you yet. This response advertises <code>Alt-Svc: h3</code>; browsers only try it with a trusted certificate, so Chrome needs <code>--origin-to-force-quic-on=localhost:PORT</code>.</p>`}</div>
<details class="card"><summary>Raw capture JSON</summary><pre>${esc(JSON.stringify(c, null, 2))}</pre></details>
<p class="muted">fingerprint-lab · passive measurement only · nothing leaves this machine</p>
</main></body></html>`;
}
