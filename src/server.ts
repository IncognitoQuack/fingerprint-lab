// fingerprint-lab: a local endpoint that shows a client what an anti-bot edge sees.
//
// TCP  : peek + parse the raw ClientHello -> replay the same bytes into Node's TLS ->
//        ALPN h2:       tap decrypted frames (SETTINGS/WINDOW_UPDATE/PRIORITY) -> node:http2 for headers
//        ALPN http/1.1: read the raw request head (header order and casing preserved)
// UDP  : decrypt QUIC Initial packets (RFC 9001) -> reassemble CRYPTO frames -> ClientHello -> JA4 "q"
// Every capture is answered as JSON (or an HTML dashboard for browsers) and appended to captures.jsonl.
import net from 'node:net';
import tls from 'node:tls';
import http2 from 'node:http2';
import dgram from 'node:dgram';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { Duplex } from 'node:stream';
import { extractClientHello, parseClientHello, NotTlsError, nameOf, EXTENSION_NAMES, GROUP_NAMES, isGrease, type ClientHello } from './clienthello.ts';
import { ja3, ja3n, ja3String, ja4 } from './fingerprints.ts';
import { H2Tap, akamai, pseudoOrder, SETTING_NAMES } from './h2.ts';
import { QuicCollector, transportParams } from './quic.ts';
import { ConnectionHistory } from './history.ts';
import { assess } from './assess.ts';
import { renderDashboard } from './dashboard.ts';

const ROOT = path.resolve(import.meta.dirname, '..');
const CERT_DIR = path.join(ROOT, 'certs');
const capturesPath = () => process.env.CAPTURES ?? path.join(ROOT, 'captures', 'captures.jsonl');

function ensureCert(): { key: Buffer; cert: Buffer } {
  const key = path.join(CERT_DIR, 'key.pem');
  const cert = path.join(CERT_DIR, 'cert.pem');
  if (!fs.existsSync(key)) {
    fs.mkdirSync(CERT_DIR, { recursive: true });
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
      '-keyout', key, '-out', cert, '-days', '30', '-subj', '/CN=localhost',
      '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1'], { stdio: 'ignore' });
  }
  return { key: fs.readFileSync(key), cert: fs.readFileSync(cert) };
}

/** Wraps a stream in a plain JS Duplex, optionally pre-loading bytes and tapping reads. */
function bridge(target: Duplex, initial?: Buffer, tap?: (b: Buffer) => void): Duplex {
  const d = new Duplex({
    read() { target.resume(); },
    write(chunk, _enc, cb) { target.write(chunk, cb); },
    final(cb) { target.end(); cb(); },
    destroy(err, cb) { target.destroy(err ?? undefined); cb(err); },
  });
  if (initial?.length) d.push(initial);
  target.on('data', (c: Buffer) => { tap?.(c); if (!d.push(c)) target.pause(); });
  target.on('end', () => d.push(null));
  target.on('error', (e) => d.destroy(e));
  target.on('close', () => d.destroy());
  return d;
}

export interface Lab {
  server: net.Server;
  port: number;
  /** label attached to the next QUIC capture (QUIC requests are never decrypted, so no ?client=) */
  setQuicLabel(label: string | null): void;
  close(): Promise<void>;
}

// One identity per host: IPv4-mapped and both loopbacks collapse (Chrome may use ::1 for QUIC, 127.0.0.1 for TCP).
const peerIp = (a: string | undefined) => {
  const ip = (a ?? '').replace(/^::ffff:/, '');
  return ip === '::1' ? '127.0.0.1' : ip;
};

export async function startServer(port = Number(process.env.PORT ?? 8443), host = '127.0.0.1', quiet = false): Promise<Lab> {
  const { key, cert } = ensureCert();
  const tlsServer = tls.createServer({ key, cert, ALPNProtocols: ['h2', 'http/1.1'] });
  const secureContext = tls.createSecureContext({ key, cert });
  const history = new ConnectionHistory();
  const ja3ByJa4 = new Map<string, Set<string>>();
  const lastQuicByIp = new Map<string, any>();
  let quicLabel: string | null = null;

  function tlsSummary(h: ClientHello, transport: 't' | 'q') {
    const j4 = ja4(h, transport);
    const j3 = ja3(h);
    const set = ja3ByJa4.get(j4.ja4) ?? new Set();
    set.add(j3);
    ja3ByJa4.set(j4.ja4, set);
    return {
      sni: h.sni ?? null,
      alpn: h.alpn,
      ja3: j3,
      ja3n: ja3n(h),
      ja3_string: ja3String(h),
      ja4: j4.ja4,
      ja4_r: j4.ja4_r,
      ja4_ro: j4.ja4_ro,
      distinct_ja3_seen_for_this_ja4: set.size,
      grease: h.ciphers.some(isGrease) || h.extensions.some((e) => isGrease(e.type)),
      cipher_count: h.ciphers.filter((c) => !isGrease(c)).length,
      extensions: h.extensions.map((e) => nameOf(EXTENSION_NAMES, e.type)),
      groups: h.groups.map((g) => nameOf(GROUP_NAMES, g)),
      key_shares: h.keyShareGroups.map((g) => nameOf(GROUP_NAMES, g)),
      supported_versions: h.supportedVersions.map((v) => (isGrease(v) ? 'GREASE' : `0x${v.toString(16)}`)),
      signature_algorithms: h.sigAlgs.map((v) => `0x${v.toString(16).padStart(4, '0')}`),
    };
  }

  function record(obj: any) {
    const p = capturesPath();
    if (p === '/dev/null') return;
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.appendFileSync(p, JSON.stringify(obj) + '\n');
  }
  const log = (o: any, proto: string) => {
    if (!quiet) console.log(`${o.at} ${String(o.client ?? '-').padEnd(24)} ${o.tls.ja4.padEnd(38)} ${proto.padEnd(8)} ${o.assessment.verdict}`);
  };

  const labelFrom = (urlPath: string | undefined) => {
    try { return new URL(urlPath ?? '/', 'https://x').searchParams.get('client'); } catch { return null; }
  };

  // ---------- TCP / TLS ----------
  const open = new Set<net.Socket>();
  const server = net.createServer((sock) => {
    open.add(sock);
    sock.on('close', () => open.delete(sock));
    let pending = Buffer.alloc(0);
    const onPeek = (chunk: Buffer) => {
      pending = Buffer.concat([pending, chunk]);
      let got;
      try {
        got = extractClientHello(pending);
      } catch (e) {
        sock.removeListener('data', onPeek);
        if (e instanceof NotTlsError) sock.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nThis endpoint speaks TLS. Use https://\n');
        else sock.destroy();
        return;
      }
      if (!got) { if (pending.length > 65536) sock.destroy(); return; }
      sock.removeListener('data', onPeek);
      sock.pause();
      let hello: ClientHello;
      try { hello = parseClientHello(got.handshake, got.recordVersion); } catch { sock.destroy(); return; }
      handleTls(sock, pending, hello);
    };
    sock.on('data', onPeek);
    sock.on('error', () => {});
  });

  function handleTls(sock: net.Socket, initial: Buffer, hello: ClientHello) {
    const tlsSock = new tls.TLSSocket(bridge(sock, initial), { isServer: true, server: tlsServer, secureContext, ALPNProtocols: ['h2', 'http/1.1'] });
    tlsSock.on('error', () => {});
    tlsSock.once('secure', () => {
      const t = tlsSummary(hello, 't');
      const hist = history.observe(`${peerIp(sock.remoteAddress)}|${t.ja4}`, hello);
      const base = {
        at: new Date().toISOString(),
        remote: peerIp(sock.remoteAddress),
        transport: 'tcp',
        negotiated: { protocol: tlsSock.getProtocol(), cipher: tlsSock.getCipher()?.standardName, alpn: tlsSock.alpnProtocol || null },
        tls: t,
      };
      if (tlsSock.alpnProtocol === 'h2') serveH2(tlsSock, base, hello, hist);
      else serveH1(tlsSock, base, hello, hist);
    });
  }

  function respond(base: any, hello: ClientHello, http: any, ua: string | undefined, accept: string | undefined, hist: any, h2frames?: any, pseudo?: string) {
    const label = http.label;
    delete http.label;
    const out: any = { ...base, client: label, http, assessment: assess(hello, ua, h2frames, pseudo, hist) };
    const q = lastQuicByIp.get(out.remote);
    record(out);
    log(out, http.version);
    if (q) out.quic_last_seen = { at: q.at, ja4: q.tls.ja4, transport_parameters: q.quic.transport_parameters.length };
    const html = /text\/html/.test(accept ?? '');
    return { type: html ? 'text/html; charset=utf-8' : 'application/json', body: html ? renderDashboard(out, q) : JSON.stringify(out, null, 2) + '\n' };
  }

  const ALT_SVC = () => `h3=":${actualPort}"; ma=60`;

  function serveH2(tlsSock: tls.TLSSocket, base: any, hello: ClientHello, hist: any) {
    const tap = new H2Tap();
    const h2 = http2.createServer();
    h2.on('stream', (stream, headers, _flags, rawHeaders: string[]) => {
      const pseudo = pseudoOrder(rawHeaders);
      const regular: string[] = [];
      for (let i = 0; i < rawHeaders.length; i += 2) if (!rawHeaders[i].startsWith(':')) regular.push(rawHeaders[i]);
      const ua = headers['user-agent'] as string | undefined;
      const r = respond(base, hello, {
        label: labelFrom(headers[':path'] as string),
        version: 'h2',
        user_agent: ua ?? null,
        header_order: regular,
        akamai_h2: akamai(tap.frames, pseudo),
        h2_settings: tap.frames.settings.map(([k, v]) => `${SETTING_NAMES[k] ?? k}=${v}`),
        h2_window_update: tap.frames.windowUpdate ?? null,
        h2_frame_order: tap.frames.frameOrder,
        h2_headers_priority: tap.frames.headersPriority ?? null,
      }, ua, headers.accept as string | undefined, hist, tap.frames, pseudo);
      stream.respond({ ':status': 200, 'content-type': r.type, 'alt-svc': ALT_SVC(), 'cache-control': 'no-store' });
      stream.end(r.body);
    });
    h2.on('sessionError', () => {});
    h2.emit('connection', bridge(tlsSock, undefined, (c) => tap.feed(c)));
  }

  function serveH1(tlsSock: tls.TLSSocket, base: any, hello: ClientHello, hist: any) {
    let head = Buffer.alloc(0);
    const onData = (c: Buffer) => {
      head = Buffer.concat([head, c]);
      const end = head.indexOf('\r\n\r\n');
      if (end < 0) { if (head.length > 65536) tlsSock.destroy(); return; }
      tlsSock.removeListener('data', onData);
      const lines = head.subarray(0, end).toString('latin1').split('\r\n');
      const [, target] = lines[0].split(' ');
      const names: string[] = [];
      const hv: Record<string, string> = {};
      for (const l of lines.slice(1)) {
        const i = l.indexOf(':');
        const n = l.slice(0, i);
        names.push(n);
        hv[n.toLowerCase()] = l.slice(i + 1).trim();
      }
      const r = respond(base, hello, { label: labelFrom(target), version: 'http/1.1', request_line: lines[0], user_agent: hv['user-agent'] ?? null, header_order: names },
        hv['user-agent'], hv['accept'], hist);
      tlsSock.end(`HTTP/1.1 200 OK\r\nContent-Type: ${r.type}\r\nContent-Length: ${Buffer.byteLength(r.body)}\r\nAlt-Svc: ${ALT_SVC()}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n${r.body}`);
    };
    tlsSock.on('data', onData);
  }

  // ---------- UDP / QUIC ----------
  const quic = new QuicCollector();
  const udpSockets: dgram.Socket[] = [];
  function onDatagram(msg: Buffer, rinfo: dgram.RemoteInfo) {
    const got = quic.feed(msg, `${rinfo.address}:${rinfo.port}`);
    if (!got) return;
    const t = tlsSummary(got.hello, 'q');
    const ip = peerIp(rinfo.address);
    const hist = history.observe(`${ip}|${t.ja4}`, got.hello);
    const out = {
      at: new Date().toISOString(),
      remote: ip,
      transport: 'quic',
      client: quicLabel,
      tls: t,
      quic: {
        version: 'v1',
        dcid: got.dcid.toString('hex'),
        initial_packets: got.packets.length,
        packets: got.packets.map((p) => ({ pn: p.packetNumber, bytes: p.payloadLength, frames: p.frames.map((f) => (f.type === 'CRYPTO' ? `CRYPTO[${f.offset}+${f.length}]` : f.type === 'PADDING' ? `PADDING(${f.length})` : f.type)) })),
        crypto_frames: got.packets.reduce((n, p) => n + p.crypto.length, 0),
        transport_parameters: transportParams(got.hello),
      },
      http: { version: 'h3', note: 'request headers are inside 1-RTT packets; only the handshake is observable passively' },
      assessment: assess(got.hello, undefined, undefined, undefined, hist),
    };
    lastQuicByIp.set(ip, out);
    record(out);
    log(out, 'quic');
  }

  let actualPort = port;
  await new Promise<void>((resolve) => server.listen(port, host, () => resolve()));
  actualPort = (server.address() as net.AddressInfo).port;
  for (const [type, addr] of [['udp4', '127.0.0.1'], ['udp6', '::1']] as const) {
    const s = dgram.createSocket(type);
    s.on('message', onDatagram);
    s.on('error', () => {});
    await new Promise<void>((resolve) => { s.once('error', () => resolve()); s.bind(actualPort, addr, () => resolve()); });
    udpSockets.push(s);
  }
  if (!quiet) console.log(`fingerprint-lab on https://localhost:${actualPort}/ (TCP: TLS+h2/h1, UDP: QUIC Initial)  self-signed cert in certs/`);

  return {
    server,
    port: actualPort,
    setQuicLabel: (l) => { quicLabel = l; },
    close: () => new Promise((resolve) => {
      for (const s of udpSockets) { try { s.close(); } catch {} }
      server.close(() => resolve());
      for (const s of open) s.destroy();
    }),
  };
}

if (import.meta.main) startServer();
