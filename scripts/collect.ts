// Runs every HTTP client available on this machine against the lab and writes results/REPORT.md.
// Usage: node scripts/collect.ts [--chrome-runs N]
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const run = promisify(execFile);
const ROOT = path.resolve(import.meta.dirname, '..');
const OUT = path.join(ROOT, 'results');
const CAPTURES = path.join(OUT, 'captures.jsonl');
fs.mkdirSync(OUT, { recursive: true });
fs.rmSync(CAPTURES, { force: true });
process.env.CAPTURES = CAPTURES;
const { startServer } = await import('../src/server.ts');

const PORT = 8443;
const BASE = `https://localhost:${PORT}/`;
const CHROME_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const CHROME_BIN = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const chromeRuns = Number(process.argv[process.argv.indexOf('--chrome-runs') + 1]) || 5;
const url = (label: string) => `${BASE}?client=${encodeURIComponent(label)}`;

type Client = { label: string; cmd: string; args: string[]; env?: Record<string, string>; input?: string };
const nodeEval = (code: string) => ['--no-warnings', '-e', code];
const pyEval = (code: string) => ['-I', '-c', code];

const clients: Client[] = [
  { label: 'curl (macOS) h1', cmd: 'curl', args: ['-sk', '--http1.1', url('curl (macOS) h1')] },
  { label: 'curl (macOS) h2', cmd: 'curl', args: ['-sk', '--http2', url('curl (macOS) h2')] },
  { label: 'curl + Chrome UA/headers', cmd: 'curl', args: ['-sk', '--http2', '-H', `User-Agent: ${CHROME_UA}`,
    '-H', 'sec-ch-ua: "Chromium";v="131", "Not_A Brand";v="24"', '-H', 'Accept: text/html,application/xhtml+xml', '-H', 'Accept-Language: en-US,en;q=0.9',
    url('curl + Chrome UA/headers')] },
  { label: `Node ${process.version} fetch (undici)`, cmd: process.execPath, env: { NODE_TLS_REJECT_UNAUTHORIZED: '0' },
    args: nodeEval(`fetch(${JSON.stringify(url(`Node ${process.version} fetch (undici)`))}).then(r=>r.text()).then(()=>{})`) },
  { label: 'Node https + Chrome UA', cmd: process.execPath,
    args: nodeEval(`require('https').get(${JSON.stringify(url('Node https + Chrome UA'))},{rejectUnauthorized:false,headers:{'User-Agent':${JSON.stringify(CHROME_UA)}}},r=>r.resume())`) },
  { label: 'Node http2 client', cmd: process.execPath,
    args: nodeEval(`const c=require('http2').connect('${BASE}',{rejectUnauthorized:false});const q=c.request({':path':'/?client='+encodeURIComponent('Node http2 client')});q.resume();q.on('end',()=>c.close())`) },
  { label: 'Python urllib', cmd: 'python3',
    args: pyEval(`import ssl,urllib.request as u;u.urlopen(${JSON.stringify(url('Python urllib'))},context=ssl._create_unverified_context()).read()`) },
  { label: 'Python urllib + Chrome UA', cmd: 'python3',
    args: pyEval(`import ssl,urllib.request as u;u.urlopen(u.Request(${JSON.stringify(url('Python urllib + Chrome UA'))},headers={'User-Agent':${JSON.stringify(CHROME_UA)}}),context=ssl._create_unverified_context()).read()`) },
  { label: 'openssl s_client', cmd: 'openssl', args: ['s_client', '-quiet', '-connect', `localhost:${PORT}`, '-servername', 'localhost', '-alpn', 'http/1.1'],
    input: `GET /?client=${encodeURIComponent('openssl s_client')} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n` },
];

for (let i = 1; i <= chromeRuns; i++) {
  const label = `Chrome headless #${i}`;
  clients.push({ label, cmd: CHROME_BIN, args: ['--headless=new', '--ignore-certificate-errors', '--no-first-run', '--disable-extensions',
    `--user-data-dir=${fs.mkdtempSync(path.join(os.tmpdir(), 'fplab-chrome-'))}`, '--dump-dom', url(label)] });
}

const lab = await startServer(PORT, '127.0.0.1', true);
const skipped: string[] = [];
for (const c of clients) {
  try {
    const p = run(c.cmd, c.args, { env: { ...process.env, ...c.env }, timeout: 30000 });
    if (c.input) { p.child.stdin?.write(c.input); }
    await p;
  } catch (e: any) {
    if (e.code === 'ENOENT') skipped.push(`${c.label}: not installed`);
    // otherwise the client may still have reached us (openssl exits non-zero on close); captures decide.
  }
}

// HTTP/3: force Chrome onto QUIC. The lab never answers on UDP (it only observes), so each run is
// stopped as soon as the ClientHello has been reassembled.
const lines = () => (fs.existsSync(CAPTURES) ? fs.readFileSync(CAPTURES, 'utf8').trim().split('\n').length : 0);
const quicRuns = Number(process.argv[process.argv.indexOf('--quic-runs') + 1]) || 3;
for (let i = 1; i <= quicRuns; i++) {
  lab.setQuicLabel(`Chrome HTTP/3 #${i}`);
  const before = lines();
  const p = spawn(CHROME_BIN, ['--headless=new', '--ignore-certificate-errors', '--no-first-run', '--disable-extensions',
    `--user-data-dir=${fs.mkdtempSync(path.join(os.tmpdir(), 'fplab-chrome-'))}`, '--enable-quic', `--origin-to-force-quic-on=localhost:${PORT}`,
    '--dump-dom', url('quic')], { stdio: 'ignore' });
  const t0 = Date.now();
  while (lines() === before && Date.now() - t0 < 10000) await new Promise((r) => setTimeout(r, 100));
  p.kill('SIGKILL');
}
lab.setQuicLabel(null);

// Dashboard screenshot as a browser sees it (Accept: text/html), after this IP's QUIC handshake is known.
try {
  await run(CHROME_BIN, ['--headless=new', '--ignore-certificate-errors', '--no-first-run', '--hide-scrollbars', '--force-device-scale-factor=2',
    `--user-data-dir=${fs.mkdtempSync(path.join(os.tmpdir(), 'fplab-chrome-'))}`, '--window-size=1000,1640',
    `--screenshot=${path.join(OUT, 'dashboard.png')}`, url('dashboard screenshot')], { timeout: 30000 });
} catch {}
await lab.close();

const all = fs.readFileSync(CAPTURES, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
const quicCaps = all.filter((c) => c.transport === 'quic' && c.client);
const caps = all.filter((c) => c.transport === 'tcp' && c.client && c.client !== 'quic' && c.client !== 'dashboard screenshot');
let chromeVer = '';
try { chromeVer = (await run(CHROME_BIN, ['--version'])).stdout.trim(); } catch {}

const md: string[] = [];
md.push('# Fingerprint lab: what the edge sees', '');
md.push(`Collected ${new Date().toISOString()} on ${os.type()} ${os.release()} (${os.arch()}). ${chromeVer}. Node ${process.version}.`, '');
md.push('| Client | User-Agent claims | JA4 | JA3 | HTTP/2 (Akamai) | Verdict |', '|---|---|---|---|---|---|');
for (const c of caps) {
  const v = c.assessment.verdict === 'MISMATCH' ? '**MISMATCH**' : c.assessment.verdict;
  md.push(`| ${c.client} | ${c.assessment.claimed} | \`${c.tls.ja4}\` | \`${c.tls.ja3.slice(0, 12)}…\` | ${c.http.akamai_h2 ? `\`${c.http.akamai_h2}\`` : `(${c.http.version})`} | ${v} |`);
}
md.push('', '## Why each script was caught', '');
for (const c of caps.filter((c) => c.assessment.verdict === 'MISMATCH')) md.push(`- **${c.client}**: ${c.assessment.reasons.join('; ')}`);

const chrome = caps.filter((c) => c.client.startsWith('Chrome headless'));
if (chrome.length) {
  const ja3s = new Set(chrome.map((c) => c.tls.ja3));
  const ja4s = new Set(chrome.map((c) => c.tls.ja4));
  const ja3ns = new Set(chrome.map((c) => c.tls.ja3n));
  md.push('', '## Chrome shuffles its extensions every connection', '');
  md.push(`${chrome.length} fresh Chrome launches produced **${ja3s.size} distinct JA3** hashes, **${ja3ns.size} distinct JA3N** (sorted) and **${ja4s.size} distinct JA4**.`, '');
  md.push('Wire order of extensions per launch:', '');
  for (const c of chrome) md.push(`- ${c.client}: ${c.tls.extensions.join(', ')}`);
  md.push('', `Chrome key shares: ${chrome[0].tls.key_shares.join(', ')}; HTTP/2 header order: ${chrome[0].http.header_order.join(', ')}`);
}
if (quicCaps.length) {
  md.push('', '## HTTP/3: Chrome over QUIC, decrypted passively', '');
  md.push('| Run | JA4 (q) | Initial packets | CRYPTO frames | Frame layout of the first packet |', '|---|---|---|---|---|');
  for (const q of quicCaps) md.push(`| ${q.client} | \`${q.tls.ja4}\` | ${q.quic.initial_packets} | ${q.quic.crypto_frames} | ${q.quic.packets[0].frames.join(' ')} |`);
  const q = quicCaps[0];
  md.push('', `Extensions (wire order): ${q.tls.extensions.join(', ')}`, '');
  md.push('Transport parameters (wire order):', '');
  for (const t of q.quic.transport_parameters) md.push(`- \`${t.id}\` ${t.name}${t.value !== undefined ? ` = ${t.value}` : ''}`);
  const tpOrders = new Set(quicCaps.map((c) => c.quic.transport_parameters.map((t: any) => t.name).join(',')));
  md.push('', `${quicCaps.length} runs: ${new Set(quicCaps.map((c) => c.tls.ja4)).size} distinct JA4, ${new Set(quicCaps.map((c) => c.tls.ja3)).size} distinct JA3, ${tpOrders.size} distinct transport-parameter orders.`);
}
if (skipped.length) md.push('', '## Skipped', '', ...skipped.map((s) => `- ${s}`));
fs.writeFileSync(path.join(OUT, 'REPORT.md'), md.join('\n') + '\n');
console.log(md.join('\n'));
