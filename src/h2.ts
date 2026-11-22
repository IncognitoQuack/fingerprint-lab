// Passive HTTP/2 fingerprint (Akamai format, Shuster & Segal, Black Hat EU 2017):
//   SETTINGS | WINDOW_UPDATE | PRIORITY | pseudo-header order
// Read from the decrypted connection-level frames a client sends before its first request.

const PREFACE = Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n', 'latin1');

export const SETTING_NAMES: Record<number, string> = {
  1: 'HEADER_TABLE_SIZE', 2: 'ENABLE_PUSH', 3: 'MAX_CONCURRENT_STREAMS', 4: 'INITIAL_WINDOW_SIZE',
  5: 'MAX_FRAME_SIZE', 6: 'MAX_HEADER_LIST_SIZE', 8: 'ENABLE_CONNECT_PROTOCOL', 9: 'NO_RFC7540_PRIORITIES',
};

export interface H2Frames {
  settings: Array<[number, number]>;
  windowUpdate?: number;
  priorityFrames: string[];
  headersPriority?: string;
  frameOrder: string[];
}

const TYPES = ['DATA', 'HEADERS', 'PRIORITY', 'RST_STREAM', 'SETTINGS', 'PUSH_PROMISE', 'PING', 'GOAWAY', 'WINDOW_UPDATE', 'CONTINUATION'];

export class H2Tap {
  private buf = Buffer.alloc(0);
  private prefaceSeen = false;
  done = false;
  frames: H2Frames = { settings: [], priorityFrames: [], frameOrder: [] };

  feed(chunk: Buffer): void {
    if (this.done) return;
    this.buf = Buffer.concat([this.buf, chunk]);
    if (!this.prefaceSeen) {
      if (this.buf.length < PREFACE.length) return;
      if (!this.buf.subarray(0, PREFACE.length).equals(PREFACE)) { this.done = true; return; }
      this.prefaceSeen = true;
      this.buf = this.buf.subarray(PREFACE.length);
    }
    while (this.buf.length >= 9) {
      const len = this.buf.readUIntBE(0, 3);
      if (this.buf.length < 9 + len) return;
      const type = this.buf[3];
      const flags = this.buf[4];
      const stream = this.buf.readUInt32BE(5) & 0x7fffffff;
      const payload = this.buf.subarray(9, 9 + len);
      this.buf = this.buf.subarray(9 + len);
      this.frames.frameOrder.push(`${TYPES[type] ?? type}(${stream})`);
      if (type === 4 && !(flags & 1)) {
        for (let i = 0; i + 6 <= payload.length; i += 6) this.frames.settings.push([payload.readUInt16BE(i), payload.readUInt32BE(i + 2)]);
      } else if (type === 8 && stream === 0 && this.frames.windowUpdate === undefined) {
        this.frames.windowUpdate = payload.readUInt32BE(0) & 0x7fffffff;
      } else if (type === 2 && payload.length >= 5) {
        this.frames.priorityFrames.push(priorityString(stream, payload, 0));
      } else if (type === 1) {
        if (flags & 0x20) {
          const pad = flags & 0x08 ? 1 : 0;
          this.frames.headersPriority = priorityString(stream, payload, pad);
        }
        this.done = true; // everything after the first request is not part of the fingerprint
        return;
      }
    }
  }
}

function priorityString(stream: number, p: Buffer, off: number): string {
  const dep = p.readUInt32BE(off);
  const exclusive = dep >>> 31;
  return `${stream}:${exclusive}:${dep & 0x7fffffff}:${p[off + 4] + 1}`;
}

/** pseudo-header order letters from node's rawHeaders, e.g. ':method',':authority',... -> "m,a,s,p" */
export function pseudoOrder(rawHeaders: string[]): string {
  const out: string[] = [];
  for (let i = 0; i < rawHeaders.length; i += 2) {
    const n = rawHeaders[i];
    if (n.startsWith(':')) out.push(n[1]);
  }
  return out.join(',');
}

export function akamai(f: H2Frames, pseudo: string): string {
  const s = f.settings.map(([k, v]) => `${k}:${v}`).join(';');
  const p = f.priorityFrames.length ? f.priorityFrames.join(',') : '0';
  return `${s}|${f.windowUpdate ?? '00'}|${p}|${pseudo}`;
}
