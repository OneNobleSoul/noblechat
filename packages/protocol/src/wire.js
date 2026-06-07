// Minimal length-prefixed binary framing (u16 big-endian length per field).
import { concatBytes } from "../../crypto/src/util.js";

export function pack(fields) {
  const parts = [];
  for (const f of fields) {
    if (f.length > 0xffff) throw new Error("wire: field too large");
    const len = new Uint8Array(2);
    len[0] = (f.length >> 8) & 0xff;
    len[1] = f.length & 0xff;
    parts.push(len, f);
  }
  return concatBytes(...parts);
}

export function unpack(bytes, count) {
  const out = [];
  let off = 0;
  for (let i = 0; i < count; i++) {
    if (off + 2 > bytes.length) throw new Error("wire: truncated");
    const len = (bytes[off] << 8) | bytes[off + 1];
    off += 2;
    if (off + len > bytes.length) throw new Error("wire: truncated field");
    out.push(bytes.subarray(off, off + len));
    off += len;
  }
  return out;
}
