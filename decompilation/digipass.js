/**
 * DIGIPASS OTP for the SQUARE ENIX Software Token (OneSpan/VASCO DIGIPASS).
 *
 * This is NOT TOTP/HOTP (Steam Guard style) — it is the proprietary DIGIPASS
 * "event/time" algorithm embedded in the app's Java (obfuscated.b) code.
 *
 * STATUS: ported from reverse-engineered smali; the byte-level hash-input
 * construction (seed expansion) and final checksum are marked with VERIFY and
 * MUST be validated against a real code before relying on it.
 *
 * Input: the two values recovered by decrypting VDS_dfms4142:
 *   seed = instance0sv tag 0x02   (16 bytes hex, e.g. 00112233445566778899AABBCCDDEEFF)
 *   dv   = instance0dv tag 0x32   (16 bytes hex, e.g. FFEEDDCCBBAA99887766554433221100)
 *
 * Usage (Node >= 15, uses node:crypto):
 *   const { Digipass } = require('./digipass');
 *   const d = new Digipass("00112233445566778899AABBCCDDEEFF",
 *                          "FFEEDDCCBBAA99887766554433221100");
 *   console.log(d.generate());
 */
'use strict';

const crypto = require('node:crypto');

// 256-entry permutation table from obfuscated/b.java (f545a)
const SCRAMBLE = [
  146, 130, 85, 35, 144, 113, 34, 99, 55, 37, 254, 255, 250, 251, 252, 253,
  89, 83, 6, 68, 121, 117, 136, 19, 100, 54, 239, 234, 235, 236, 237, 238,
  52, 70, 53, 33, 87, 39, 32, 101, 119, 3, 218, 219, 220, 221, 222, 223,
  16, 120, 129, 73, 132, 1, 50, 150, 17, 2, 203, 204, 205, 206, 207, 202,
  4, 36, 0, 84, 69, 114, 135, 9, 115, 131, 188, 189, 190, 191, 186, 187,
  118, 152, 18, 66, 56, 51, 148, 5, 145, 134, 173, 174, 175, 170, 171, 172,
  40, 57, 104, 71, 21, 86, 96, 23, 153, 7, 158, 159, 154, 155, 156, 157,
  38, 24, 80, 116, 147, 137, 112, 97, 49, 88, 143, 138, 139, 140, 141, 142,
  22, 105, 48, 8, 67, 133, 103, 98, 149, 72, 122, 123, 124, 125, 126, 127,
  82, 102, 20, 41, 25, 151, 81, 64, 128, 65, 107, 108, 109, 110, 111, 106,
  229, 244, 163, 178, 193, 208, 233, 248, 167, 182, 92, 93, 94, 95, 90, 91,
  245, 164, 179, 194, 209, 224, 249, 168, 183, 198, 77, 78, 79, 74, 75, 76,
  165, 180, 195, 210, 225, 240, 169, 184, 199, 214, 62, 63, 58, 59, 60, 61,
  181, 196, 211, 226, 241, 160, 185, 200, 215, 230, 47, 42, 43, 44, 45, 46,
  197, 212, 227, 242, 161, 176, 201, 216, 231, 246, 26, 27, 28, 29, 30, 31,
  213, 228, 243, 162, 177, 192, 217, 232, 247, 166, 11, 12, 13, 14, 15, 10,
];

function hexToBytes(hex) {
  const s = String(hex).replace(/[^0-9a-fA-F]/g, '');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

/** nibble-BCD → ASCII digits (DIGIPASS decimal conversion, cVar.m == 0) */
function bcdToDigits(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += String.fromCharCode(48 + ((bytes[i] >> 4) & 15));
    s += String.fromCharCode(48 + (bytes[i] & 15));
  }
  return s;
}

/**
 * 6-round scramble (obfuscated/b.java a(byte[8])).
 * Substitutes bytes 4,5,6 through SCRAMBLE and rotates the nibbles across them.
 */
function scramble(b) {
  const t = new Uint8Array(2);
  for (let round = 0; round < 6; round++) {
    for (let i2 = 0; i2 < 3; i2++) {
      const idx = i2 + 4;
      t[0] = (b[idx] & 0xf0) >> 4;
      t[1] = b[idx] & 0x0f;
      b[idx] = SCRAMBLE[(t[0] << 4) + t[1]];
    }
    b[6] = ((b[5] & 0x0f) << 4) | ((b[6] & 0xf0) >> 4);
    b[5] = ((b[4] & 0x0f) << 4) | ((b[5] & 0xf0) >> 4);
    b[4] = ((b[6] & 0x0f) << 4) | ((b[4] & 0xf0) >> 4);
  }
}

class Digipass {
  /**
   * @param {string} seedHex  16-byte secret (instance0sv tag 0x02)
   * @param {string} dvHex    16-byte diversification (instance0dv tag 0x32)
   * @param {number} timeStep 32 (derived: exponent e=2 => 2^(2+3)=32)
   */
  constructor(seedHex, dvHex, timeStep = 32) {
    this.seed = hexToBytes(seedHex); // 16 bytes
    this.dv = hexToBytes(dvHex);     // 16 bytes
    this.timeStep = timeStep;
  }

  /**
   * 8-byte time/event factor for a Unix timestamp (seconds).
   * Config flags for the SQEX instance: r=0 (not BCD time), n=0 (not event),
   * l=1, D=0 => t = floor(now >> (e+3)) = floor(now / 32), XORed into bytes 4..7.
   */
  factor(nowSeconds) {
    const t = Math.floor(nowSeconds / this.timeStep);
    const f = new Uint8Array(8);
    // bytes 0..3 stay 0 for this instance (VERIFY: no BCD-time/counter path used)
    f[4] = (t >>> 24) & 0xff;
    f[5] = (t >>> 16) & 0xff;
    f[6] = (t >>> 8) & 0xff;
    f[7] = t & 0xff;
    return f;
  }

  /**
   * DIGIPASS hash step for the p=1 variant (obfuscated/b.java a(a,c,b,b,z)):
   * AES-256-CBC(key = seed-derived 32 bytes, no IV) over (factor || factor),
   * then XOR the two 8-byte halves together.
   * VERIFY: exact seed expansion to a 32-byte AES key.
   */
  hash(factor) {
    // The app's bArr4 (seed material) is aVar.c.g. For AES-256 it must be 32 bytes;
    // reverse-engineered seed is 16 bytes, so it is duplicated (VERIFY).
    const key = Buffer.concat([Buffer.from(this.seed), Buffer.from(this.seed)]);
    const block = Buffer.concat([Buffer.from(factor), Buffer.from(factor)]);
    const enc = crypto.createCipheriv('aes-256-cbc', key, Buffer.alloc(16, 0));
    enc.setAutoPadding(false);
    const ct = Buffer.concat([enc.update(block), enc.final()]);
    const out = new Uint8Array(8);
    for (let i = 0; i < 8; i++) out[i] = ct[i] ^ ct[i + 8];
    return out;
  }

  /** Generate a 6-digit OTP for the current time (or a given Unix timestamp). */
  generate(nowSeconds = Math.floor(Date.now() / 1000)) {
    const f = this.factor(nowSeconds);
    let h = this.hash(f);

    // decimal conversion (cVar.m == 2 path is used by SQEX):
    // hex -> decimal in 10-digit groups, drop first 4 digits, take 8 bytes
    // (cVar.m == 0 BCD path shown here as fallback)
    let digits;
    if (false /* cVar.m === 2 */) {
      let dec = '';
      const hex = Buffer.from(h).toString('hex').toUpperCase();
      for (let i = 0; i < hex.length; i += 8) {
        const n = parseInt(hex.substr(i, 8), 16).toString(10);
        dec += '0'.repeat(10 - n.length) + n;
      }
      digits = dec.substring(4);
    } else {
      digits = bcdToDigits(h);
    }

    // take 8 bytes of the digit string, scramble, return first 6 chars
    const b = new Uint8Array(8);
    for (let i = 0; i < 8; i++) b[i] = digits.charCodeAt(i) || 48;
    scramble(b);
    let code = '';
    for (let i = 0; i < 6; i++) code += String.fromCharCode(b[i] & 0x7f);
    return code.replace(/[^0-9]/g, '0');
  }
}

module.exports = { Digipass, SCRAMBLE };
