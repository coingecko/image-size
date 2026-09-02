import * as assert from 'node:assert'
import { describe, it } from 'node:test'
import { imageSize } from '../lib'

// Regression test for GHSA-w3rx-r6r6-pgpr: a crafted ICNS entry with a
// zero-valued length field used to leave the parser's offset unchanged,
// spinning the containing loop forever.

const u32be = (n: number): number[] => [
  (n >>> 24) & 0xff,
  (n >>> 16) & 0xff,
  (n >>> 8) & 0xff,
  n & 0xff,
]
const ascii = (s: string): number[] => [...s].map((c) => c.charCodeAt(0))

describe('Denial of Service via a zero-length entry', () => {
  it('does not hang on an ICNS file with a zero-length entry', () => {
    // icns: magic + fileLength(16) + entry('ic10' + length(0, malformed))
    const buffer = new Uint8Array([
      ...ascii('icns'),
      ...u32be(16),
      ...ascii('ic10'),
      ...u32be(0),
    ])

    assert.deepStrictEqual(imageSize(buffer), {
      width: 1024,
      height: 1024,
      type: 'icns',
    })
  })

  it('advances by a full entry header even when the length is smaller than that', () => {
    // Two back-to-back entries, each declaring a length of 1 (smaller than
    // the 8-byte entry header). Advancing by the declared length instead of
    // the header size would turn this into a slow, unbounded byte-by-byte
    // scan on a large file instead of a bounded one.
    const entry = [...ascii('xxxx'), ...u32be(1)]
    const buffer = new Uint8Array([
      ...ascii('icns'),
      ...u32be(8 + entry.length * 2),
      ...entry,
      ...entry,
    ])

    const result = imageSize(buffer) as { images: unknown[] }
    assert.strictEqual(result.images.length, 2)
  })
})
