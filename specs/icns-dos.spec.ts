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
})
