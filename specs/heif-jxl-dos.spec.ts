import * as assert from 'node:assert'
import { describe, it } from 'node:test'
import { imageSize } from '../lib'

// Regression test for GHSA-5p2g-fcmc-qvqq: a crafted 'ispe'/'jxlp' box with a
// zero-valued size field used to leave the parser's offset unchanged,
// spinning the containing loop forever.

const u32be = (n: number): number[] => [
  (n >>> 24) & 0xff,
  (n >>> 16) & 0xff,
  (n >>> 8) & 0xff,
  n & 0xff,
]
const ascii = (s: string): number[] => [...s].map((c) => c.charCodeAt(0))

describe('Denial of Service via zero-size boxes', () => {
  it('does not hang on a HEIF file with a zero-size ispe box', () => {
    // ftyp: size(16) + 'ftyp' + 'heic' + minor_version(0)
    const ftyp = [...u32be(16), ...ascii('ftyp'), ...ascii('heic'), ...u32be(0)]
    // meta: size(36) + 'meta' + version/flags(0)
    const meta = [...u32be(36), ...ascii('meta'), ...u32be(0)]
    // iprp: size(24) + 'iprp'
    const iprp = [...u32be(24), ...ascii('iprp')]
    // ipco: size(16) + 'ipco'
    const ipco = [...u32be(16), ...ascii('ipco')]
    // ispe: size(0, malformed) + 'ispe' + padding(4) + width(100) + height(50)
    const ispe = [
      ...u32be(0),
      ...ascii('ispe'),
      ...u32be(0),
      ...u32be(100),
      ...u32be(50),
    ]

    const buffer = new Uint8Array([...ftyp, ...meta, ...iprp, ...ipco, ...ispe])

    assert.deepStrictEqual(imageSize(buffer), {
      width: 100,
      height: 50,
      type: 'heic',
    })
  })

  it('does not hang on a JXL file with a zero-size jxlp box', () => {
    // JXL signature box: size(12) + 'JXL ' + payload(4)
    const sig = [...u32be(12), ...ascii('JXL '), 0x0d, 0x0a, 0x87, 0x0a]
    // ftyp: size(20) + 'ftyp' + 'jxl ' + minor_version(0) + 'jxl '
    const ftyp = [
      ...u32be(20),
      ...ascii('ftyp'),
      ...ascii('jxl '),
      ...u32be(0),
      ...ascii('jxl '),
    ]
    // jxlp: size(0, malformed) + 'jxlp'
    const jxlp = [...u32be(0), ...ascii('jxlp')]

    const buffer = new Uint8Array([...sig, ...ftyp, ...jxlp])

    assert.throws(() => imageSize(buffer))
  })
})
