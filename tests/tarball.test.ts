/**
 * Tests for the one-request tarball reader.
 *
 * The reader is the only part of a scan that can decide to read nothing and
 * hand the work back, so the fallback triggers matter as much as the happy
 * path: each one has to leave the caller able to run the per-file path
 * instead of failing the scan.
 */

import { gzipSync } from "node:zlib"
import { afterEach, describe, expect, it, vi } from "vitest"
import {
  MAX_TARBALL_COMPRESSED_BYTES,
  readRepoTarball,
} from "../src/github/tarball"

const SHA = "0123456789abcdef0123456789abcdef01234567"
const ROOT = `sample-${SHA}`

/** One ustar entry: 512-byte header, body, padding to the next block. */
function tarEntry(
  name: string,
  body: Buffer | string,
  typeFlag = "0"
): Buffer {
  const data = Buffer.isBuffer(body) ? body : Buffer.from(body, "utf-8")
  const header = Buffer.alloc(512)
  header.write(name.slice(0, 100), 0, "utf-8")
  header.write("0000644\0", 100)
  header.write("0000000\0", 108)
  header.write("0000000\0", 116)
  header.write(`${data.length.toString(8).padStart(11, "0")}\0`, 124)
  header.write("00000000000\0", 136)
  header.write("        ", 148) // checksum is spaces while it is computed
  header.write(typeFlag, 156)
  header.write("ustar\0", 257)
  header.write("00", 263)
  let sum = 0
  for (const byte of header) sum += byte
  header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148)
  const padding = Buffer.alloc((512 - (data.length % 512)) % 512)
  return Buffer.concat([header, data, padding])
}

/** A gzipped tar shaped like `git archive`: everything under one root dir. */
function tarball(
  files: Record<string, string>,
  options: { root?: string; extras?: Buffer[] } = {}
): Buffer {
  const root = options.root ?? ROOT
  const entries = [tarEntry(`${root}/`, "", "5")]
  for (const [path, content] of Object.entries(files)) {
    entries.push(tarEntry(`${root}/${path}`, content))
  }
  entries.push(...(options.extras ?? []))
  // Two zero blocks close the archive.
  entries.push(Buffer.alloc(1024))
  return gzipSync(Buffer.concat(entries))
}

/**
 * A body that is a valid gzip stream and wrong in exactly one way: too big.
 *
 * Zero-filled chunks are the cheap way to make a large body, but they are not
 * gzip, so such a response is over the cap *and* unreadable — and which
 * reason comes back depends on whether the counter trips before the
 * decompressor rejects the header. That ordering is not the reader's to
 * control: Node 24.22.3 reversed it. Level 0 stores rather than deflates, so
 * zeroed input buys a valid single-member gzip stream of the same size.
 */
let oversizedGzipCache: Uint8Array | null = null
function oversizedGzip(): Uint8Array {
  if (!oversizedGzipCache) {
    // One entry larger than the cap, so the parse is still mid-file when the
    // counter trips. A body of plain zeroes would not do: two zero blocks are
    // tar's end-of-archive marker, so the parse would finish at byte 1024
    // having found nothing, long before the cap came into it.
    const archive = Buffer.concat([
      tarEntry(`${ROOT}/big.bin`, Buffer.alloc(MAX_TARBALL_COMPRESSED_BYTES + 2 * 1024 * 1024)),
      Buffer.alloc(1024),
    ])
    oversizedGzipCache = new Uint8Array(gzipSync(archive, { level: 0 }))
  }
  return oversizedGzipCache
}

/** Serves `bytes` in 1MB chunks, reporting how far the consumer actually got. */
function streamInChunks(bytes: Uint8Array): {
  body: ReadableStream<Uint8Array>
  sent: () => number
  cancelled: () => boolean
} {
  let sent = 0
  let cancelled = false
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (sent >= bytes.byteLength) {
        controller.close()
        return
      }
      const end = Math.min(sent + 1024 * 1024, bytes.byteLength)
      controller.enqueue(bytes.subarray(sent, end))
      sent = end
    },
    cancel() {
      cancelled = true
    },
  })
  return { body, sent: () => sent, cancelled: () => cancelled }
}

function serve(body: Buffer | string, init: ResponseInit = {}): typeof fetch {
  return vi.fn(async () => new Response(body, { status: 200, ...init })) as unknown as typeof fetch
}

async function read(
  wanted: string[],
  body: Buffer | string,
  init: ResponseInit = {}
) {
  return readRepoTarball("acme", "sample", SHA, new Set(wanted), {}, serve(body, init))
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe("readRepoTarball", () => {
  it("reads the wanted files and strips the archive's root directory", async () => {
    const result = await read(
      ["src/index.js", "package.json"],
      tarball({
        "src/index.js": "export const x = 1\n",
        "package.json": `{"name":"sample"}`,
        "README.md": "# sample\n",
      })
    )

    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect([...result.files.keys()].sort()).toEqual(["package.json", "src/index.js"])
    expect(new TextDecoder().decode(result.files.get("src/index.js")!)).toBe(
      "export const x = 1\n"
    )
    // A file nobody asked for is not retained, so memory tracks the
    // selection rather than the repo.
    expect(result.files.has("README.md")).toBe(false)
  })

  it("reassembles files that span response chunks", async () => {
    // A 300KB file crosses many 512-byte blocks and arrives in pieces; the
    // bytes still have to come back whole and in order.
    const big = "a".repeat(300 * 1024)
    const archive = tarball({ "src/big.js": big, "src/after.js": "const after = 1\n" })
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        for (let at = 0; at < archive.length; at += 701) {
          controller.enqueue(new Uint8Array(archive.subarray(at, at + 701)))
        }
        controller.close()
      },
    })
    const result = await readRepoTarball(
      "acme",
      "sample",
      SHA,
      new Set(["src/big.js", "src/after.js"]),
      {},
      vi.fn(async () => new Response(stream, { status: 200 })) as unknown as typeof fetch
    )

    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(new TextDecoder().decode(result.files.get("src/big.js")!)).toBe(big)
    // The entry after a long body is still found, so the block alignment
    // survived the odd chunk size.
    expect(new TextDecoder().decode(result.files.get("src/after.js")!)).toBe(
      "const after = 1\n"
    )
  })

  it("keeps bytes raw rather than round-tripping them through text", async () => {
    // The font masquerade check reads magic numbers, so a byte that is not
    // valid UTF-8 must survive as itself.
    const bytes = Buffer.from([0x77, 0x4f, 0x46, 0x32, 0x00, 0xff, 0xfe, 0x80])
    const result = await read(
      ["public/fonts/a.woff2"],
      tarball({}, { extras: [tarEntry(`${ROOT}/public/fonts/a.woff2`, bytes)] })
    )
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect([...result.files.get("public/fonts/a.woff2")!]).toEqual([...bytes])
  })

  it("reads a path too long for the ustar name field via its pax header", async () => {
    const deep = `${"nested/".repeat(20)}module.js`
    const record = `${`path=${ROOT}/${deep}\n`.length + String(`path=${ROOT}/${deep}\n`.length).length + 1} path=${ROOT}/${deep}\n`
    const result = await read(
      [deep],
      tarball(
        {},
        {
          extras: [
            tarEntry(`${ROOT}/PaxHeaders/x`, record, "x"),
            tarEntry("ignored-name", "deep content\n"),
            Buffer.alloc(0),
          ],
        }
      )
    )

    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(new TextDecoder().decode(result.files.get(deep)!)).toBe("deep content\n")
  })

  it("reads a path carried by a GNU long-name header", async () => {
    const deep = `${"long/".repeat(30)}mod.js`
    const result = await read(
      [deep],
      tarball(
        {},
        {
          extras: [
            tarEntry("././@LongLink", `${ROOT}/${deep}\0`, "L"),
            tarEntry("ignored-name", "gnu content\n"),
          ],
        }
      )
    )

    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(new TextDecoder().decode(result.files.get(deep)!)).toBe("gnu content\n")
  })

  it("ignores directories, symlinks and anything the tree never listed", async () => {
    const result = await read(
      ["src/index.js"],
      tarball(
        { "src/index.js": "export const x = 1\n" },
        {
          extras: [
            tarEntry(`${ROOT}/src/link.js`, "", "2"),
            // A crafted entry name cannot be kept: nothing matches it in the
            // wanted set, which is built from the tree.
            tarEntry(`${ROOT}/../../../etc/passwd`, "root:x:0:0\n"),
          ],
        }
      )
    )

    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect([...result.files.keys()]).toEqual(["src/index.js"])
  })

  describe("falling back to the per-file path", () => {
    it("reports unavailable when GitHub refuses the request", async () => {
      const result = await readRepoTarball(
        "acme",
        "sample",
        SHA,
        new Set(["src/index.js"]),
        {},
        vi.fn(async () => new Response("Not Found", { status: 404 })) as unknown as typeof fetch
      )
      expect(result).toEqual({ ok: false, reason: "unavailable" })
    })

    it("reports unavailable when the request itself throws", async () => {
      // What an extension without the codeload.github.com permission sees,
      // and what being offline looks like.
      const result = await readRepoTarball(
        "acme",
        "sample",
        SHA,
        new Set(["src/index.js"]),
        {},
        vi.fn(async () => {
          throw new TypeError("Failed to fetch")
        }) as unknown as typeof fetch
      )
      expect(result).toEqual({ ok: false, reason: "unavailable" })
    })

    it("reports too-large on a declared length over the cap, without downloading", async () => {
      const cancel = vi.fn()
      const body = new ReadableStream<Uint8Array>({ cancel })
      const result = await readRepoTarball(
        "acme",
        "sample",
        SHA,
        new Set(["src/index.js"]),
        {},
        vi.fn(
          async () =>
            new Response(body, {
              status: 200,
              headers: { "content-length": String(MAX_TARBALL_COMPRESSED_BYTES + 1) },
            })
        ) as unknown as typeof fetch
      )

      expect(result).toEqual({ ok: false, reason: "too-large" })
      // The point of checking the header is not paying for the body.
      expect(cancel).toHaveBeenCalled()
    })

    it("reports too-large when a response with no length streams past the cap", async () => {
      // tensorflow's archive is chunked and carries no content-length, so the
      // cap has to hold while the bytes arrive — and stop them arriving.
      const { body, sent, cancelled } = streamInChunks(oversizedGzip())
      const result = await readRepoTarball(
        "acme",
        "sample",
        SHA,
        new Set(["src/index.js"]),
        {},
        vi.fn(async () => new Response(body, { status: 200 })) as unknown as typeof fetch
      )

      expect(result).toEqual({ ok: false, reason: "too-large" })
      expect(cancelled()).toBe(true)
      // It stopped at the cap instead of reading the whole response.
      expect(sent()).toBeLessThanOrEqual(MAX_TARBALL_COMPRESSED_BYTES + 2 * 1024 * 1024)
    })

    it("reports unreadable when the body is not gzip", async () => {
      const result = await read(["src/index.js"], "this is not a gzip stream")
      expect(result).toEqual({ ok: false, reason: "unreadable" })
    })

    it("reports unreadable when the gzip does not contain a tar", async () => {
      const result = await read(["src/index.js"], gzipSync(Buffer.from("plain text, no blocks")))
      expect(result).toEqual({ ok: false, reason: "unreadable" })
    })

    it("refuses a long-name header big enough to be an attack", async () => {
      const result = await read(
        ["src/index.js"],
        tarball({}, { extras: [tarEntry("././@LongLink", "x".repeat(200 * 1024), "L")] })
      )
      expect(result).toEqual({ ok: false, reason: "unreadable" })
    })
  })
})
