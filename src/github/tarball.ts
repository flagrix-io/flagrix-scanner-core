/**
 * Read a repo's whole snapshot in one request.
 *
 * `GET /repos/{owner}/{repo}/tarball/{sha}` returns every file at a commit as
 * one gzipped tar, which changes two things:
 *
 * - Coverage. The per-file path spends one request per file, so its file cap
 *   is a request budget rather than a work budget: facebook/react's 4,565
 *   scannable files cost 4,565 requests, and only 200 were ever read. The
 *   tarball costs one request whatever the file count, so the cap becomes a
 *   byte cap.
 * - Rate limit. Without a token the REST limit is 60 requests an hour, so a
 *   first per-file scan runs out of budget around file 57 and returns a
 *   partial verdict. One request fits inside that limit.
 *
 * Mechanics:
 *
 * - The endpoint 302-redirects to codeload.github.com, so a browser extension
 *   needs that origin in `optional_host_permissions`. The redirect target is
 *   pre-signed, which is why it still works after `fetch` strips the
 *   Authorization header on the cross-origin hop.
 * - `content-length` is present for most repos (react 10,237,720 bytes,
 *   express 136,124) but absent for some — tensorflow's response is chunked —
 *   so the size guard has to hold while streaming as well as before it.
 * - `git archive` wraps everything in a single `<repo>-<sha>/` directory,
 *   which is stripped so paths match the tree's.
 *
 * The parse is streaming and keeps only the files the caller asked for, so
 * memory is bounded by the selection rather than by the repo: nothing holds a
 * decompressed copy of the archive.
 */



/**
 * Why the tarball read was not used. Each one falls back to the per-file path,
 * which is slower and reads less but needs no extra permission and no cap.
 */
export type TarballFallbackReason =
  /** The archive is larger than a scan should download. */
  | "too-large"
  /** GitHub refused the request (404, rate limit, redirect blocked, offline). */
  | "unavailable"
  /** The response was not a readable gzipped tar. */
  | "unreadable"

export type TarballRead =
  | { ok: true; files: Map<string, Uint8Array>; compressedBytes: number }
  | { ok: false; reason: TarballFallbackReason }

/**
 * How big a repo may be, measured from the tree, before the tarball is worth
 * asking for. The tree is already in hand, so this is the only cap that costs
 * nothing to check: microsoft/vscode spent 30.6s reaching the compressed cap
 * below before giving up, and the per-file scan still had to run afterwards.
 *
 * Measured tree bytes against the archive they produced: express 0.7MB → 0.1MB
 * gzipped, react 40.6MB → 10.2MB (6.7s), prisma 104.6MB → 37.2MB (15.2s),
 * vscode 364.7MB → over the cap, tensorflow 628.3MB → far over. 150MB admits
 * prisma, 8,226 source files in 15s against 200 in the same time, and turns
 * vscode and tensorflow away without a request.
 */
export const MAX_TARBALL_TREE_BYTES = 150 * 1024 * 1024

/**
 * Backstop for an archive that is larger than its tree predicted — a repo of
 * incompressible binaries, where the ratio is 1 rather than the 0.14–0.36
 * measured above. The tree check should mean this never fires; it bounds the
 * wasted download when it does. prisma legitimately needs 37.2MB, so this has
 * to sit above that.
 */
export const MAX_TARBALL_COMPRESSED_BYTES = 48 * 1024 * 1024

/**
 * Cap on bytes pushed through the decompressor. The compressed cap cannot
 * bound this on its own: gzip's ratio is unbounded, so a small archive can
 * expand without limit. Nothing retains these bytes — only the wanted files
 * are kept — so this guards time, not memory.
 */
export const MAX_TARBALL_DECOMPRESSED_BYTES = 512 * 1024 * 1024

/** A long-name header's own body. Real ones are a path; refuse the rest. */
const MAX_LONG_NAME_BYTES = 64 * 1024

const TAR_BLOCK = 512

/**
 * Read the files named by `wanted` out of the commit's tarball.
 *
 * `wanted` is built from the tree, so a tar entry whose name does not appear
 * in it is ignored — which also means a crafted entry name (`../../etc/x`)
 * can never be kept, because it cannot match a path the tree listed.
 *
 * Never throws: every failure is a `reason` for the caller to fall back on.
 */
export async function readRepoTarball(
  owner: string,
  repo: string,
  commitSha: string,
  wanted: ReadonlySet<string>,
  headers: Record<string, string>,
  fetchImpl: typeof fetch = fetch
): Promise<TarballRead> {
  let response: Response
  try {
    response = await fetchImpl(
      `https://api.github.com/repos/${owner}/${repo}/tarball/${commitSha}`,
      { headers, redirect: "follow" }
    )
  } catch {
    // No permission for codeload.github.com, offline, or a blocked redirect.
    return { ok: false, reason: "unavailable" }
  }

  if (!response.ok || !response.body) {
    // A spent budget is still just "no tarball" here: the per-file path runs
    // next and reports the rate limit for itself, with the partial coverage
    // that implies.
    return { ok: false, reason: "unavailable" }
  }

  const declaredLength = Number(response.headers.get("content-length"))
  if (Number.isFinite(declaredLength) && declaredLength > MAX_TARBALL_COMPRESSED_BYTES) {
    await response.body.cancel().catch(() => {})
    return { ok: false, reason: "too-large" }
  }

  let compressedBytes = 0
  let overCompressedCap = false
  // Count the archive as it arrives, so the cap holds for the chunked
  // responses that carry no content-length. Throwing here errors the stream,
  // which cancels the download rather than letting it run to completion.
  const counter = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      compressedBytes += chunk.byteLength
      if (compressedBytes > MAX_TARBALL_COMPRESSED_BYTES) {
        overCompressedCap = true
        throw new Error("tarball over compressed cap")
      }
      controller.enqueue(chunk)
    },
  })

  try {
    // `DecompressionStream` is typed as accepting any BufferSource, which is
    // wider than the Uint8Array pair `pipeThrough` wants; it only ever emits
    // Uint8Array.
    const gunzip = new DecompressionStream("gzip") as unknown as ReadableWritablePair<
      Uint8Array,
      Uint8Array
    >
    const files = await parseTar(response.body.pipeThrough(counter).pipeThrough(gunzip), wanted)
    // A body that decompresses but yields none of the wanted files is not a
    // tarball of this commit. Both the tree and the archive are pinned to the
    // same SHA, so every wanted blob should be in it; coming back empty means
    // the response was something else, or the archive's shape has changed.
    // Reporting that as a successful read would claim a coverage the scan
    // does not have and quietly send it down the per-file path file by file.
    if (wanted.size > 0 && files.size === 0) {
      return { ok: false, reason: "unreadable" }
    }
    return { ok: true, files, compressedBytes }
  } catch (error) {
    if (overCompressedCap || error instanceof TarballTooLarge) {
      return { ok: false, reason: "too-large" }
    }
    return { ok: false, reason: "unreadable" }
  }
}

class TarballTooLarge extends Error {}

/**
 * Pending bytes across chunk boundaries. Tar is a stream of 512-byte blocks
 * that arrive on no particular boundary, so headers and bodies both have to
 * be reassembled; `drop` exists so an unwanted 40MB blob is discarded as it
 * passes instead of being buffered to be thrown away.
 */
class ByteQueue {
  private chunks: Uint8Array[] = []
  private length = 0

  push(chunk: Uint8Array): void {
    if (chunk.byteLength === 0) return
    this.chunks.push(chunk)
    this.length += chunk.byteLength
  }

  get size(): number {
    return this.length
  }

  /** Copy out exactly `count` bytes, or null if that many are not here yet. */
  take(count: number): Uint8Array | null {
    if (this.length < count) return null
    const out = new Uint8Array(count)
    let filled = 0
    while (filled < count) {
      const head = this.chunks[0]!
      const want = Math.min(head.byteLength, count - filled)
      out.set(head.subarray(0, want), filled)
      if (want === head.byteLength) this.chunks.shift()
      else this.chunks[0] = head.subarray(want)
      filled += want
    }
    this.length -= count
    return out
  }

  /** Discard up to `count` bytes without copying; returns how many went. */
  drop(count: number): number {
    const dropped = Math.min(count, this.length)
    let left = dropped
    while (left > 0) {
      const head = this.chunks[0]!
      if (head.byteLength <= left) {
        this.chunks.shift()
        left -= head.byteLength
      } else {
        this.chunks[0] = head.subarray(left)
        left = 0
      }
    }
    this.length -= dropped
    return dropped
  }

  /** Copy out up to `count` bytes, however many are here. */
  takeSome(count: number): Uint8Array {
    return this.take(Math.min(count, this.length)) ?? new Uint8Array(0)
  }
}

/** Entry being streamed: its body is consumed across however many chunks. */
interface TarEntry {
  /** Where the body goes, or null to discard it. */
  keep: { path: string | null; bytes: Uint8Array; filled: number } | null
  /** Body bytes still to come. */
  remaining: number
  /** Trailing bytes that pad the body to a block boundary. */
  padding: number
  /** 'L'/'x' bodies are a path for the next header, not file content. */
  nameOverride: "gnu" | "pax" | null
}

const ASCII = new TextDecoder("utf-8")

/** NUL- or space-terminated field. */
function readString(block: Uint8Array, start: number, length: number): string {
  const field = block.subarray(start, start + length)
  let end = 0
  while (end < field.length && field[end] !== 0) end++
  return ASCII.decode(field.subarray(0, end)).replace(/\0+$/, "")
}

/**
 * Octal size field. GNU writes sizes over 8GB as base-256 (high bit set on
 * the first byte); such an entry is far past every cap, so it is read as 0 and
 * the archive is refused by the decompressed cap rather than mis-parsed.
 */
function readOctal(block: Uint8Array, start: number, length: number): number {
  if ((block[start]! & 0x80) !== 0) return 0
  const text = readString(block, start, length).trim()
  if (text === "") return 0
  const value = Number.parseInt(text, 8)
  return Number.isFinite(value) && value >= 0 ? value : 0
}

/** The `path=` record of a pax extended header: `<len> path=<value>\n`. */
function paxPath(body: Uint8Array): string | null {
  const text = ASCII.decode(body)
  const match = text.match(/\d+ path=([^\n]*)\n/)
  return match ? match[1]! : null
}

/**
 * Drop the single root directory `git archive` wraps the tree in
 * (`react-<sha>/src/index.js` → `src/index.js`).
 */
function stripRoot(name: string): string | null {
  const slash = name.indexOf("/")
  if (slash === -1) return null
  const path = name.slice(slash + 1)
  return path === "" ? null : path
}

async function parseTar(
  stream: ReadableStream<Uint8Array>,
  wanted: ReadonlySet<string>
): Promise<Map<string, Uint8Array>> {
  const files = new Map<string, Uint8Array>()
  const reader = stream.getReader()
  const queue = new ByteQueue()
  let decompressedBytes = 0
  let entry: TarEntry | null = null
  // Set by an 'L' (GNU) or 'x' (pax) header for the entry that follows it.
  let pendingName: string | null = null
  let done = false

  try {
    while (!done) {
      const chunk = await reader.read()
      if (chunk.done) {
        done = true
      } else {
        decompressedBytes += chunk.value.byteLength
        if (decompressedBytes > MAX_TARBALL_DECOMPRESSED_BYTES) {
          throw new TarballTooLarge("tarball over decompressed cap")
        }
        queue.push(chunk.value)
      }

      // Drain everything the queue now holds before asking for more.
      for (;;) {
        if (entry) {
          if (entry.remaining > 0) {
            if (entry.keep) {
              const piece = queue.takeSome(entry.remaining)
              if (piece.byteLength === 0) break
              entry.keep.bytes.set(piece, entry.keep.filled)
              entry.keep.filled += piece.byteLength
              entry.remaining -= piece.byteLength
            } else {
              const dropped = queue.drop(entry.remaining)
              if (dropped === 0) break
              entry.remaining -= dropped
            }
            if (entry.remaining > 0) break
          }
          if (entry.padding > 0) {
            const dropped = queue.drop(entry.padding)
            entry.padding -= dropped
            if (entry.padding > 0) break
          }
          // Body complete: either it named the next entry, or it was content.
          // Only now does a kept file land in the map — a stream that ends
          // mid-entry must not leave a half-read buffer behind as content.
          if (entry.keep) {
            const body = entry.keep.bytes
            if (entry.nameOverride === "gnu") pendingName = readString(body, 0, body.byteLength)
            else if (entry.nameOverride === "pax") pendingName = paxPath(body)
            else if (entry.keep.path !== null) files.set(entry.keep.path, body)
          }
          entry = null
          continue
        }

        const header = queue.take(TAR_BLOCK)
        if (!header) break
        // Two zero blocks end the archive; one is enough to stop on.
        if (header.every((byte) => byte === 0)) {
          done = true
          break
        }

        const typeFlag = String.fromCharCode(header[156]!)
        const size = readOctal(header, 124, 12)
        const padding = (TAR_BLOCK - (size % TAR_BLOCK)) % TAR_BLOCK

        if (typeFlag === "L" || typeFlag === "x") {
          // Keep the body: it is the next entry's path.
          if (size > MAX_LONG_NAME_BYTES) throw new Error("tar long name too large")
          entry = {
            keep: { path: null, bytes: new Uint8Array(size), filled: 0 },
            remaining: size,
            padding,
            nameOverride: typeFlag === "L" ? "gnu" : "pax",
          }
          continue
        }

        let name = pendingName
        pendingName = null
        if (name === null) {
          const base = readString(header, 0, 100)
          const prefix = readString(header, 345, 155)
          name = prefix === "" ? base : `${prefix}/${base}`
        }

        // '0' and '\0' are regular files. Directories, symlinks ('2') and
        // hard links ('1') carry no content worth scanning; a symlink's
        // target is read through the per-file path, as it was before.
        const isFile = typeFlag === "0" || typeFlag === "\0"
        const path = stripRoot(name)
        const keepIt = isFile && path !== null && wanted.has(path) && !files.has(path)

        entry = {
          keep: keepIt ? { path: path!, bytes: new Uint8Array(size), filled: 0 } : null,
          remaining: size,
          padding,
          nameOverride: null,
        }
      }
    }
  } finally {
    await reader.cancel().catch(() => {})
  }

  return files
}
