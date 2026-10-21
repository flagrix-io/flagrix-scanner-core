import { afterEach, describe, expect, it, vi } from "vitest"
import { scanGitHubRepo } from "../src/github/repo-scanner"
import { compareVersions, matchOsvFeed, pythonDependencies } from "../src/github/osv-feed"
import type { OsvMaliciousFeed, SignatureDatabase } from "../src/types/index"

const SIGNATURES: SignatureDatabase = {
  version: "test",
  lastUpdated: new Date(),
  maliciousPackages: [{ name: "curated-bad", severity: "critical", source: "test" }],
  yaraRules: [],
  knownBadHashes: []
}

const FEED: OsvMaliciousFeed = {
  schemaVersion: 1,
  npm: { all: ["curated-bad", "evil-every-version", "internal-utils"], versions: { "evil-one-release": ["1.0.1"] } },
  pypi: { all: ["foo-bar"], versions: { "pinned-bad": ["2.0.0"] } }
}

function serve(files: Record<string, string>) {
  global.fetch = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    if (url.includes("api.npmjs.org")) return new Response(JSON.stringify({ downloads: 500_000 }), { status: 200 })
    if (/\/commits\/[^/]+$/.test(url)) return new Response(JSON.stringify({ sha: "c".repeat(40) }), { status: 200 })
    if (url.includes("/git/trees/")) {
      const tree = Object.keys(files).map((path) => ({ path, type: "blob", sha: path, url: path }))
      return new Response(JSON.stringify({ sha: "t", truncated: false, tree }), { status: 200 })
    }
    const m = url.match(/\/contents\/(.+?)\?ref=/)
    if (m && files[decodeURIComponent(m[1]!)] !== undefined) {
      return new Response(JSON.stringify({ content: Buffer.from(files[decodeURIComponent(m[1]!)]!).toString("base64") }), { status: 200 })
    }
    return new Response("{}", { status: 404 })
  }) as unknown as typeof fetch
}

const repo = { owner: "acme", repo: "app", branch: "main", url: "https://github.com/acme/app" }
const osvFindings = (r: Awaited<ReturnType<typeof scanGitHubRepo>>) =>
  r.findings.filter((f) => f.pattern === "OSV_MALICIOUS_PACKAGE")

afterEach(() => vi.restoreAllMocks())

describe("OSV malicious-package feed", () => {
  it("flags a dependency malicious in every version as critical/high", async () => {
    serve({ "package.json": JSON.stringify({ name: "app", dependencies: { "evil-every-version": "^3.0.0" } }) })
    const result = await scanGitHubRepo(repo, { signatures: SIGNATURES, osvFeed: FEED })
    expect(osvFindings(result)).toMatchObject([{ severity: "critical", confidence: "high", package: "evil-every-version" }])
    expect(osvFindings(result)[0]!.codeExplanation).toContain("https://osv.dev/list?ecosystem=npm&q=evil-every-version")
    expect(result.riskLevel).toBe("high")
  })

  it("matches version-specific entries only when the declared range includes the version", async () => {
    serve({ "package.json": JSON.stringify({ dependencies: { "evil-one-release": "^1.0.1" }, devDependencies: {} }) })
    expect(osvFindings(await scanGitHubRepo(repo, { signatures: SIGNATURES, osvFeed: FEED }))).toHaveLength(1)
    serve({ "package.json": JSON.stringify({ dependencies: { "evil-one-release": "^2.0.0" } }) })
    expect(osvFindings(await scanGitHubRepo(repo, { signatures: SIGNATURES, osvFeed: FEED }))).toEqual([])
  })

  it("skips names the repo defines itself and local specifiers, and does not duplicate curated hits", async () => {
    serve({
      "package.json": JSON.stringify({ name: "root", dependencies: { "internal-utils": "1.0.0", "curated-bad": "1.0.0" } }),
      "packages/internal-utils/package.json": JSON.stringify({ name: "internal-utils", version: "1.0.0" }),
      "packages/web/package.json": JSON.stringify({ name: "web", dependencies: { "evil-every-version": "workspace:*" } })
    })
    const result = await scanGitHubRepo(repo, { signatures: SIGNATURES, osvFeed: FEED })
    expect(osvFindings(result)).toEqual([])
    expect(result.findings.filter((f) => f.package === "curated-bad")).toHaveLength(1)
  })

  it("normalises PyPI names and reads only real requirements", async () => {
    serve({
      "requirements.txt": "# deps\n-r base.txt\nFoo_Bar[extra]>=1.0 ; python_version > '3.8'\npinned-bad==2.0.0\nhttps://example.invalid/x.whl\n",
      "setup.py": "from setuptools import setup\nsetup(name='x', install_requires=['requests>=2'])\n"
    })
    const result = await scanGitHubRepo(repo, { signatures: SIGNATURES, osvFeed: FEED })
    expect(osvFindings(result).map((f) => f.package).sort()).toEqual(["Foo_Bar", "pinned-bad"])
    expect(pythonDependencies("from setuptools import setup\nsetup(install_requires=['a==1', \"b\"])\n", "setup.py").map((d) => d.name))
      .toEqual(["a", "b"])
  })

  it("honours bounded ranges (fsevents MAL-2023-462 covers only >=1.0.0 <1.2.11)", () => {
    const feed: OsvMaliciousFeed = { schemaVersion: 1, npm: { all: [], versions: { fsevents: [">=1.0.0 <1.2.11"] } }, pypi: { all: [], versions: {} } }
    const check = (spec: string) =>
      matchOsvFeed(feed, [{ ecosystem: "npm", name: "fsevents", spec, file: "package.json" }], new Set(), new Set())
    expect(check("~2.3.3")).toEqual([])
    expect(check("^1.2.11")).toEqual([])
    expect(check("^1.2.0")).toMatchObject([{ severity: "critical", confidence: "medium" }])
    expect(check("1.2.9")).toMatchObject([{ severity: "critical", confidence: "high" }])
    expect(check("*")).toEqual([])
  })

  it("compares versions numerically, pre-releases before releases", () => {
    expect(compareVersions("1.10.0", "1.9.9")).toBe(1)
    expect(compareVersions("1.0", "1.0.0")).toBe(0)
    expect(compareVersions("2.0.0-beta.1", "2.0.0")).toBe(-1)
    expect(compareVersions("0.5.143", "0.5.144")).toBe(-1)
  })

  it("does nothing without a feed", async () => {
    serve({ "package.json": JSON.stringify({ dependencies: { "evil-every-version": "1.0.0" } }) })
    expect(osvFindings(await scanGitHubRepo(repo, { signatures: SIGNATURES }))).toEqual([])
  })
})
