# @flagrix/scanner-core

Open-source scanning engine behind [Flagrix](https://flagrix.io) — detects malware, backdoors, and supply-chain attacks in GitHub repositories and GitHub profiles.

Built after real-world fake-recruiter campaigns ("coding assignment" repos that steal wallets, SSH keys, and browser sessions) started targeting developers. Flagrix scans before you clone.

## What it detects

- Known malicious npm packages (active campaign IOCs, typosquats)
- Obfuscated JavaScript (hex arrays, eval chains, base64 droppers)
- Supply-chain attacks (dependency confusion, install-time scripts)
- Backdoors, reverse shells, and data-exfiltration patterns
- Crypto miners and credential/wallet stealers
- Suspicious install hooks (postinstall, curl-pipe-bash)
- Social-engineering markers and repository anomalies

Signature data lives in the sibling repo [flagrix-detection-rules](https://github.com/flagrix-io/flagrix-detection-rules).

## Privacy — everything runs locally

All analysis happens on the caller's device — there is no Flagrix backend and no telemetry. The library's only network calls are to `api.github.com` (file contents and profile data), `codeload.github.com` (the commit tarball, when `tarball: true` is passed) and `api.npmjs.org` (package download counts for typosquat checks). Nothing that gets scanned — file contents, repo names, results — is sent to Flagrix or any third-party server. The optional `githubToken` is used exclusively as an `Authorization` header on GitHub API requests; it is never transmitted anywhere else.

## What gets scanned

A repo scan reads code files (`.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.py`, `.rb`, `.php`, `.go`, `.sh`, `.ps1`, `.psm1`, `.bat`, `.cmd`, `.vbs`) plus dependency manifests (`package.json`, lockfiles, `requirements.txt`, `setup.py`, and similar), capped at **200 files** and **1 MB per file** per scan.

When more source files are eligible than the cap allows, they are read in priority order: build and install scripts first (`scripts/`, `bin/`, `*.config.js`, `(pre|post)install.*`, dot-dir scripts), then ordinary source, then tests and samples, then generated or vendored artifacts (`dist/`, `*.min.js`) — every data-driven rule skips test files anyway, so spending the budget on them crowds out the code that actually runs on a clone. Files of equal priority keep tree order, and the order is also the fetch order, so a scan cut short by the rate limit has already read what matters most.

On top of that cap, it also reads up to **25 editor, agent and CI config files** (a byte budget instead when the repo is read as one snapshot, below), which developer tools execute or obey as soon as a repo is opened: `.vscode/{tasks,settings,launch,mcp}.json`, `.claude/settings(.local).json`, MCP configs (`.mcp.json`, `.cursor/mcp.json`, `.amazonq/mcp.json`, …), `.devcontainer/devcontainer.json`, `Dockerfile`/`Containerfile`, `docker-compose.yml` and other compose files, `.github/workflows/*.yml`, every `README` in the tree, and agent instruction files (`AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `.cursor/rules/**/*.mdc`, `.claude/commands/*.md`, `.claude/agents/*.md`, `.claude/skills/*/SKILL.md`, `.github/{instructions,prompts}/*.md`, …). When more config files match than the budget allows, the ones a tool executes are read first, then agent instruction files, then READMEs. A container build is scanned under the rule scope `.dockerfile.sh` and a compose file under `.compose.yml`, so every generic `.sh` / `.yml` rule still applies while a rule can also target just that file type — which a `fileNames` list cannot do, since `Dockerfile.prod` and `prod.Dockerfile` are the same type under different names. These files and `package.json` get the data-driven rules only, scoped by each rule's `fileExtensions` / `fileNames`. It also reads up to **10 font files** (≤ 512 KB each; every one on the snapshot path) and flags any that are really JavaScript (`MASQUERADED_SCRIPT_FONT`). Files that those configs (except CI workflows and container builds, whose steps run on a CI runner or inside a container rather than on your machine) or `package.json` scripts run with `node`/`bun`/`deno`/`tsx` (for example `node .vscode/spellright.dict` or a `preinstall: node setup.mjs`) are read as well, up to **10** per scan and whatever their extension or position in the source cap, and are scanned as JavaScript. Text files are decoded as UTF-8, so rules for invisible Unicode and bidi controls see real code points.

Everything else (other docs, images, data files, oversized blobs) is skipped, and the result says so: `scanSummary.scannedFiles` lists every file that was read, and `scanSummary.skippedFiles` lists what was skipped with a per-file reason (`unsupported-type`, `over-file-limit`, `too-large`, `fetch-failed`, `rate-limited`). The list is capped at 500 entries (`skippedCount` is the true total) and ordered by reason, most telling first — `rate-limited`, `fetch-failed`, `over-file-limit`, `too-large`, then `unsupported-type` — so the files a budget left out are never crowded off the list by images and lockfiles.

### How much gets read depends on how it is read

The 200-file cap above is a *request* budget, not a work budget: on the default
path each file costs its own round trip, so bounding the scan means bounding the
file count. Pass `tarball: true` and the whole commit arrives in one request
(`/repos/{owner}/{repo}/tarball/{sha}`), file count stops costing anything, and
the source budget becomes **16 MB of decoded source** instead. The 1 MB-per-file
limit is unchanged.

The config and font counts go too, since a count is exactly what padding a repo
with decoys defeats: 25 throwaway workflows or nested READMEs used to be enough
to push a hook file or a poisoned README out of the scan. On the snapshot path
configs get a **4 MB** budget of their own, still spent in the same order
(executed configs, then agent instructions, then READMEs) — the largest total in
the reference corpus is nodejs/node's 1.3 MB across 256 configs. Fonts are not
budgeted at all: every one is magic-number-checked as the archive streams, a
real font keeps only its first 64 bytes, and only a file that is not really a
font is held whole for the masquerade check (up to 8 MB of those). Counts of
2,000 configs and 2,000 fonts remain as backstops against pathological trees.

`node <path>` targets keep their cap of 10 on both paths: they are known only
once the configs naming them have been read, after the archive has streamed
past, so each one the archive did not already carry is its own request.

```ts
await scanGitHubRepo(repo, { signatures, tarball: true })
```

Measured on `facebook/react`: 226 files in 16.5 s on the per-file path, against
**4,373 files in 11.5 s** via the tarball — and one rate-limit unit instead of
231. What bounds the byte budget is memory, not time: the detectors retain every
file's masked copy for the whole scan, so peak heap runs about 13–14x the source
read, and 16 MB peaks around 217 MB. That is why the budget is not simply raised
to cover every repo whole.

It is **off by default**, because asking is not free. The endpoint redirects to
`codeload.github.com`, so a browser extension needs that origin granted — as an
*optional* host permission, since a required one is scored as a privilege
increase and disables the extension until every existing user re-approves it —
and a request made without it costs a round trip before it fails.

Every failure falls back to the per-file path rather than failing the scan: an
archive larger than the repo's tree says it should be (decided before any
request, so nothing is downloaded and abandoned), a refused or unreachable
endpoint, a body that is not a readable tarball. Files the archive did not carry
— a symlink, or a config's `node <path>` target found only after the configs
were read — are fetched individually.

`scanSummary.readMode` reports which reader ran (`"tarball"` or `"per-file"`),
and `scanSummary.readFallbackReason` why a requested tarball was not used
(`"too-large"`, `"unavailable"`, `"unreadable"`).

**Consumers must surface `readMode`.** Coverage decides the verdict, so two
people can get different scores for the same commit depending on which reader
ran — and for a security tool a verdict that varies silently is worse than one
that is slow.

The scan also makes two read-only calls for git-history signals: the branch's push activity and its last 100 commits. A commit pushed 30 or more days after its own date is flagged as `GIT_HISTORY_TAMPERING` / `BACKDATED_PUSH` (medium, or high for a force push). Account-takeover campaigns such as PolinRider backdate loader commits this way. Signed commits, branch creation and pushes onto an empty ref are exempt. A bare force push in the last 90 days is reported as low, non-blocking information. If either call fails, the scan continues without these signals.

## Usage

```ts
import { scanGitHubRepo, type SignatureDatabase } from "@flagrix/scanner-core"

const result = await scanGitHubRepo(
  { owner: "some-org", repo: "some-repo", branch: "main", url: "https://github.com/some-org/some-repo" },
  { signatures, githubToken } // token optional — raises rate limits, enables private repos
)

console.log(result.riskLevel) // "low" | "medium" | "high"
console.log(result.findings)  // detailed findings with severity + evidence
console.log(result.commitSha) // the exact commit the verdict applies to
```

To check dependencies against every package the OpenSSF malicious-packages project has confirmed malicious (OSV `MAL-*` records: about 220k npm and 12k PyPI names), also pass the `osv-malicious.json` feed that flagrix-detection-rules publishes next to `signatures.json`:

```ts
const osvFeed = await (await fetch("https://raw.githubusercontent.com/flagrix-io/flagrix-detection-rules/main/osv-malicious.json")).json()
await scanGitHubRepo(repo, { signatures, osvFeed })
```

The feed is matched locally: dependency names never leave the device. A hit is a critical `SUSPICIOUS_DEPENDENCY` / `OSV_MALICIOUS_PACKAGE` finding, with high confidence when every version is malicious or the exact affected version is pinned, and medium when a range such as `^1.2.0` merely starts inside an affected range. Packages the repo defines itself and `workspace:`/`file:`/`link:` specifiers are skipped.

Scans are pinned: the branch is resolved to a commit SHA up front and every file is read at that SHA, so a push mid-scan (or between scan and clone) can't invalidate the verdict silently — compare `commitSha` against the head you actually check out.

Also exported: `scanGitHubUser` (profile authenticity scoring) and the shared risk-calculation utilities. See [src/index.ts](src/index.ts) for the full API.

The package also ships standalone `scoreLinkedInProfile` and `scanPdfBytes` / `scanPdfFromUrl` scanners. These aren't wired into the current Flagrix extension (which is GitHub-only) or backed by rules in flagrix-detection-rules — they're available for anyone building on the library, but should be treated as unmaintained until that changes.

## GitHub API rate limits

`scanGitHubRepo` and `scanGitHubUser` call the GitHub REST API directly. A single repo scan issues one tree request plus up to 200 file-content requests (most repos need far fewer) — or, with `tarball: true`, one tree request plus **one** archive request whatever the file count, which is what makes a scan viable without a token at all. Unauthenticated, GitHub allows **60 requests/hour** — enough for scans of small repos. Pass a `githubToken` (a fine-grained or classic PAT, `public_repo`/`repo` scope) in the options to raise this to **5,000 requests/hour** and to scan private repositories:

```ts
await scanGitHubRepo(repo, { signatures, githubToken })
```

A scan that runs out of budget part-way through does **not** quietly return a
clean verdict. The first refusal (`x-ratelimit-remaining: 0`, or a secondary
limit's `retry-after`) stops the read — there is no point spending the next 150
requests on certain refusals — and every file that went unread is recorded as
`rate-limited`. The result then carries `scanSummary.complete: false` and
`scanSummary.incompleteReason: "rate-limit"`.

**Consumers must qualify the verdict when `complete` is false.** Files that were
never read cannot clear a repository, so "no findings" over partial coverage is
not a clean bill of health:

```ts
const result = await scanGitHubRepo(repo, { signatures })
if (!result.scanSummary.complete) {
  // Coverage fell short — say so instead of showing "safe to clone".
  console.warn(
    `Partial scan (${result.scanSummary.incompleteReason}): read ` +
      `${result.scanSummary.filesScanned} of ` +
      `${result.scanSummary.filesScanned + result.scanSummary.skippedCount} files.`
  )
}
```

`incompleteReason` is `"fetch-errors"` when individual reads failed for some
other reason; those do not stop the scan, since one bad response says nothing
about the next file.

## What a 404 means

GitHub answers `404` rather than `403` for a repository the caller may not see, so "not found" really means "not visible to you". `githubNotFoundError(hasToken)` splits the two cases, because they have different fixes:

| `githubToken` | Message |
|---|---|
| absent | The repo is private; add a token. |
| present | The token expired, or it's a fine-grained token whose repository access doesn't cover this repo. |

Reporting both as "add a token" sends someone who already has one nowhere.

## Risk scoring

Findings are weighted by severity (`critical` 0.4, `high` 0.25, `medium` 0.15, `low` 0.05, `info` 0.01), summed, and capped at 1.0. The pre-cap sum is also returned as `rawRiskScore`, and `factors[]` carries one entry per deduped signal with the confidence-adjusted weight actually counted — factor weights always sum to `rawRiskScore`, so a consumer-rendered deduction breakdown reconciles with the score. `getRiskLevel` maps the score to a level using the shared `RISK_THRESHOLDS` (`< 0.3` low, `< 0.6` medium, otherwise high) — with one override: a single `critical` finding always forces `high`, since a lone backdoor or keylogger shouldn't average down to "review before cloning" just because nothing else in the repo was flagged. Pass `findings` as the scanner does (`getRiskLevel(score, findings)`) to get this floor; omit it to fall back to threshold-only scoring. The GitHub **user** scanner uses its own tuned thresholds because profile signals (account age, follower ratios) distribute differently from code findings.

## Development

```bash
npm install
npm run build   # tsc → dist/
npm test        # vitest
```

Pure TypeScript with a single runtime dependency (`franc-min` for language detection). Callers inject network and storage — the primary consumer is the Flagrix Chrome extension, which currently uses the GitHub repo and profile scanners and supplies `fetch` results and signature data. See [CONTRIBUTING.md](CONTRIBUTING.md) to add a detector or report a false positive.

## Disclaimer

Risk assessments are informational, not definitive malware or fraud determinations. Always verify through official channels.

## AI Disclosure

This project leverages Claude AI for boilerplate generation, test-suite expansion, and optimization. All AI-generated code is strictly reviewed, refactored, and verified by human maintainers before merging.

## License

MIT — see [LICENSE](LICENSE).

---

*Part of the [Flagrix](https://flagrix.io) open-core security platform.*
