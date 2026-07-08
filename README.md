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

Scans are pinned: the branch is resolved to a commit SHA up front and every file is read at that SHA, so a push mid-scan (or between scan and clone) can't invalidate the verdict silently — compare `commitSha` against the head you actually check out.

Also exported: `scanGitHubUser` (profile authenticity scoring) and the shared risk-calculation utilities. See [src/index.ts](src/index.ts) for the full API.

The package also ships standalone `scoreLinkedInProfile` and `scanPdfBytes` / `scanPdfFromUrl` scanners. These aren't wired into the current Flagrix extension (which is GitHub-only) or backed by rules in flagrix-detection-rules — they're available for anyone building on the library, but should be treated as unmaintained until that changes.

## GitHub API rate limits

`scanGitHubRepo` and `scanGitHubUser` call the GitHub REST API directly. A single repo scan issues one tree request plus up to ~50 file-content requests. Unauthenticated, GitHub allows **60 requests/hour** — enough for a handful of scans. Pass a `githubToken` (a fine-grained or classic PAT, `public_repo`/`repo` scope) in the options to raise this to **5,000 requests/hour** and to scan private repositories:

```ts
await scanGitHubRepo(repo, { signatures, githubToken })
```

## Risk scoring

Findings are weighted by severity (`critical` 0.4, `high` 0.25, `medium` 0.15, `low` 0.05, `info` 0.01), summed, and capped at 1.0. `getRiskLevel` maps the score to a level using the shared `RISK_THRESHOLDS` (`< 0.3` low, `< 0.6` medium, otherwise high) — with one override: a single `critical` finding always forces `high`, since a lone backdoor or keylogger shouldn't average down to "review before cloning" just because nothing else in the repo was flagged. Pass `findings` as the scanner does (`getRiskLevel(score, findings)`) to get this floor; omit it to fall back to threshold-only scoring. The GitHub **user** scanner uses its own tuned thresholds because profile signals (account age, follower ratios) distribute differently from code findings.

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
