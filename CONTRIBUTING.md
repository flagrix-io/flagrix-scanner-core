# Contributing to @flagrix/scanner-core

Thank you for helping keep developers safe! This repo holds the **pure scanning
engine** behind Flagrix. Detection *data* (signatures, malicious packages, YARA
rules) lives in the separate [flagrix-detection-rules](https://github.com/flagrix-io/flagrix-detection-rules)
repo — add IOCs there, add *detection logic* here.

## Ground rules

- Keep the engine **pure**: no `chrome.*`, no `fetch` singletons, no environment
  assumptions. Network and storage are injected by the caller (see `RepoScanOptions`).
- Every detector must be **deterministic** and safe to run on hostile input. Bound
  your regexes (avoid catastrophic backtracking) and cap how much content you scan.
- **Accuracy over noise.** A scanner that cries wolf loses trust. Prefer a precise
  rule that occasionally misses over a broad one that flags legitimate code. If a
  detector is prone to false positives, gate it behind a volume/confidence threshold
  (see the non-English comment detector for the pattern).

## Adding or changing a detector

1. Detectors live in `src/github/repo-scanner.ts`, `src/github/user-scanner.ts`,
   `src/linkedin/profile-scorer.ts`, and `src/pdf/pdf-scanner.ts`.
2. Return `GitHubFinding`s with an honest `severity` and `confidence`. Severity
   describes potential impact; confidence describes certainty that the matched
   code has that behavior. Reserve high-confidence `critical` for verified
   code-execution / credential-theft chains. Heuristic critical matches do not
   force the final verdict to high risk.
3. Add a test. Unit-test the helper directly, or add an end-to-end case to
   `tests/repo-scanner.integration.test.ts`, which drives `scanGitHubRepo` through a
   mocked GitHub API. **Use only benign, non-malicious fixtures** that reproduce the
   *pattern* (e.g. a hardcoded `"admin123"` literal), never real malware or shellcode.
4. `npm run build && npm test` must pass.

## Reporting a false positive

Open an issue with the repository (or a minimal snippet) that was mis-flagged, the
finding it produced, and why it's benign. False-positive reports are as valuable as
new detectors.

## AI disclosure

This project uses Claude AI for boilerplate, test expansion, and optimization. All
AI-generated code is reviewed, refactored, and verified by human maintainers before
merging — please hold your contributions to the same bar.
