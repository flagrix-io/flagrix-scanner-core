import type { GitHubFinding, YaraRule } from "../types/index.js"
import { collectEvidence } from "../utils/evidence.js"

// Test file patterns — skip or reduce severity for these paths
const TEST_FILE_PATTERNS = [
  /__tests__\//i,
  /\/test\//i,
  /\/tests\//i,
  /\/spec\//i,
  /\.test\.[jt]sx?$/i,
  /\.spec\.[jt]sx?$/i,
  /_test\.[jt]sx?$/i,
  /\.mock\.[jt]sx?$/i,
  /fixtures?\//i,
  /cypress\.config\.[jt]sx?$/i,
  /jest\.config\.[jt]sx?$/i,
  /vitest\.config\.[jt]sx?$/i,
  /playwright\.config\.[jt]sx?$/i,
  /\/cypress\//i,
  /\/e2e\//i,
]

export function isTestFile(filePath: string): boolean {
  return TEST_FILE_PATTERNS.some((pattern) => pattern.test(filePath))
}

export function applyYaraRules(
  content: string,
  rules: YaraRule[],
  filePath: string
): GitHubFinding[] {
  const findings: GitHubFinding[] = []
  const isTest = isTestFile(filePath)

  for (const rule of rules) {
    try {
      // Honor the rule's file-extension scope (default: all scanned files).
      if (
        rule.fileExtensions &&
        rule.fileExtensions.length > 0 &&
        !rule.fileExtensions.some((ext) => filePath.endsWith(ext))
      ) {
        continue
      }

      const regex = new RegExp(rule.pattern, "gi")
      const matches = content.match(regex)
      // Honor the rule's match threshold (e.g. "6+ base64 strings" — a single
      // occurrence of a legitimate encoding is not a signal).
      const required = rule.minMatches && rule.minMatches > 1 ? rule.minMatches : 1
      if (matches && matches.length >= required) {
        // Skip test files for non-critical patterns (reduce false positives)
        if (isTest && rule.severity !== "critical") {
          continue
        }

        findings.push({
          severity: rule.severity as GitHubFinding["severity"],
          type: "MALWARE_SIGNATURE",
          file: filePath,
          pattern: rule.id,
          description: rule.description,
          evidence: collectEvidence(content, regex),
        })
      }
    } catch {
      // Invalid regex, skip
    }
  }

  return findings
}
