import type { GitHubFinding, YaraRule } from "../types/index"
import { collectEvidence } from "../utils/evidence"

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
      const regex = new RegExp(rule.pattern, "gi")
      const matches = content.match(regex)
      if (matches && matches.length > 0) {
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
