import { describe, expect, it } from "vitest"
import {
  calculateRawRiskScore,
  calculateRiskScore,
  calculateSignalContributions,
  getRiskLevel,
  getSeverityWeight,
} from "../src/utils/risk-calculator"
import type { GitHubFinding } from "../src/types/index"

function finding(
  severity: GitHubFinding["severity"],
  confidence?: GitHubFinding["confidence"],
  pattern?: string
): GitHubFinding {
  return {
    severity,
    confidence,
    type: "MALWARE_SIGNATURE",
    pattern,
    description: `Test ${severity} finding`,
  }
}

describe("getSeverityWeight", () => {
  it("returns correct weights for each severity", () => {
    expect(getSeverityWeight("critical")).toBe(0.4)
    expect(getSeverityWeight("high")).toBe(0.25)
    expect(getSeverityWeight("medium")).toBe(0.15)
    expect(getSeverityWeight("low")).toBe(0.05)
    expect(getSeverityWeight("info")).toBe(0.01)
  })
})

describe("calculateRiskScore", () => {
  it("returns 0 for empty findings", () => {
    expect(calculateRiskScore([])).toBe(0)
  })

  it("sums severity weights correctly", () => {
    const score = calculateRiskScore([finding("high", undefined, "A"), finding("medium", undefined, "B")])
    expect(score).toBeCloseTo(0.4) // 0.25 + 0.15
  })

  it("caps at 1.0", () => {
    const manyFindings = Array.from({ length: 10 }, (_, index) =>
      finding("critical", undefined, `rule-${index}`)
    )
    expect(calculateRiskScore(manyFindings)).toBe(1)
  })

  it("returns a single critical finding score of 0.4", () => {
    expect(calculateRiskScore([finding("critical")])).toBeCloseTo(0.4)
  })

  it("discounts medium- and low-confidence heuristic findings", () => {
    expect(calculateRiskScore([finding("critical", "medium")])).toBeCloseTo(0.24)
    expect(calculateRiskScore([finding("critical", "low")])).toBeCloseTo(0.1)
  })

  it("does not multiply one repeated signal across many files", () => {
    expect(calculateRiskScore([
      finding("medium", "medium", "OBF_EVAL"),
      finding("medium", "medium", "OBF_EVAL"),
      finding("medium", "medium", "OBF_EVAL"),
    ])).toBeCloseTo(0.09)
  })

  it("groups related obfuscation heuristics as one signal family", () => {
    const minification: GitHubFinding = {
      severity: "medium",
      confidence: "low",
      type: "CODE_INTEGRITY_ISSUE",
      description: "Minified/obfuscated code detected in source repository",
    }
    expect(calculateRiskScore([
      finding("medium", "low", "OBF_BASE64_HEAVY"),
      finding("medium", "low", "OBF_HEX_STRINGS"),
      finding("medium", "low", "OBF_EVAL"),
      minification,
    ])).toBeCloseTo(0.0375)
  })
})

describe("calculateSignalContributions", () => {
  it("weights sum exactly to the raw risk score", () => {
    const findings = [
      finding("critical", "medium", "BACKDOOR_RCE"),
      finding("high", undefined, "EXFIL_COOKIE"),
      finding("medium", "low", "OBF_EVAL"),
      finding("medium", "low", "OBF_HEX_STRINGS"),
      finding("high", undefined, "EXFIL_COOKIE"),
    ]
    const contributions = calculateSignalContributions(findings)
    const total = contributions.reduce((sum, c) => sum + c.weight, 0)
    expect(total).toBeCloseTo(calculateRawRiskScore(findings), 10)
  })

  it("collapses repeats into one contribution, keeping the strongest finding", () => {
    const weak = finding("medium", "low", "OBF_EVAL")
    const strong = finding("medium", "medium", "OBF_EVAL")
    const contributions = calculateSignalContributions([weak, strong])
    expect(contributions).toHaveLength(1)
    expect(contributions[0]!.weight).toBeCloseTo(0.09) // 0.15 × 0.6
    expect(contributions[0]!.finding).toBe(strong)
    expect(contributions[0]!.findingCount).toBe(2)
  })

  it("applies confidence multipliers to the counted weight", () => {
    const [c] = calculateSignalContributions([finding("critical", "low", "X")])
    expect(c!.weight).toBeCloseTo(0.1) // 0.4 × 0.25
  })

  it("merges the obfuscation heuristic family into one signal", () => {
    const contributions = calculateSignalContributions([
      finding("medium", "low", "OBF_BASE64_HEAVY"),
      finding("medium", "low", "OBF_HEX_STRINGS"),
    ])
    expect(contributions).toHaveLength(1)
    expect(contributions[0]!.signal).toBe("OBFUSCATION_HEURISTIC")
    expect(contributions[0]!.findingCount).toBe(2)
  })
})

describe("getRiskLevel", () => {
  it("returns low for score < 0.3", () => {
    expect(getRiskLevel(0)).toBe("low")
    expect(getRiskLevel(0.1)).toBe("low")
    expect(getRiskLevel(0.29)).toBe("low")
  })

  it("returns medium for score 0.3–0.59", () => {
    expect(getRiskLevel(0.3)).toBe("medium")
    expect(getRiskLevel(0.45)).toBe("medium")
    expect(getRiskLevel(0.59)).toBe("medium")
  })

  it("returns high for score >= 0.6", () => {
    expect(getRiskLevel(0.6)).toBe("high")
    expect(getRiskLevel(0.8)).toBe("high")
    expect(getRiskLevel(1)).toBe("high")
  })

  it("forces high when any finding is critical, even if the score is medium", () => {
    // A lone keylogger/backdoor in an otherwise-small repo (score 0.4) must
    // never soften to "review before cloning".
    expect(getRiskLevel(0.4, [finding("critical")])).toBe("high")
  })

  it("does not force high for a heuristic critical match", () => {
    expect(getRiskLevel(0.24, [finding("critical", "medium")])).toBe("low")
  })

  it("ignores the floor when no finding is critical", () => {
    expect(getRiskLevel(0.4, [finding("high"), finding("medium")])).toBe("medium")
  })

  it("still applies normal thresholds when findings is omitted", () => {
    expect(getRiskLevel(0.4)).toBe("medium")
  })

  it("forces high for an independently confirmed malicious dependency", () => {
    const maliciousDependency: GitHubFinding = {
      severity: "high",
      confidence: "high",
      type: "SUSPICIOUS_DEPENDENCY",
      package: "known-malware",
      description: "Known malicious package",
    }
    expect(getRiskLevel(0.25, [maliciousDependency])).toBe("high")
  })
})

describe("the verdict floor for configs a tool executes", () => {
  const inFile = (f: GitHubFinding, file: string): GitHubFinding => ({ ...f, file })
  const padding = finding("high", "medium", "HIDDEN_CODE_WHITESPACE_PADDING")

  it("makes one strong finding in an executed config at least medium", () => {
    // The fixture's tailwind.config.js: 0.15 + 0.0375 scored low before.
    const findings = [
      inFile(padding, "tailwind.config.js"),
      inFile(finding("medium", "low", "OBF_FROMCHARCODE"), "tailwind.config.js"),
    ]
    expect(calculateRiskScore(findings)).toBeCloseTo(0.1875)
    expect(getRiskLevel(calculateRiskScore(findings), findings)).toBe("medium")
  })

  it("covers bundler, lint and test configs and committed hooks", () => {
    for (const file of [
      "next.config.mjs", "apps/web/vite.config.ts", "postcss.config.cjs",
      ".eslintrc.cjs", ".githooks/pre-commit", ".husky/pre-push",
    ]) {
      expect(getRiskLevel(0.15, [inFile(padding, file)])).toBe("medium")
    }
  })

  it("leaves the same finding in an ordinary source file to the score", () => {
    expect(getRiskLevel(0.15, [inFile(padding, "src/config.js")])).toBe("low")
    expect(getRiskLevel(0.15, [inFile(padding, "config/webpack.js")])).toBe("low")
  })

  it("is not raised by low-confidence, medium-severity or secret findings", () => {
    const file = "tailwind.config.js"
    expect(getRiskLevel(0.0625, [inFile(finding("high", "low", "X"), file)])).toBe("low")
    expect(getRiskLevel(0.15, [inFile(finding("medium", "high", "X"), file)])).toBe("low")
    expect(getRiskLevel(0.15, [inFile(finding("high", "medium", "HARDCODED_API_KEY"), file)])).toBe("low")
    expect(getRiskLevel(0.25, [{
      severity: "high", type: "HARDCODED_SECRETS", file, description: "secret",
    }])).toBe("low")
  })

  it("takes the caller's idea of an executed config", () => {
    const hooksPathHook = inFile(padding, "tools/hooks/pre-commit")
    expect(getRiskLevel(0.15, [hooksPathHook])).toBe("low")
    expect(getRiskLevel(0.15, [hooksPathHook], (path) => path.startsWith("tools/hooks/"))).toBe("medium")
  })
})
