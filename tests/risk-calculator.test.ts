import { describe, expect, it } from "vitest"
import { calculateRiskScore, getRiskLevel, getSeverityWeight } from "../src/utils/risk-calculator"
import type { GitHubFinding } from "../src/types/index"

function finding(severity: GitHubFinding["severity"]): GitHubFinding {
  return {
    severity,
    type: "MALWARE_SIGNATURE",
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
    const score = calculateRiskScore([finding("high"), finding("medium")])
    expect(score).toBeCloseTo(0.4) // 0.25 + 0.15
  })

  it("caps at 1.0", () => {
    const manyFindings = Array(10).fill(finding("critical"))
    expect(calculateRiskScore(manyFindings)).toBe(1)
  })

  it("returns a single critical finding score of 0.4", () => {
    expect(calculateRiskScore([finding("critical")])).toBeCloseTo(0.4)
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

  it("ignores the floor when no finding is critical", () => {
    expect(getRiskLevel(0.4, [finding("high"), finding("medium")])).toBe("medium")
  })

  it("still applies normal thresholds when findings is omitted", () => {
    expect(getRiskLevel(0.4)).toBe("medium")
  })
})
