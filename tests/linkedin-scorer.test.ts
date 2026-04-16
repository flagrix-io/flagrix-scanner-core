import { describe, expect, it } from "vitest"
import { scoreLinkedInProfile } from "../src/linkedin/profile-scorer"
import type { LinkedInProfileFeatures } from "../src/types/index"

const baseFeatures: LinkedInProfileFeatures = {
  profileUrl: "https://www.linkedin.com/in/test-user",
  accountAgeDays: null,
  connectionCount: null,
  followerCount: null,
  hasProfilePhoto: true,
  workHistoryCount: 3,
  educationCount: 1,
  endorsementCount: 5,
  postCount: 10,
  mutualConnections: 5,
  profileCompleteness: 0.8,
  name: "Test User",
  headline: "Software Engineer",
  location: "San Francisco, CA",
  isVerified: false,
  isTopVoice: false,
  hasJobPostings: false,
  hasOpenToWork: false,
}

describe("scoreLinkedInProfile", () => {
  it("scores a clean, established profile as low risk", () => {
    const features: LinkedInProfileFeatures = {
      ...baseFeatures,
      accountAgeDays: 730,
      connectionCount: 600,
      followerCount: 600,
      mutualConnections: 20,
      isVerified: true,
    }
    const result = scoreLinkedInProfile(features)
    expect(result.riskLevel).toBe("low")
    expect(result.riskScore).toBeLessThan(0.3)
  })

  it("scores a brand-new, empty profile as high risk", () => {
    const features: LinkedInProfileFeatures = {
      ...baseFeatures,
      accountAgeDays: 5,
      connectionCount: 3,
      followerCount: 3,
      hasProfilePhoto: false,
      workHistoryCount: 0,
      educationCount: 0,
      endorsementCount: 0,
      postCount: 0,
      mutualConnections: 0,
      profileCompleteness: 0.1,
    }
    const result = scoreLinkedInProfile(features)
    expect(result.riskLevel).toBe("high")
    expect(result.riskScore).toBeGreaterThan(0.6)
  })

  it("scores a medium-risk profile in medium range", () => {
    const features: LinkedInProfileFeatures = {
      ...baseFeatures,
      accountAgeDays: 45,
      connectionCount: 80,
      followerCount: 80,
      mutualConnections: 0,
      postCount: 0,
    }
    const result = scoreLinkedInProfile(features)
    expect(result.riskLevel).toBe("medium")
    expect(result.riskScore).toBeGreaterThanOrEqual(0.3)
    expect(result.riskScore).toBeLessThan(0.6)
  })

  it("returns separate risk factors and trust signals", () => {
    const features: LinkedInProfileFeatures = {
      ...baseFeatures,
      accountAgeDays: 10,
      connectionCount: 500,
    }
    const result = scoreLinkedInProfile(features)
    const riskFactors = result.factors.filter((f) => f.weight > 0)
    const trustSignals = result.factors.filter((f) => f.weight < 0)
    expect(riskFactors.length).toBeGreaterThan(0)
    expect(trustSignals.length).toBeGreaterThan(0)
  })

  it("applies Top Voice badge as strong trust signal", () => {
    // Add risk factors so the -0.20 Top Voice credit produces a visible score difference
    const risky = { ...baseFeatures, accountAgeDays: 10, connectionCount: 5, followerCount: 5 }
    const withTopVoice = scoreLinkedInProfile({ ...risky, isTopVoice: true })
    const withoutTopVoice = scoreLinkedInProfile({ ...risky, isTopVoice: false })
    expect(withTopVoice.riskScore).toBeLessThan(withoutTopVoice.riskScore)
  })

  it("always clamps risk score between 0 and 1", () => {
    const extremeHigh: LinkedInProfileFeatures = {
      ...baseFeatures,
      accountAgeDays: 1,
      connectionCount: 0,
      followerCount: 0,
      hasProfilePhoto: false,
      workHistoryCount: 0,
      educationCount: 0,
      endorsementCount: 0,
      postCount: 0,
      mutualConnections: 0,
      profileCompleteness: 0,
    }
    const result = scoreLinkedInProfile(extremeHigh)
    expect(result.riskScore).toBeGreaterThanOrEqual(0)
    expect(result.riskScore).toBeLessThanOrEqual(1)
  })
})
