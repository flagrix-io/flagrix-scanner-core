// Types
export type {
  RiskLevel,
  RiskFactor,
  RiskAssessment,
  LinkedInProfileFeatures,
  LinkedInScanResult,
  ScanDepth,
  GitHubRepoInfo,
  GitHubFinding,
  FindingEvidence,
  GitHubScanResult,
  GitHubUserFeatures,
  GitHubUserScanResult,
  DocumentMetadata,
  StaticAnalysisResult,
  VirusTotalResult,
  DocumentScanResult,
  MaliciousPackage,
  YaraRule,
  KnownBadHash,
  SignatureDatabase,
  RepoScanOptions,
  UserScanOptions,
  UserProfileRuleset,
  ProfileRiskRule,
  ProfileCondition,
  ProfileSimpleCondition,
  ProfileCompoundCondition,
  ProfileFeatureField,
  ProfileOperator,
  ProfileRiskLevels,
} from "./types/index.js"

export { RISK_THRESHOLDS, DEFAULT_DISCLAIMER } from "./types/index.js"

// GitHub scanners
export { scanGitHubRepo } from "./github/repo-scanner.js"
export { scanGitHubUser } from "./github/user-scanner.js"
export { DEFAULT_USER_PROFILE_RULES } from "./github/user-profile-ruleset.js"

// LinkedIn scorer
export { scoreLinkedInProfile } from "./linkedin/profile-scorer.js"

// PDF scanner
export { scanPdfBytes, scanPdfFromUrl } from "./pdf/pdf-scanner.js"
export type { PdfScanResult } from "./pdf/pdf-scanner.js"

// Utilities
export { calculateRiskScore, getSeverityWeight, getRiskLevel } from "./utils/risk-calculator.js"
export { applyYaraRules, isTestFile } from "./rules/rule-matcher.js"
