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
} from "./types/index"

export { RISK_THRESHOLDS, DEFAULT_DISCLAIMER } from "./types/index"

// GitHub scanners
export { scanGitHubRepo } from "./github/repo-scanner"
export { scanGitHubUser } from "./github/user-scanner"

// LinkedIn scorer
export { scoreLinkedInProfile } from "./linkedin/profile-scorer"

// PDF scanner
export { scanPdfBytes, scanPdfFromUrl } from "./pdf/pdf-scanner"
export type { PdfScanResult } from "./pdf/pdf-scanner"

// Utilities
export { calculateRiskScore, getSeverityWeight, getRiskLevel } from "./utils/risk-calculator"
export { applyYaraRules, isTestFile } from "./rules/rule-matcher"
