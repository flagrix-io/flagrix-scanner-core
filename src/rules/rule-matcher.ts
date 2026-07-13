import type { GitHubFinding, YaraRule } from "../types/index.js"
import { collectEvidence } from "../utils/evidence.js"

// Test file patterns — skip or reduce severity for these paths
const TEST_FILE_PATTERNS = [
  /(?:^|\/)__tests__\//i,
  /(?:^|\/)tests?\//i,
  /(?:^|\/)spec\//i,
  /(?:^|\/)benchmarks?\//i,
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

const KEYBOARD_LISTENER =
  /(?:addEventListener\s*\(\s*['"](?:keydown|keypress|keyup)['"]|\.on(?:keydown|keypress|keyup)\s*=)/gi
const KEY_VALUE = /\b[A-Za-z_$][\w$]*\.(?:key|code|keyCode|which)\b/gi
const KEYBOARD_SINKS = [
  /(?:fetch|axios\.(?:post|put|patch)|navigator\.sendBeacon|XMLHttpRequest|WebSocket)\b/gi,
  /(?:localStorage|sessionStorage)\.setItem\s*\(/gi,
  /(?:writeFile|writeFileSync|appendFile|appendFileSync)\s*\(/gi,
  /\b(?:send|post|emit|upload|transmit|report|collect|capture|record|store|save)\w*\s*\([^)]*\b[A-Za-z_$][\w$]*\.(?:key|code|keyCode|which)\b/gi,
  /(?:\+=|\.push\s*\()\s*\b[A-Za-z_$][\w$]*\.(?:key|code|keyCode|which)\b/gi,
]

export interface KeyboardCaptureContext {
  evidencePatterns: RegExp[]
}

const PLACEHOLDER_SECRET_WORDS =
  /(?:^|[-_.\s])(?:your|change|replace|example|dummy|placeholder|development|dev|test|sample|not[-_]?secret|changeme)(?:$|[-_.\s])/i

export function isObviousPlaceholderSecret(match: string): boolean {
  const quotedValue = match.match(/['"]([^'"]+)['"]\s*$/)?.[1]
  if (!quotedValue) return false
  return PLACEHOLDER_SECRET_WORDS.test(quotedValue)
}

export function isDocumentedAwsExampleKey(match: string): boolean {
  return /\bAKIAIOSFODNN7EXAMPLE\b/.test(match)
}

const CASE_SENSITIVE_RULE_IDS = new Set([
  "HARDCODED_AWS_KEY",
  "HARDCODED_GITHUB_TOKEN",
  "HARDCODED_STRIPE_KEY",
  "NETWORK_TELEGRAM_TOKEN",
])

/**
 * A keyboard listener is normal UI code. Treat it as keylogging only when the
 * nearby handler both reads the pressed key and stores or transmits it.
 */
export function detectKeyboardCapture(content: string): KeyboardCaptureContext | null {
  const listeners = [...content.matchAll(KEYBOARD_LISTENER)]
  for (const listener of listeners) {
    const start = listener.index ?? 0
    // Keep source and sink correlated to one small handler-sized region.
    const region = content.slice(start, start + 2_000)
    if (!KEY_VALUE.test(region)) continue
    KEY_VALUE.lastIndex = 0

    const sink = KEYBOARD_SINKS.find((pattern) => {
      pattern.lastIndex = 0
      return pattern.test(region)
    })
    if (sink) {
      KEYBOARD_LISTENER.lastIndex = 0
      KEY_VALUE.lastIndex = 0
      sink.lastIndex = 0
      return { evidencePatterns: [KEYBOARD_LISTENER, KEY_VALUE, sink] }
    }
  }
  KEYBOARD_LISTENER.lastIndex = 0
  KEY_VALUE.lastIndex = 0
  return null
}

export function applyYaraRules(
  content: string,
  rules: YaraRule[],
  filePath: string,
  scopePath = filePath
): GitHubFinding[] {
  const findings: GitHubFinding[] = []
  const isTest = isTestFile(scopePath)

  for (const rule of rules) {
    try {
      // Test and benchmark sources intentionally contain attack-shaped inputs
      // and dynamic execution. Dependency metadata is still scanned separately.
      if (isTest) continue

      // Honor the rule's file-extension scope (default: all scanned files).
      if (
        rule.fileExtensions &&
        rule.fileExtensions.length > 0 &&
        !rule.fileExtensions.some((ext) => scopePath.endsWith(ext))
      ) {
        continue
      }
      if (
        rule.fileNames &&
        rule.fileNames.length > 0 &&
        !rule.fileNames.includes(scopePath.split("/").pop() ?? scopePath)
      ) {
        continue
      }

      const regex = new RegExp(
        rule.pattern,
        CASE_SENSITIVE_RULE_IDS.has(rule.id) ? "g" : "gi"
      )
      const matches = content.match(regex)
      // Honor the rule's match threshold (e.g. "6+ base64 strings" — a single
      // occurrence of a legitimate encoding is not a signal).
      const required = rule.minMatches && rule.minMatches > 1 ? rule.minMatches : 1
      if (matches && matches.length >= required) {
        if (rule.id === "HARDCODED_AWS_KEY" && matches.every(isDocumentedAwsExampleKey)) {
          continue
        }
        // A documented placeholder is not a stolen credential or malware.
        // Keep the deployment warning, but don't let it block cloning.
        if (
          rule.id === "HARDCODED_API_KEY" &&
          matches.every(isObviousPlaceholderSecret)
        ) {
          findings.push({
            severity: "low",
            confidence: "high",
            cloneBlocking: false,
            type: "INSECURE_CONFIGURATION",
            file: filePath,
            pattern: rule.id,
            description: "Predictable placeholder secret must be replaced before deployment",
            evidence: collectEvidence(content, regex),
          })
          continue
        }

        // Treat legacy cached EXFIL_KEYLOGGER rules as context-aware too, so
        // clients are protected before their next signature refresh.
        const contextName =
          rule.context ?? (rule.id === "EXFIL_KEYLOGGER" ? "keyboard-capture" : undefined)
        const context =
          contextName === "keyboard-capture" ? detectKeyboardCapture(content) : null
        if (contextName && !context) continue
        findings.push({
          severity: rule.severity as GitHubFinding["severity"],
          confidence: rule.confidence ?? "high",
          type: "MALWARE_SIGNATURE",
          file: filePath,
          pattern: rule.id,
          description: rule.description,
          evidence: collectEvidence(content, context?.evidencePatterns ?? regex),
        })
      }
    } catch {
      // Invalid regex, skip
    }
  }

  return findings
}
