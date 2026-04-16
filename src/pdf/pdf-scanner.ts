/**
 * PDF Scanner
 *
 * Client-side PDF analysis without external APIs.
 * Analyzes raw PDF bytes for suspicious patterns:
 * - Embedded JavaScript / auto-actions
 * - Embedded files/attachments
 * - Suspicious URL patterns
 * - Obfuscated content
 * - Social engineering markers
 *
 * Does NOT use pdf.js DOM parsing — works in service worker context
 * by analyzing the raw PDF byte structure directly.
 */

interface PdfFinding {
  severity: "critical" | "high" | "medium" | "low" | "info"
  type: string
  description: string
}

export interface PdfScanResult {
  riskScore: number
  riskLevel: "low" | "medium" | "high"
  findings: PdfFinding[]
  metadata: {
    pageCount: number
    hasJavaScript: boolean
    hasEmbeddedFiles: boolean
    hasAutoActions: boolean
    fileSize: number
  }
  safeToOpen: boolean
  disclaimer: string
}

const DANGEROUS_PDF_PATTERNS: Array<{
  pattern: RegExp
  type: string
  severity: PdfFinding["severity"]
  description: string
}> = [
  { pattern: /\/JavaScript\s/i, type: "EMBEDDED_JS", severity: "critical", description: "PDF contains embedded JavaScript" },
  { pattern: /\/JS\s*\(/i, type: "EMBEDDED_JS", severity: "critical", description: "PDF contains JavaScript action" },
  { pattern: /\/OpenAction/i, type: "AUTO_ACTION", severity: "high", description: "PDF has auto-open action (runs on open)" },
  { pattern: /\/AA\s/i, type: "AUTO_ACTION", severity: "high", description: "PDF has additional automatic actions" },
  { pattern: /\/Launch/i, type: "LAUNCH_ACTION", severity: "critical", description: "PDF contains Launch action (can execute programs)" },
  { pattern: /\/SubmitForm/i, type: "FORM_SUBMIT", severity: "high", description: "PDF submits form data to external server" },
  { pattern: /\/ImportData/i, type: "IMPORT_DATA", severity: "high", description: "PDF imports external data" },
  { pattern: /\/EmbeddedFile/i, type: "EMBEDDED_FILE", severity: "high", description: "PDF contains embedded files" },
  { pattern: /\/Filespec/i, type: "EMBEDDED_FILE", severity: "medium", description: "PDF references file attachments" },
  { pattern: /\/AcroForm/i, type: "INTERACTIVE_FORM", severity: "low", description: "PDF contains interactive form fields" },
  { pattern: /\/RichMedia/i, type: "RICH_MEDIA", severity: "medium", description: "PDF contains rich media (Flash/multimedia)" },
  { pattern: /\/XFA/i, type: "XFA_FORM", severity: "high", description: "PDF uses XFA forms (common exploit vector)" },
  { pattern: /app\.launchURL/i, type: "URL_LAUNCH", severity: "critical", description: "PDF launches external URL via JavaScript" },
  { pattern: /this\.exportDataObject/i, type: "DATA_EXPORT", severity: "high", description: "PDF exports data objects" },
  { pattern: /eval\s*\(/i, type: "JS_EVAL", severity: "critical", description: "PDF contains eval() JavaScript execution" },
  { pattern: /unescape\s*\(/i, type: "JS_OBFUSCATION", severity: "high", description: "PDF uses unescape() (common obfuscation)" },
]

const SUSPICIOUS_URLS: RegExp[] = [
  /bit\.ly/i,
  /tinyurl\.com/i,
  /goo\.gl/i,
  /is\.gd/i,
  /ngrok\.io/i,
  /raw\.githubusercontent\.com.*\.(exe|bat|ps1|sh)/i,
  /pastebin\.com\/raw/i,
  /transfer\.sh/i,
  /discord\.gg/i,
]

const MALWARE_TOOLS = /msfvenom|metasploit|cobaltstrike|veil-evasion|empire|set\s*toolkit/i

export async function scanPdfFromUrl(url: string): Promise<PdfScanResult> {
  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`Failed to fetch PDF: ${response.status}`)
  }
  const arrayBuffer = await response.arrayBuffer()
  return scanPdfBytes(new Uint8Array(arrayBuffer))
}

export function scanPdfBytes(bytes: Uint8Array): PdfScanResult {
  const findings: PdfFinding[] = []
  const rawText = new TextDecoder("latin1").decode(bytes)

  if (!rawText.startsWith("%PDF")) {
    findings.push({
      severity: "high",
      type: "INVALID_PDF",
      description: "File does not have a valid PDF header",
    })
  }

  let hasJavaScript = false
  let hasAutoActions = false
  let hasEmbeddedFiles = false

  for (const check of DANGEROUS_PDF_PATTERNS) {
    if (check.pattern.test(rawText)) {
      findings.push({
        severity: check.severity,
        type: check.type,
        description: check.description,
      })

      if (check.type === "EMBEDDED_JS" || check.type === "JS_EVAL" || check.type === "JS_OBFUSCATION") {
        hasJavaScript = true
      }
      if (check.type === "AUTO_ACTION" || check.type === "LAUNCH_ACTION") {
        hasAutoActions = true
      }
      if (check.type === "EMBEDDED_FILE") {
        hasEmbeddedFiles = true
      }
    }
  }

  const urlMatches = rawText.match(/https?:\/\/[^\s)<>"]+/gi) || []
  const suspiciousUrlSet = new Set<string>()

  for (const url of urlMatches) {
    for (const pattern of SUSPICIOUS_URLS) {
      if (pattern.test(url)) {
        suspiciousUrlSet.add(url.substring(0, 100))
      }
    }
    if (/\.(exe|bat|cmd|ps1|sh|msi|dll|scr|vbs|wsf)(\?|$)/i.test(url)) {
      findings.push({
        severity: "critical",
        type: "EXECUTABLE_LINK",
        description: `Link to executable: ${url.substring(0, 100)}`,
      })
    }
  }

  for (const url of suspiciousUrlSet) {
    findings.push({
      severity: "high",
      type: "SUSPICIOUS_URL",
      description: `Suspicious shortened/redirect URL: ${url}`,
    })
  }

  const producerMatch = rawText.match(/\/Producer\s*\(([^)]+)\)/i)
  const creatorMatch = rawText.match(/\/Creator\s*\(([^)]+)\)/i)
  const toolString = (producerMatch?.[1] || "") + (creatorMatch?.[1] || "")

  if (MALWARE_TOOLS.test(toolString)) {
    findings.push({
      severity: "critical",
      type: "MALWARE_TOOL",
      description: `PDF created with known exploit framework: ${toolString.substring(0, 80)}`,
    })
  }

  const streamCount = (rawText.match(/stream\r?\n/g) || []).length
  const encodedStreams = (rawText.match(/\/Filter\s*\[?\s*\/[A-Z]/g) || []).length

  if (streamCount > 5 && encodedStreams > streamCount * 0.8) {
    findings.push({
      severity: "medium",
      type: "HEAVY_ENCODING",
      description: `Heavily encoded: ${encodedStreams}/${streamCount} streams use filters`,
    })
  }

  const pageCountMatch = rawText.match(/\/Count\s+(\d+)/i)
  const pageCount = pageCountMatch ? parseInt(pageCountMatch[1]!, 10) : 0

  const criticalCount = findings.filter((f) => f.severity === "critical").length
  const highCount = findings.filter((f) => f.severity === "high").length
  const mediumCount = findings.filter((f) => f.severity === "medium").length

  const riskScore = Math.min(1, criticalCount * 0.35 + highCount * 0.15 + mediumCount * 0.05)
  const riskLevel: "low" | "medium" | "high" =
    riskScore >= 0.6 ? "high" : riskScore >= 0.3 ? "medium" : "low"

  return {
    riskScore,
    riskLevel,
    findings,
    metadata: {
      pageCount,
      hasJavaScript,
      hasEmbeddedFiles,
      hasAutoActions,
      fileSize: bytes.length,
    },
    safeToOpen: riskLevel === "low",
    disclaimer:
      "Risk assessment only. Not a definitive malware determination. Always verify documents from unknown sources.",
  }
}
