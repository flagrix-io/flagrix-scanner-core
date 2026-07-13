import { describe, expect, it } from "vitest"
import { checkTyposquat, detectObfuscation, isTestFile } from "../src/github/repo-scanner"
import { applyYaraRules, detectKeyboardCapture } from "../src/rules/rule-matcher"

describe("isTestFile", () => {
  it("detects __tests__ directory", () => {
    expect(isTestFile("src/__tests__/foo.ts")).toBe(true)
  })

  it("detects .test.ts files", () => {
    expect(isTestFile("src/utils/foo.test.ts")).toBe(true)
  })

  it("detects .spec.ts files", () => {
    expect(isTestFile("src/utils/foo.spec.ts")).toBe(true)
  })

  it("detects /test/ directory", () => {
    expect(isTestFile("src/test/helpers.ts")).toBe(true)
  })

  it("detects vitest.config.ts", () => {
    expect(isTestFile("vitest.config.ts")).toBe(true)
  })

  it("detects /cypress/ directory", () => {
    expect(isTestFile("cypress/e2e/login.cy.ts")).toBe(true)
  })

  it("returns false for normal source files", () => {
    expect(isTestFile("src/lib/scanner.ts")).toBe(false)
    expect(isTestFile("src/index.ts")).toBe(false)
    expect(isTestFile("package.json")).toBe(false)
  })

  it("detects root-level test and benchmark directories", () => {
    expect(isTestFile("test/auth.js")).toBe(true)
    expect(isTestFile("tests/auth.js")).toBe(true)
    expect(isTestFile("benchmark/eval.js")).toBe(true)
  })
})

describe("checkTyposquat", () => {
  it("detects simple typosquats (1-char edit)", () => {
    expect(checkTyposquat("lodahs")).toBe("lodash")
    expect(checkTyposquat("expres")).toBe("express")
    expect(checkTyposquat("reeact")).toBe("react")
  })

  it("detects transposition typosquats", () => {
    // lodsah: swap a/s positions relative to lodash — 2 substitutions, distance = 2
    expect(checkTyposquat("lodsah")).toBe("lodash")
  })

  it("returns null for legitimate popular packages", () => {
    expect(checkTyposquat("lodash")).toBeNull()
    expect(checkTyposquat("express")).toBeNull()
    expect(checkTyposquat("react")).toBeNull()
  })

  it("returns null for unrelated packages", () => {
    expect(checkTyposquat("zod")).toBeNull()
    expect(checkTyposquat("flagrix-scanner-core")).toBeNull()
    expect(checkTyposquat("completely-unrelated-pkg")).toBeNull()
  })
})

describe("detectObfuscation", () => {
  it("detects heavy Base64 usage", () => {
    // Use space-free base64 strings (50+ consecutive chars required by regex)
    const b64 = "SGVsbG9Xb3JsZEhlbGxvV29ybGRIZWxsb1dvcmxkSGVsbG9Xb3JsZA=="
    const content = Array(10).fill(b64).join("\n")
    const findings = detectObfuscation(content, "src/index.js")
    expect(findings.some((f) => f.description.includes("Base64"))).toBe(true)
  })

  it("detects eval abuse", () => {
    const content = `eval(atob("c29tZSBtYWxpY2lvdXMgY29kZQ=="))`
    const findings = detectObfuscation(content, "src/index.js")
    expect(findings.some((f) => f.description.includes("Dynamic code execution"))).toBe(true)
  })

  it("detects hex-encoded strings", () => {
    const content = Array(25).fill("\\x41\\x42\\x43\\x44").join("")
    const findings = detectObfuscation(content, "src/index.js")
    expect(findings.some((f) => f.description.includes("hex-encoded"))).toBe(true)
  })

  it("skips test files for non-critical patterns", () => {
    const content = Array(10)
      .fill("dGhpcyBpcyBhIHRlc3QgYmFzZTY0IHN0cmluZw==")
      .join("\n")
    const findings = detectObfuscation(content, "src/__tests__/index.test.js")
    expect(findings).toHaveLength(0)
  })

  it("returns empty for clean code", () => {
    const content = `
      const greeting = "Hello, world!"
      function add(a: number, b: number) { return a + b }
    `
    const findings = detectObfuscation(content, "src/utils.ts")
    expect(findings).toHaveLength(0)
  })
})

describe("keyboard capture context", () => {
  const rule = {
    id: "EXFIL_KEYLOGGER",
    name: "Keyboard Capture and Transmission",
    pattern:
      "(?:addEventListener\\s*\\(\\s*['\\\"](?:keydown|keypress|keyup)['\\\"]|\\.on(?:keydown|keypress|keyup)\\s*=)",
    description: "Reads and transmits pressed keys",
    tags: ["keylogger"],
    severity: "critical" as const,
    context: "keyboard-capture" as const,
  }

  it("ignores llmfit-style Escape modal handling", () => {
    const content = `document.addEventListener('keydown', (e) => {\n  if (e.key === 'Escape') closeModal()\n})`
    expect(detectKeyboardCapture(content)).toBeNull()
    expect(applyYaraRules(content, [rule], "ui/app.js")).toHaveLength(0)
  })

  it("ignores navigation shortcuts that do not retain key data", () => {
    const content = `window.addEventListener("keyup", event => {\n  if (event.code === "ArrowDown") selectNext()\n})`
    expect(applyYaraRules(content, [rule], "src/shortcuts.ts")).toHaveLength(0)
  })

  it("detects a key read passed to a transmission sink", () => {
    const content = `document.addEventListener("keydown", (event) => {\n  sendCapturedKey(event.key)\n})`
    const findings = applyYaraRules(content, [rule], "src/payload.js")
    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({
      pattern: "EXFIL_KEYLOGGER",
      severity: "critical",
      confidence: "high",
    })
  })
})

describe("test-source and documented-placeholder controls", () => {
  it("does not classify critical attack-shaped fixtures in test directories", () => {
    const rule = {
      id: "REVERSE_SHELL",
      name: "Reverse shell",
      pattern: "net\\.Socket\\(\\)",
      description: "Socket behavior",
      tags: ["shell"],
      severity: "critical" as const,
    }
    expect(applyYaraRules("net.Socket()", [rule], "test/socket.js")).toHaveLength(0)
  })

  it("ignores AWS's reserved documentation key but keeps other key-shaped values", () => {
    const rule = {
      id: "HARDCODED_AWS_KEY",
      name: "AWS key",
      pattern: "AKIA[0-9A-Z]{16}",
      description: "AWS key-shaped value",
      tags: ["credentials"],
      severity: "critical" as const,
    }
    expect(applyYaraRules("AKIAIOSFODNN7EXAMPLE", [rule], "src/docs.js")).toHaveLength(0)
    expect(applyYaraRules("AKIAJhisMixedCaseCoincidence", [rule], "dist/bundle.js")).toHaveLength(0)
    expect(applyYaraRules("AKIA1234567890ABCDEF", [rule], "src/config.js")).toHaveLength(1)
  })
})

describe("placeholder secret classification", () => {
  const rule = {
    id: "HARDCODED_API_KEY",
    name: "Hardcoded API Key",
    pattern:
      "(?:api[_-]?key|apikey|secret[_-]?key|auth[_-]?token|private[_-]?key)\\s*[:=]\\s*['\"]([^'\"]{20,})['\"]",
    description: "Generic API key / secret key pattern assigned to a variable",
    tags: ["secrets"],
    severity: "critical" as const,
  }

  it("reports an obvious placeholder as a non-blocking configuration warning", () => {
    const findings = applyYaraRules(
      `app.secret_key = 'your-secret-key-change-in-production'`,
      [rule],
      "app.py"
    )
    expect(findings).toEqual([
      expect.objectContaining({
        type: "INSECURE_CONFIGURATION",
        severity: "low",
        cloneBlocking: false,
        pattern: "HARDCODED_API_KEY",
      }),
    ])
  })

  it("keeps a non-placeholder secret critical", () => {
    const findings = applyYaraRules(
      `app.secret_key = 'b7d21cc9aab14575b676c579b96ec790'`,
      [rule],
      "app.py"
    )
    expect(findings).toEqual([
      expect.objectContaining({
        type: "MALWARE_SIGNATURE",
        severity: "critical",
      }),
    ])
  })
})

describe("data-driven regex performance", () => {
  const rule = {
    id: "OBF_CHARCODE_ARRAY",
    name: "Large Character Code Array",
    pattern: "\\[\\s*(?:\\d{2,3}\\s*,\\s*){20,}\\d{2,3}\\s*\\]",
    description: "Array of 20+ numbers that look like character codes",
    tags: ["charcode-array", "obfuscation"],
    severity: "medium" as const,
    fileExtensions: [".ts"],
  }

  it("rejects large Unicode range tables without catastrophic backtracking", () => {
    const unicodeRanges = `[${Array.from({ length: 2_000 }, (_, index) =>
      1_000 + index
    ).join(", ")}]`
    expect(applyYaraRules(unicodeRanges, [rule], "src/compiler/scanner.ts")).toHaveLength(0)
  })

  it("still detects arrays containing 20 or more character codes", () => {
    const characterCodes = `[${Array.from({ length: 21 }, (_, index) =>
      65 + index
    ).join(", ")}]`
    expect(applyYaraRules(characterCodes, [rule], "src/payload.ts")).toHaveLength(1)
  })
})
