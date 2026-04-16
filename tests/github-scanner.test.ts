import { describe, expect, it } from "vitest"
import { checkTyposquat, detectObfuscation, isTestFile } from "../src/github/repo-scanner"

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
