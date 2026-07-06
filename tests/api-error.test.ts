import { describe, expect, it } from "vitest"

import { githubApiError } from "../src/github/api-error"

function response(
  status: number,
  body: unknown,
  headers: Record<string, string> = {}
): Response {
  return new Response(JSON.stringify(body), { status, headers })
}

describe("githubApiError", () => {
  it("explains SAML/SSO enforcement 403s", async () => {
    const err = await githubApiError(
      response(403, {
        message:
          "Resource protected by organization SAML enforcement. You must grant your OAuth token access to this organization."
      })
    )
    expect(err.message).toContain("SSO authorization")
    expect(err.message).toContain("Configure SSO")
  })

  it("detects SSO via the X-GitHub-SSO header when the body is unhelpful", async () => {
    const err = await githubApiError(
      response(403, { message: "Forbidden" }, { "x-github-sso": "required; url=https://github.com/orgs/acme/sso" })
    )
    expect(err.message).toContain("SSO authorization")
  })

  it("explains org-level PAT restrictions", async () => {
    const err = await githubApiError(
      response(403, {
        message:
          "`acme` forbids access via a fine-grained personal access tokens if the token's lifetime is greater than 366 days."
      })
    )
    expect(err.message).toContain("restricts personal access tokens")
  })

  it("explains rate limiting", async () => {
    const err = await githubApiError(
      response(
        403,
        { message: "API rate limit exceeded for 1.2.3.4." },
        { "x-ratelimit-remaining": "0" }
      )
    )
    expect(err.message).toContain("rate limit")
  })

  it("explains invalid tokens", async () => {
    const err = await githubApiError(response(401, { message: "Bad credentials" }))
    expect(err.message).toContain("invalid or expired")
  })

  it("appends GitHub's message to other errors", async () => {
    const err = await githubApiError(response(422, { message: "Validation Failed" }))
    expect(err.message).toBe("GitHub API error: 422 — Validation Failed")
  })

  it("falls back to the bare status for non-JSON bodies", async () => {
    const err = await githubApiError(new Response("<html>", { status: 500 }))
    expect(err.message).toBe("GitHub API error: 500")
  })

  it("supports a custom fallback label", async () => {
    const err = await githubApiError(new Response("x", { status: 502 }), "Failed to fetch events")
    expect(err.message).toBe("Failed to fetch events: 502")
  })
})
