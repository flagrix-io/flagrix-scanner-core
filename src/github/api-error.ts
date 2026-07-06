/**
 * Turns a failed GitHub API response into an actionable error.
 *
 * GitHub uses 403 for several unrelated conditions (SAML/SSO enforcement,
 * disabled classic PATs, rate limiting) and explains which one in the JSON
 * body — so surface that instead of a bare status code.
 */
export async function githubApiError(
  response: Response,
  fallback = "GitHub API error"
): Promise<Error> {
  let apiMessage = ""
  try {
    const body = (await response.json()) as { message?: unknown }
    if (typeof body?.message === "string") apiMessage = body.message
  } catch {
    // Non-JSON body — fall through to the status-only message.
  }

  if (response.status === 401) {
    return new Error(
      "GitHub token is invalid or expired — update it in Flagrix settings (401)."
    )
  }

  if (response.status === 403) {
    if (/saml|sso/i.test(apiMessage) || response.headers?.get("x-github-sso")) {
      return new Error(
        "This organization requires SSO authorization for your token. Open github.com/settings/tokens and use 'Configure SSO' on your token to authorize it for the organization (403)."
      )
    }
    if (/personal access token/i.test(apiMessage)) {
      return new Error(
        `This organization restricts personal access tokens — ${apiMessage} (403).`
      )
    }
    if (response.headers?.get("x-ratelimit-remaining") === "0") {
      return new Error(
        "GitHub API rate limit exceeded. Add a personal access token in Flagrix settings to raise the limit (403)."
      )
    }
  }

  return new Error(
    apiMessage
      ? `${fallback}: ${response.status} — ${apiMessage}`
      : `${fallback}: ${response.status}`
  )
}
