# SEC-02: Broken function-level authorization (BFLA) on `GET /admin/audit`

| Field | Value |
| --- | --- |
| Severity | High (privileged data exposed to ordinary users) |
| Category | OWASP API Security Top 10 (2023) API5, Broken Function Level Authorization |
| Affected | `GET /admin/audit` on branch `vulnerable/sec-02-bfla` |
| Status | Fixed on `main` |
| Environment | Local lab, synthetic data |

## Summary

The admin audit log endpoint requires a signed-in user but does not check the user's role. Any normal user can read it.

## Steps to reproduce (vulnerable branch)

1. Sign in as Alice (role: User) using `Authorization: Bearer token-alice`.
2. Request `GET /admin/audit`.
3. The server returns the audit log with status 200. Expected: 403.

## Root cause

The route was registered without an authorization policy for the Admin role. The app's fallback policy only requires authentication, so any signed-in user passes.

## Impact

Ordinary users can see administrative activity and other users' email addresses. The same pattern on a write endpoint would allow privilege escalation.

## Fix

Apply a role policy to the endpoint and keep deny-by-default for everything else:

```csharp
options.AddPolicy("AdminOnly", p => p.RequireRole("Admin"));

app.MapGet("/admin/audit", (DataStore db) => Results.Ok(db.AuditLog))
   .RequireAuthorization("AdminOnly");
```

## Tests

7 tests (`Sec02_*`). 2 core and 5 bypass tests:

- Admin can read the audit log
- Normal user gets 403
- Bypass: no token gets 401
- Bypass: trailing slash (`/admin/audit/`) is not allowed
- Bypass: different casing (`/ADMIN/AUDIT`) is not allowed
- Bypass: a user from another tenant gets 403
- Bypass: POST to the same route is not allowed

On `vulnerable/sec-02-bfla`, 4 of these fail. On `main`, all pass.

## What I did not test

Header-based path overrides that depend on a reverse proxy, which this lab does not have.

## Lessons

Hiding an admin link is not a control. Every privileged function needs its own server-side role check, and a deny-by-default fallback catches routes that someone forgets.
