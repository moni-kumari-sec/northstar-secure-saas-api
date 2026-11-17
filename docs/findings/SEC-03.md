# SEC-03: Mass assignment on `PATCH /users/{id}`

| Field | Value |
| --- | --- |
| Severity | High (privilege escalation and tenant change) |
| Category | OWASP API Security Top 10 (2023) API3, Broken Object Property Level Authorization |
| Affected | `PATCH /users/{id}` on branch `vulnerable/sec-03-mass-assignment` |
| Status | Fixed on `main` |
| Environment | Local lab, synthetic data |

## Summary

The profile update endpoint binds the request body directly onto the internal user model. A user can include `role` or `tenantId` in the JSON and change fields they should never control.

## Steps to reproduce (vulnerable branch)

1. Sign in as Alice (role: User) using `Authorization: Bearer token-alice`.
2. Send `PATCH /users/1` with body `{"displayName":"Alice","role":"Admin"}`.
3. Request `GET /users/1`. The role is now `Admin`. Sending `{"tenantId":"tenant-b"}` moves the account to another tenant.

## Root cause

The endpoint accepts the full `UserRecord` model as its input and copies the role and tenant fields onto the stored record. The client decides which fields to send, so the client decides what changes.

## Impact

Any user can become an administrator or move into another tenant, which chains directly into SEC-01 and SEC-02.

## Fix

Use an explicit request type with only the fields a user may change. Role and tenant do not exist on it, so they cannot be set from the body:

```csharp
public record UpdateProfileRequest(string? DisplayName, string? Email);
```

The endpoint also checks that the caller is updating their own profile.

## Tests

6 tests (`Sec03_*`). 2 core and 4 bypass tests:

- User can update their own display name
- User cannot set their own role
- Bypass: uppercase field name (`ROLE`)
- Bypass: role nested inside another object
- Bypass: tenant cannot be changed
- Bypass: a user cannot edit another user's profile

On `vulnerable/sec-03-mass-assignment`, 3 of these fail. On `main`, all pass.

## What I did not test

Other serializers and content types such as XML or form posts.

## Lessons

Never bind a request onto an internal model. Define the request shape explicitly and map the allowed fields one by one.
