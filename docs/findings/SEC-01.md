# SEC-01: Broken object-level authorization (BOLA) on `GET /orders/{id}`

| Field | Value |
| --- | --- |
| Severity | High (cross-tenant data exposure) |
| Category | OWASP API Security Top 10 (2023) API1, Broken Object Level Authorization |
| Affected | `GET /orders/{id}` on branch `vulnerable/sec-01-bola` |
| Status | Fixed on `main` |
| Environment | Local lab, synthetic data |

## Summary

Any signed-in user can read any tenant's order by changing the numeric ID in the URL. The endpoint finds the order by ID only and never checks that the order belongs to the caller's tenant.

## Steps to reproduce (vulnerable branch)

1. Sign in as Alice (Tenant A) using `Authorization: Bearer token-alice`.
2. Request `GET /orders/1001`. It returns Tenant A's order, as expected.
3. Request `GET /orders/2001`. It returns **Tenant B's** order with status 200. This is the bug.

## Root cause

The lookup trusts the ID from the request:

```csharp
var order = db.Orders.FirstOrDefault(o => o.Id == id);
```

Authentication proves who the caller is. Nothing checks whether this caller may see this object.

## Impact

One customer can read another customer's orders. On a real system that is a data breach with contractual and legal consequences. Because IDs are sequential, an attacker can enumerate every order.

## Fix

Scope the query to the caller's tenant, taken from the verified identity and never from the request. Return the same 404 for a missing order and for another tenant's order, so the response does not confirm that the object exists:

```csharp
var tenant = user.FindFirstValue("tenant_id");
var order = db.Orders.FirstOrDefault(o => o.Id == id && tenant != null && o.TenantId == tenant);
return order is null ? Results.NotFound() : Results.Ok(order);
```

## Tests

7 tests (`Sec01_*`). 2 core and 5 bypass tests:

- Owner can read their own order
- Tenant A cannot read Tenant B's order
- Bypass: alternate ID (`2002`)
- Bypass: a Tenant B user cannot read Tenant A's order
- Bypass: token with no tenant claim gets 404
- Bypass: PUT and DELETE on the same route are not allowed
- Bypass: no token gets 401

On `vulnerable/sec-01-bola`, 4 of these fail. On `main`, all pass.

## What I did not test

Guessing attacks at scale, rate limiting, and other resources such as invoices.

## Lessons

Sequential IDs make the bug easy to exploit, but unpredictable IDs would not fix it. The fix is the ownership check on every request.
