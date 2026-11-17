# Threat Model: Northstar Orders API (draft v1)

Scope: local lab with synthetic data. This is a starting register. I will refine it as I build and test the API, and link each threat to a real test.

## System

Two tenants (A and B) use one ASP.NET Core API. Users have a role (user or admin). The API reads and writes orders, invoices, and user profiles in a database.

## Data-flow diagram

To be added as `dfd.png` (drawn in OWASP Threat Dragon).

Elements: tenant users and admin (external), the API (process), the database (data store). Trust boundaries: internet to API, and API to database.

## Assets

Orders and invoices, user profiles and roles, access tokens, audit log.

## Threat register

| # | Asset | Data flow | STRIDE | Abuse scenario | Impact | Proposed control | Linked test | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Orders | User to GET /orders/{id} | Information disclosure | Tenant A changes the ID to read Tenant B's order | Cross-tenant data leak | Tenant-scoped queries | SEC-01 tests | Planned |
| 2 | Admin audit log | User to GET /admin/audit | Elevation of privilege | Normal user calls the admin route | Audit data exposed | Role check, deny by default | SEC-02 tests | Planned |
| 3 | User role | User to PATCH /users/{id} | Tampering | User sends a role field in the body | Privilege escalation | Explicit request DTOs | SEC-03 tests | Planned |
| 4 | Access token | Client to API | Spoofing | Stolen or forged token used to call the API | Account takeover | Validate signature, expiry, audience | To write | Open |
| 5 | Login | User to POST /login | Spoofing | Repeated password guessing | Account takeover | Rate limiting, lockout | To write | Open |
| 6 | Order data | API to database | Tampering | SQL injection in a search parameter | Data read or altered | Parameterized queries | To write | Open |
| 7 | Refund requests | User to POST /refund-requests | Repudiation | User denies a refund request was made | Disputes, no evidence | Audit events with user, tenant, time | To write | Open |
| 8 | API availability | Client to API | Denial of service | Flood of expensive requests | Service unavailable | Rate limits, request size limits | To write | Open |

## Residual risk

To be written after the controls are implemented and tested.
