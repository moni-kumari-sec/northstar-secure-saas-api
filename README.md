# northstar-secure-saas-api

A small multi-tenant ASP.NET Core API for a fictional company, **Northstar Orders**. I plant authorization flaws on labeled branches, fix each one, and write regression tests, including bypass attempts, to show the fix holds.

**Status:** in progress (started November 2026). Nothing below is claimed as done until the linked report and tests exist.

> **Safety:** Branches named `vulnerable/*` will contain deliberately flawed code for learning. Run it locally only. Do not deploy it. All data is synthetic.

## Why this matters

Two customers (Tenant A and Tenant B) share one API. If tenant isolation or role checks fail, one customer can read or change another customer's data. This project shows how that happens, how to fix it, and how to keep it fixed.

## Planned findings

| ID | Flaw | Expected fix | Report | Status |
| --- | --- | --- | --- | --- |
| SEC-01 | Broken object-level authorization (BOLA): Tenant A reads Tenant B's order by changing the ID | Tenant-scoped queries | docs/findings/SEC-01.md | Planned |
| SEC-02 | Broken function-level authorization (BFLA): a normal user calls an admin route | Role check on the endpoint | docs/findings/SEC-02.md | Planned |
| SEC-03 | Mass assignment: a user sets their own role in a profile update | Explicit request DTOs | docs/findings/SEC-03.md | Planned |

Each fix needs a test that fails on the vulnerable branch and passes on `main`, plus at least two bypass tests (alternate HTTP method, nested route, other role, omitted tenant claim, alternate ID).

## Planned API surface

`POST /login` · `GET /orders/{id}` · `GET /invoices/{id}` · `PATCH /users/{id}` · `POST /refund-requests` · `GET /admin/audit`

## Threat model

Starter threat register: [docs/threat-model/threat-model.md](docs/threat-model/threat-model.md)

## Quick start

Coming once the first version of the API is committed. The goal is one command to start the app and one command to run the tests.

## Results

Test counts, bypass tests, and a short demo will be added here as they exist.

## What I will not test

- Production deployment, network-level attacks, and performance under load

## License

To be added.
