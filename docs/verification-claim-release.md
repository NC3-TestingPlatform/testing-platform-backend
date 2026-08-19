# Releasing a verified domain claim

A verified domain claim is **terminal and platform-wide**: the row in
`domain_verification` is unique on `value` across every organization, so once a
domain is proven it names exactly one organization and no other organization can
verify it. There is no self-service release and no platform-administrator surface
in v4.0 (IDR-016), which makes this document the release mechanism rather than a
description of one.

`POST /assets/{asset_id}/verification/checks` refuses a claimed domain with `409`
and problem type `domain-claim-lost`, and that refusal points here. The message
deliberately does not say which organization holds the claim: the conflicting row
belongs to another tenant and is invisible under row-level security, so naming it
would be a cross-tenant disclosure.

## When a release is legitimate

All four of these are ordinary, expected situations rather than abuse. The claim
model is first-prover-wins, and DNS control is a moment in time.

- **Ownership changed.** The domain was sold, or the organization holding it was
  acquired, merged or dissolved.
- **A departed employee's workspace holds it.** Registration provisions every
  registrant as `organization_admin` of their own organization, so an employee who
  verified a company domain from a personal account holds the claim in an
  organization the company does not control.
- **A provider verified a customer's domain.** A hosting provider, MSP or
  registrar with temporary write access to a customer's zone — common during
  onboarding, or through a stale reseller credential — can prove control they were
  never authorized to assert on the customer's behalf.
- **A test or a mistake.** The domain was verified from the wrong organization.

## Evidence to require before releasing

The claim authorizes scheduling and branded reporting in v4.0, and from v4.1 it
authorizes **intrusive scanning** of everything its scope covers. Releasing it to
the wrong party hands that authorization over, so treat a release request as an
authorization decision and not as a data-correction ticket.

Require, at minimum:

1. **Current control of the domain**, demonstrated the way verification
   demonstrates it: publish a TXT record the operator specifies, at a name the
   operator specifies. Current control is necessary but not sufficient — it is
   exactly what a provider holding an illegitimate claim also has.
2. **Authority to bind the domain's owner.** A named contact on the registrant
   record, a request on organization letterhead, or an existing contractual
   relationship. Zone control does not prove authority to bind a legal entity,
   which is the whole reason IDR-016 records provisioned tenancy as the target
   direction once a platform-admin area exists.
3. **A reason from the list above**, recorded in the ticket.

Where the request comes from a party other than the current claimant, notify the
current claimant at their organization admin's address before releasing, and give
them a window to object. A release without that notice turns this procedure into a
domain-takeover path.

## Procedure

Run as the migration-owning role, against the production database, inside a
transaction, with the ticket reference to hand.

```sql
BEGIN;

-- 1. Identify the claim. Record all of this in the ticket before changing
--    anything: the provenance columns are how a later dispute is settled.
SELECT dv.id,
       dv.organization_id,
       o.name           AS organization_name,
       dv.value,
       dv.verified_scope,
       dv.verified_at,
       dv.verified_by_user_id,
       dv.dnssec_validated,
       dv.resolvers,
       dv.corroborating_answers
  FROM domain_verification AS dv
  JOIN organization        AS o ON o.id = dv.organization_id
 WHERE dv.value = :domain;

-- 2. Release it. Removing the proof IS the release: the global unique index frees
--    the value, and the asset row is untouched, so the losing organization keeps
--    its inventory and its scan history and simply reads as unverified.
DELETE FROM domain_verification WHERE value = :domain;

COMMIT;
```

Then, outside the transaction:

- **Do not** clear `organization.named_at` for the losing organization. The name it
  was given is now its identity, and unsetting the stamp would let the *next*
  verification rename it — see the invariant in data-model §3.1.
- Tell the losing organization that the claim was released, and why. Their asset
  now reads `expired`, and any schedule that depended on verification stops being
  eligible.
- Record the release in the ticket with the values captured in step 1, the
  evidence, and who approved it. Until B7 lands there is no `audit_event` row for
  an operator action, so **the ticket is the audit trail**.

## What this procedure cannot fix

- **A forged proof against an unsigned zone is indistinguishable from a real one.**
  Roughly nine `.lu` domains in ten are unsigned (9.76% signed, dns.lu,
  2026-07-27), so most claims rest on resolver corroboration rather than on a
  signature. If a claim is disputed and `dnssec_validated` is false with a low
  `corroborating_answers`, the provenance is weak evidence and the decision has to
  rest on the paperwork in step 2.
- **A `zone` claim covers delegated subdomains its holder may not control.** The
  public-suffix guard is v4.1. Until then, a zone claim on a shared suffix is worth
  checking against the actual delegation before accepting it as authoritative.
