---
status: proposed
---

# Adopt owner-first runtime and protocol migration

Shannon IMS will migrate toward one owner for RuntimeAttempt,
MessagingCapability, CarrierBehavior, ProtectedChannel, SWUSession, and
StatePublication/Reconcile. Each migration must move an invariant behind the
target Module's Interface and delete the old owner or bypass after equivalent
contracts pass; adding a permanent forwarding wrapper is not completion.

This decision preserves separate Worker, attempt, RuntimeInstance, SWU, and SA
generation domains rather than replacing them with one global counter. It also
keeps device eligibility outside StatePublication/Reconcile, SIP orchestration
outside ProtectedChannel, IKE/Child-SA protocol details inside the swu-go
Adapter, and runtime carrier overrides distinct from CarrierBehavior wire
policy.

## Considered options

- A big-bang rewrite was rejected because both validated carriers depend on
  load-bearing ordering and wire behavior that must be migrated one invariant at
  a time.
- One global generation was rejected because Worker, attempt, Instance, and SA
  freshness have different lifetimes and failure modes.
- Permanent compatibility facades were rejected because they preserve duplicate
  state and decisions while making the new Module appear deeper than it is.
- Keeping ProtectedChannel ownership in imscore was rejected because SIP
  orchestration should not own transform, replay, protected flow, and teardown
  resources; imscore consumes one opaque channel handle instead.

## Consequences

Migration proceeds in three gated stages and temporarily costs extra
characterization tests. In return, callers learn smaller Interfaces, ownership
and cleanup gain Locality, legacy paths acquire explicit deletion criteria, and
the current 310/240 and 234/15 successful behavior remains the acceptance
baseline. This ADR remains proposed until the blueprint receives independent
review.
