---
status: accepted
accepted: 2026-07-30
reviewed-baseline: 911dc11f9a3ca002087b832f2aca09f21354a67d
---

# Adopt owner-first runtime and protocol migration

Shannon IMS assigns one owner to RuntimeAttempt, MessagingCapability,
CarrierBehavior, ProtectedChannel, SWUSession, and StatePublication/Reconcile.
The six names are domain Modules, not a requirement to create same-named Go
types or packages. Each migration moved invariants behind an existing deep
Interface and removed the superseded owner or bypass after equivalent contracts
passed; a permanent forwarding wrapper is not completion.

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

## Implemented decision

- `internal/vowifihost.Manager` plus `Store` own RuntimeAttempt admission,
  currentness, claim, cancellation, joined stop, StatePublication, desired
  Reconcile, and the cancelable APDU-busy schedule. Worker, attempt, instance,
  SWu, and SA token domains remain separate.
- `vowifi-go/runtimehost.Instance` owns the stop-safe MessagingCapability.
  Production SMS and USSD callers cannot borrow the raw messaging
  implementation.
- `vowifi-go/internal/vowifi/policy.CarrierBehavior` is resolved once per
  RuntimeAttempt and downstream code consumes typed decisions rather than
  reinterpreting the diagnostic template ID.
- `vowifi-go/runtimehost.swuSessionLease` owns a candidate-scoped session,
  Connect task, result, ready state, dataplane, MOBIKE admission, cancel, and
  joined cleanup.
- `vowifi-go/internal/vowifi/ipsec3gpp.ProtectedChannelOwner` owns every SA
  generation's policy, transforms, UDP/TCP flows, ports, replay state, adoption,
  replacement, and joined teardown. REGISTER passes an opaque lease, not a
  pointer bundle.
- CI treats root, `vowifi-go`, and `third_party/swu-go` as three independent Go
  Modules, each with direct test and vet gates; concurrency-sensitive packages
  also have direct race gates.

## Consequences

Callers now learn smaller Interfaces and ownership failures have one Locality.
The compatibility baseline remains 310/240 and 234/15 (including normalized
234/015), with unchanged REGISTER, SWu, IKE, IPsec, protected UDP/TCP, SMS, and
USSD wire behavior.

`Manager.BroadcastState` is intentionally retained as a notification-only Seam
for device facts such as cache, radio, and SIM identity changes. It accepts no
runtime state and cannot bypass RuntimeAttempt publication authority. Runtime
state is accepted only through the current attempt/instance checks in `Store`.

Legacy deletion remains evidence-gated. Internal zero-call adapters may be
removed as a chain. Exported `runtimehost/voiceclient.Dial` and its
`swuPacketConn` implementation remain until an external Interface census is
available; tests or possible external consumers are not deleted to manufacture
a clean census.
