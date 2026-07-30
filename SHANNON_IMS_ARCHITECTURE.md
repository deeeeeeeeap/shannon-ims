# Shannon IMS owner architecture

## Status and scope

The owner-first migration is implemented and independently gated. This document
describes the current architecture, not a proposed wrapper topology.

The reviewed baseline before this engineering-closure work was:

- branch `main`;
- `HEAD == origin/main == 911dc11f9a3ca002087b832f2aca09f21354a67d`;
- a clean working tree;
- validated carrier contracts for 310/240, 234/15, and normalized 234/015.

The closure work adds direct CI gates for the local swu-go Module, removes one
provably dead internal Adapter, and updates architecture records. It does not
change protocol wire bytes, carrier behavior, device behavior, dependencies, or
an installed runtime.

## Architecture rules

1. Every mutable lifecycle or protocol resource has one owner.
2. Module names express domain ownership; they do not justify same-named Go
   types, packages, Interfaces, or wrappers.
3. A Module must pass the deletion test: removing it must make its invariants
   reappear across callers. Otherwise it is shallow and should not exist.
4. Callers and tests cross the same Seam.
5. One Adapter is a hypothetical Seam. Retain a Seam only when behavior varies
   or when the Seam enforces a lifecycle invariant callers cannot reproduce.
6. Worker, RuntimeAttempt, RuntimeInstance, SWu, and SA generation domains stay
   distinct.
7. A migration is complete only when the old owner or bypass is removed, or its
   evidence-based retention reason is recorded.

The accepted decision is recorded in
[ADR-0001](./ADR-0001-owner-first-runtime-and-protocol-migration.md).

## Frozen compatibility contract

Engineering cleanup must preserve:

- 310/240 resolves to `3gpp-default`;
- 234/15 and 234/015 resolve to `vodafone_uk_23415`;
- current initial and authenticated REGISTER behavior;
- explicit SIP statuses fail closed for transport/candidate fallback;
- current SWu candidate ordering and bounded budgets;
- group 14 direct success, bounded group 15 negotiation feedback, and
  negotiated-group rekey;
- current IKE, Child SA, ESP, replay, and dataplane behavior;
- current protected UDP/TCP selection, MSS handling, framing, port roles, and
  winning P-CSCF binding;
- distinct IMSReady and SMSReady states;
- current SMS and USSD presentation and transport behavior;
- `submit_report_success` means SMSC acceptance, not terminal delivery;
- only a correlated SMS-STATUS-REPORT with successful TP status means
  terminal delivery.

## Current owner flow

~~~mermaid
flowchart TD
    Facts["device facts Adapter"] --> Control["RuntimeAttempt + StatePublication/Reconcile"]
    Intent["enable / recover / switch / stop"] --> Control
    Control --> Instance["RuntimeInstance"]
    Control --> Carrier["CarrierBehavior"]
    Instance --> SWU["SWUSession lease"]
    Carrier --> IMS["IMS REGISTER orchestration"]
    SWU --> IMS
    IMS --> Protected["ProtectedChannel owner"]
    Protected --> Messaging["MessagingCapability"]
    Instance --> Control
    Messaging --> Control
~~~

## Owner matrix

| Module | Concrete owner | Unique responsibility | Evidence anchors |
| --- | --- | --- | --- |
| RuntimeAttempt | `internal/vowifihost.Manager`, `Store`, and `LifecycleController` | Admission, preemption, currentness, claim, cancel, replacement, and joined stop | `runtime_attempt_control_test.go`, lifecycle/reconcile tests |
| StatePublication/Reconcile | `internal/vowifihost.Store` and `Manager` | Attempt-aware startup/live state, notification, desired-state dedupe/backoff/result, and APDU-busy schedule | `state_pubsub_test.go`, `reconcile_test.go`, `apdu_busy_recover_test.go` |
| CarrierBehavior | `vowifi-go/internal/vowifi/policy.CarrierBehavior` | One normalized home-PLMN decision for REGISTER, transport, retry, and messaging presentation | policy defaults and carrier-consumption contracts |
| SWUSession | `vowifi-go/runtimehost.swuSessionLease` | Candidate-scoped session, Connect task/result, ready/snapshot, dataplane, MOBIKE admission, cancel, and join | `swu_session_lifecycle_test.go` |
| ProtectedChannel | `vowifi-go/internal/vowifi/ipsec3gpp.ProtectedChannelOwner` | SA generation, policy, transforms, UDP/TCP flows, ports, replay, adoption/replacement, and joined teardown | protected owner and imscore adoption tests |
| MessagingCapability | `vowifi-go/runtimehost.Instance` | Ready/stopped checks, safe borrow/release, SMS/USSD dispatch, and Stop join | runtimehost capability plus device production-chain tests |

The domain name `RuntimeAttempt` is intentionally not a concrete struct.
Lifecycle generation and startup epoch remain separate tokens inside the host
owner. Likewise, StatePublication is an invariant of `Store`, not another
notification wrapper.

## Implemented ownership

### RuntimeAttempt and StatePublication/Reconcile

- Lifecycle commands enter one per-device controller.
- `Store` owns lifecycle generation, startup epoch, claimed instance, run
  cancel, desired recovery state, and APDU-busy schedule state.
- Startup callbacks are accepted only while their attempt is current.
- Runtime callbacks are accepted only when both epoch and claimed instance
  match.
- Stop/replacement invalidates the old attempt and joins the owned runtime.
- Reconcile deduplicates work, owns backoff/result state, and cancels remaining
  APDU-busy retries after success, policy block, switch, forget, or teardown.

No production package outside `internal/vowifihost` mutates attempt tokens
directly.

### MessagingCapability

- Production SMS calls `RuntimeInstance.SendSMS`.
- Production USSD calls `SendUSSD`, `ContinueUSSD`, or `CancelUSSD` on
  the same Instance.
- Not-ready and stopped instances dispatch zero Adapter calls.
- Each accepted operation borrows the current messaging Adapter; Stop rejects
  new borrows and joins in-flight work before close.
- The raw `Instance.Service()` production Interface no longer exists.

Delivery state remains deliberately layered:

~~~text
SMS-SUBMIT
-> submit_report_success       (SMSC accepted)
-> SMS-STATUS-REPORT TP-ST=0   (terminal delivered)
~~~

Malformed reports update neither persistence nor RP acknowledgement state.

### CarrierBehavior

- `ResolveCarrierBehavior` normalizes the PLMN once per RuntimeAttempt.
- Downstream policy consumes typed fields; `RegisterTemplate.ID` is
  diagnostic metadata rather than a second decision source.
- The protocol Adapter still maps typed messaging presentation to the
  corresponding REGISTER/MESSAGE profile. That mapping is implementation, not
  another carrier owner.

The golden mappings are:

| PLMN | Behavior |
| --- | --- |
| 310/240 | `3gpp-default` |
| 234/15 | `vodafone_uk_23415` |
| 234/015 | `vodafone_uk_23415` |

### SWUSession

`swuSessionLease` owns the complete candidate lifecycle. Timeout, cancel, and
Stop enter the same cleanup path. Cleanup rejects new MOBIKE operations, waits
for an already admitted MOBIKE operation, cancels Connect, calls protocol
Shutdown when initialized, and joins the session task. Snapshots and IP slices
are deep copied before publication.

`third_party/swu-go/pkg/swu.Session` remains the protocol Adapter that owns
IKE, Child SA, rekey, and ESP implementation. It is not a second runtime
lifecycle owner.

### ProtectedChannel

`ProtectedChannelOwner` owns both UDP and TCP Adapters for one IMS service.
REGISTER receives a generation-bound opaque lease and the service adopts it
into a handle. No policy/transform/flow pointer bundle crosses that Seam.

The owner enforces:

- exactly-once install, adoption, and close;
- stale-generation rejection and immediate cleanup;
- replacement without mixing SA generations;
- unique live client ports;
- in-flight operation join before replacement or Stop;
- unchanged UDP and TCP wire behavior.

### Messaging status publication

SMSC acceptance and terminal delivery are separate states throughout
voiceclient, persistence, API, and UI. A successful submit report cannot
upgrade a message to delivered. STATUS-REPORT correlation is fail closed when
ambiguous.

## BroadcastState audit

`Manager.BroadcastState` is not a runtime-state publication Interface.
`Store.Broadcast` accepts only a device ID and synchronously coalesces an
empty subscriber notification; it cannot inject a state, epoch, instance, or
generation.

The nine production calls are retained because they announce device facts:

- cache pre-warm completion;
- AT/QMI runtime or identity refresh;
- SIM identity transition begin;
- post-switch runtime/identity refresh;
- switch failure/finalization fact changes.

Subscribers reread current Worker facts and the authoritative host snapshot.
All RuntimeAttempt state still passes through `RecordStartupState` or
`publishRuntimeState`. Therefore no current call bypasses publication
authority. The broad method name is a navigation debt, not evidence of a
correctness defect; renaming it without a failing behavior contract would add
churn rather than Depth.

## CI topology

The repository has three first-class Go Modules:

| Module | Ordinary | Race | Vet |
| --- | --- | --- | --- |
| root | `go test ./... -count=1` | selected concurrency packages | `go vet ./...` |
| `vowifi-go` | `go test ./... -count=1` | IPsec, imscore, runtimehost, SIM auth, voiceclient | `go vet ./...` |
| `third_party/swu-go` | `go test ./... -count=1` | crypto, IKEv2, IPsec, SWu state machine | `go vet ./...` |

Both pull-request CI and release validation run the local swu-go gates directly,
and all three `go.sum` files participate in the Go cache key.

## Legacy deletion ledger

### Removed

| Interface or path | Evidence |
| --- | --- |
| `internal/vowifi/imscore/adapter.go` / `NewVoiceClientAdapter` | Go `internal` package; zero production, test, and build references; entire Adapter was self-contained |
| raw production `RuntimeInstance.Service()` | SMS and USSD callers use MessagingCapability |
| split SWu result/cancel/MOBIKE fields | one `swuSessionLease` owns the lifecycle |
| protected holder, pointer-transfer helpers, and `transportRuntime` | `ProtectedChannelOwner` and opaque lease/handle replaced them |
| downstream carrier template-ID decision branches | typed CarrierBehavior contracts drive active decisions |

### Retained with a deletion gate

| Interface or path | Why it remains | Gate before deletion |
| --- | --- | --- |
| `internal/vowifi/imscore.Dial` | same-package `setup_realm_test.go` is a real build consumer | move its validation contract to the active StartSession Interface, then prove no calls |
| `runtimehost/voiceclient.Dial` | exported Module Interface; repository census cannot exclude external consumers | deprecation plus external Interface census and active-path parity |
| `voiceclient/swu_packetconn.go` | `swuPacketConn` is owned by public `voiceclient.Dial`; packet helpers also have test consumers | retire Dial and preserve helper coverage at the active packet Adapter |
| `protectedDialPathFor` | test consumer remains | replace the isolated classification test with active UDP/TCP dispatch coverage |
| legacy carrier runtime input Adapter | still accepts optional runtime overrides | remove only after configuration compatibility policy is separately approved |

Deleting tests or exported Interfaces to manufacture a zero-call result fails
the deletion test and is prohibited.

## Remaining technical debt

1. The public legacy `voiceclient.Dial` REGISTER FSM still increases
   navigation cost. Its external Interface census is unavailable offline.
2. TP-MR/RP-MR allocation is process-scoped rather than per-SIM persistent.
   Correlation also uses recipient and a bounded time window and fails closed
   on ambiguity.
3. The project has not yet captured a real carrier STATUS-REPORT proving
   terminal delivery; local synthetic evidence proves parsing and lifecycle
   behavior only.
4. The installed local binary can carry a version label older than the source
   commit used to build it. Build provenance and deployment are an operational
   Goal, not an architecture refactor.
5. `BroadcastState` is accurately safe but broadly named. Rename only in a
   separate behavior-preserving cleanup with subscriber contracts.

## Review checklist

- Exactly one current RuntimeAttempt may claim one RuntimeInstance.
- Stale attempts and stale instances publish nothing.
- Reconcile and APDU-busy schedules are deduplicated, cancelable, and joined.
- CarrierBehavior is resolved once and golden PLMN mappings remain unchanged.
- Timeout/cancel/Stop leave no detached SWu owner.
- Only one current ProtectedChannel generation owns policy, transforms, flows,
  replay state, and ports.
- Messaging calls cannot borrow a stopped or unready Adapter.
- Explicit SIP statuses never trigger transport/candidate fallback.
- SMSC acceptance is never presented as terminal delivery.
- Root, vowifi-go, and local swu-go gates all run directly.

## Next action

Stop after offline verification and independent review. Commit, push,
deployment, service startup, device use, and real SMS testing each require
separate authorization.
