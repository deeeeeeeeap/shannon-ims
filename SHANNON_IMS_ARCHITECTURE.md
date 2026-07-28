# Shannon IMS owner migration blueprint

## Status and scope

This is a proposed, documentation-only migration blueprint. It records current
call paths and assigns one owner to each target Module; it does not authorize or
perform production refactoring.

The reviewed baseline is:

- branch main, HEAD 3ca051a;
- the pre-document working inventory contains 39 modified and 163 untracked
  entries and matches the previously recorded content fingerprint;
- Compatibility contracts are frozen for PLMN 310/240 and 234/15
  device baselines;
- the offline carrier contract also covers normalized 234/015.

No real configuration, database, log, identity, packet, address, or credential
was used for this review.

## Architecture rules

1. Every mutable lifecycle or protocol resource has one owner.
2. A target Module is accepted only when the deletion test proves Depth: deleting
   it would force its invariants back into multiple callers.
3. Migration must move responsibility and then delete the old path. A permanent
   forwarding wrapper is not a completed migration.
4. Callers and tests cross the same Seam.
5. One Adapter is a hypothetical Seam; retain a Seam only when at least two real
   Adapters vary or when it enforces a lifecycle invariant that callers cannot
   safely reproduce.
6. Worker, RuntimeAttempt, RuntimeInstance, SWU, and SA generation domains remain
   distinct. They are related by ownership, not by a shared counter.

The owner-first decision is recorded in
[ADR-0001](./ADR-0001-owner-first-runtime-and-protocol-migration.md).

## Frozen compatibility contract

Every migration stage must preserve:

- 310/240 resolves to 3gpp-default;
- 234/15 and 234/015 resolve to vodafone_uk_23415;
- both carriers retain the current initial and authenticated REGISTER behavior;
- explicit SIP status responses remain fail-closed for transport and registrar
  fallback;
- current SWu candidate ordering, bounded budgets, group 14 direct success,
  bounded group 15 feedback handling, and negotiated-group rekey remain;
- current 3GPP IPsec transforms, UDP protected signaling, size-driven protected
  TCP selection, listener-before-write ordering, port roles, replay behavior,
  and SA replacement remain;
- IMSReady and SMSReady remain distinct;
- the current successful protected UDP/TCP messaging and SMS behavior remains;
- runtimehost.Start continues to return after AccessReady until a separate
  reviewed decision explicitly changes that contract.

## Current call graph

~~~mermaid
flowchart TD
    Device["internal/device Pool"] --> Lifecycle["LifecycleController generation"]
    Lifecycle --> Store["RuntimeStore startup epoch"]
    Store --> Start["runtimehost.Start + ShouldRun"]
    Start --> Instance["RuntimeInstance private generation"]
    Instance --> Candidates["SWu candidate loop owns cancel"]
    Candidates --> External["swu-go Session owns Connect and done"]
    Instance --> IMS["imscore REGISTER orchestration"]
    IMS --> IPsec["ipsec3gpp transforms and flows"]
    IMS --> Messaging["voiceclient secure messaging"]

    Device -. "raw Service bypass" .-> Messaging
    Device -. "eligibility + result callback" .-> Reconcile["vowifihost reconcile/backoff"]
    Reconcile -. "result classification" .-> Device
    Instance -. "observer" .-> Store
    Store -. "manual broadcast" .-> Hub["StateHub"]
~~~

## Current architecture problems

### 1. Runtime freshness has four partial owners

LifecycleController owns command generation, RuntimeStore owns startup epoch,
StartRuntime constructs a ShouldRun closure, and runtimehost.Instance owns
another generation for its asynchronous pipeline. Callers must understand
several tokens to decide whether a result is current.

### 2. Production messaging bypasses its tested safety Seam

Pool.SendVoWiFiSMSWithOptions obtains Instance.Service() and calls the raw
messaging implementation. USSD does the same. This bypasses the existing
Instance.SendSMS checks for SMSReady, stopped state, in-flight borrowing, and
Stop joining. The tested Interface and production Interface are different.

### 3. State mutation, authority, and publication are separate

Store selects startup versus live state, StateHub only signals, Manager methods
sometimes mutate without publishing, and the runtime observer decides whether to
broadcast or cache. Wall-clock UpdatedAt also participates in stale suppression
despite attempt identity being the stronger authority.

### 4. Reconcile ownership crosses packages twice

internal/device determines card/worker eligibility, internal/vowifihost owns
in-flight and backoff state, and an OnResult callback returns to device code to
classify and write the result back into the host store. APDU-busy recovery adds
separate timers rather than entering the same owner.

### 5. Carrier behavior is interpreted repeatedly

policy.IMSRegisterTemplate, runtimehost/carrier, voiceclient.RegisterProfile,
and template-ID branches in several imscore files all express parts of carrier
behavior. Post-register messaging additionally hard-codes one profile in both
protected transports. The current bytes work for both validated carriers, so
this is an ownership problem, not permission to "correct" the profile.

### 6. Protected channel ownership is transferred through pointer bundles

UDP registration returns a secure connection; TCP registration transfers a
runtime and a client flow, then transfers the runtime again from registerResult
into Service. Policy, transform, ports, generation, flows, replay state, and
close/join are therefore checked in several files.

### 7. SWu lifecycle ownership is split

The candidate loop creates cancellation, startSWuSession creates the concrete
session and Connect goroutine, host.Instance stores cancel and MOBIKE separately,
and the concrete swu-go Session owns its own cancel, done channel, and cleanup.
The test Interface omits Shutdown and WaitDone, even though the concrete Adapter
implements both.

### 8. Legacy paths remain navigable

VoiceClientAdapter and voiceclient.Dial have no repository production caller.
swuPacketConn is used only by the legacy Dial path. A prototype protected-dial
chain and a legacy transport runtime also remain beside the successful path.
These shallow Modules increase navigation cost and can be mistaken for owners.

### 9. Reproducibility does not yet match the runtime topology

The current build uses a local third_party/swu-go Module containing 97 files,
but existing workflows test the root and vowifi-go Modules only. This Goal does
not change CI; clean-clone provenance and all-module gates must be closed before
production migration begins.

## Target owner flow

~~~mermaid
flowchart TD
    Intent["device intent"] --> Attempt["RuntimeAttempt owner"]
    Eligibility["device eligibility Adapter"] --> State["StatePublication/Reconcile owner"]
    State --> Attempt
    Attempt --> Instance["RuntimeInstance"]
    Instance --> SWU["SWUSession lease"]
    Attempt --> Carrier["CarrierBehavior"]
    Carrier --> IMS["imscore REGISTER orchestration"]
    SWU --> IMS
    IMS --> Protected["ProtectedChannel owner"]
    Protected --> Capability["MessagingCapability"]
    Instance --> State
    Capability --> State
~~~

## Target Module and owner matrix

| Module | Unique owner | Sole responsibility | What stays outside |
| --- | --- | --- | --- |
| RuntimeAttempt | internal/vowifihost | Per-device admission, ordering, preemption, attempt identity, cancel, claim, replacement, and stop | Device Worker generation; Instance-private generation; SA generation |
| MessagingCapability | vowifi-go/runtimehost.Instance | Messaging readiness, safe borrow/release, dispatch, Stop exclusion, in-flight join, and messaging implementation lifetime | SMS TPDU/RP-DATA encoding; carrier policy; protected transport internals |
| CarrierBehavior | vowifi-go/internal/vowifi/policy | PLMN normalization and all carrier-specific REGISTER, transport, retry, and messaging-presentation decisions | SIP object manipulation; device/ePDG override loading; runtime lifecycle |
| ProtectedChannel | vowifi-go/internal/vowifi/ipsec3gpp | One SA generation's policy, transforms, UDP/TCP Adapter, port roles, flows, replay state, replacement, and joined teardown | REGISTER FSM; carrier selection; SWu candidate lifecycle |
| SWUSession | vowifi-go/runtimehost | One candidate-scoped Connect/ready/snapshot/cancel/join/dataplane/MOBIKE lease | IKE/Child-SA protocol implementation; carrier REGISTER behavior |
| StatePublication/Reconcile | internal/vowifihost | Authoritative attempt-aware state transition, snapshot, notification, desired-state dedupe, result, and backoff | Worker/card eligibility and device policy facts |

## Module migration boundaries

### RuntimeAttempt

**Current path**

Pool.EnableVoWiFi -> Manager.Enable -> LifecycleController.Submit ->
enableRuntime -> BeginStart -> StartRuntime -> runtimehost.Start.

**Move into the owner**

- admission and preemption from controller.go;
- epoch/claim/currentness from start.go and the attempt portion of store.go;
- stale result disposal from runtime_start.go;
- Enable/Disable/Restart/Recover/Switch ordering from lifecycle_run.go;
- cancel, stop, replacement, and delete ordering from teardown paths.

runtimehost.Instance keeps only private, single-instance pipeline freshness.
internal/device supplies facts and side-effect Adapters but does not mint or
compare host attempt tokens.

**Delete when migration is complete**

- externally visible NextLifecycleGeneration, CurrentLifecycleGeneration,
  CurrentEpoch, ShouldRun, and ClaimStarted;
- caller-supplied recovery generation and fallback ensureLifecycleGeneration;
- device-side direct runtime invalidation and recovery start bypasses;
- external mutation through Manager.RuntimeStore().

**Depth proof**

Without RuntimeAttempt, admission, cancel, stale rejection, claim, replacement,
and stop ordering reappear in Enable, Restart, Switch, Recover, and rebuild
callers. The Module therefore provides real Leverage and Locality.

### MessagingCapability

**Current path**

The runtime installs messaging.Service and publishes SMSReady, but production
SMS and USSD retrieve the raw implementation through Instance.Service().

**Move into the owner**

- SMS/USSD capability readiness and dispatch;
- stopped/current checks;
- borrow/release counting and Stop joining;
- messaging implementation install, replacement, and close.

internal/device retains SMSC lookup and TPDU/RP-DATA construction. Protected UDP
and TCP messaging remain concrete Adapters behind the capability Seam.

**Delete when migration is complete**

- all production inst.Service() calls;
- the production-visible raw Instance.Service() accessor;
- direct svc.SendSMS, svc.SendUSSD, svc.ContinueUSSD, and svc.CancelUSSD calls;
- the assumption that an admitted RuntimeInstance is equivalent to a ready
  MessagingCapability.

Do not change the current smsModeVoWiFi handoff timing until a separate
characterization proves whether early cellular polling suppression is required.
USSD readiness must be characterized separately from SMSReady.

**Depth proof**

Without MessagingCapability, every messaging caller must reproduce readiness,
currentness, borrow, stopped, close, and join rules. The existing production
bypass demonstrates the cost of the shallow Interface.

### CarrierBehavior

**Current path**

Device code resolves an optional handset profile, runtimehost resolves an IMS
template, and imscore reinterprets the template ID for candidate order,
protected transport, serializer selection, retry behavior, and messaging
presentation.

**Move into the owner**

- PLMN normalization and behavior resolution in policy/defaults.go;
- the resolved behavior model currently split across policy/types.go and
  voiceclient.RegisterProfile;
- unprotected candidate policy from register_transport.go;
- carrier opt-in/opt-out from register_protected_transport.go;
- Vodafone serializer/header-order selection data from REGISTER files;
- post-register messaging presentation currently selected in service_lifecycle.go.

SIP types and byte serialization stay as protocol Adapters in imscore.
runtimehost/carrier remains an input Adapter for optional runtime overrides, not
an owner of wire policy. Deepen the existing policy Module before creating a new
package; a new package is justified only when it replaces at least three
current decision sites.

**Delete when migration is complete**

- the pass-through runtimehost.resolveIMSRegisterTemplate;
- downstream string comparisons against 3gpp-default and vodafone_uk_23415;
- the two hard-coded SimAdminGBEERegisterProfile selections in active messaging
  attachment;
- legacy-only RegisterProfile fields after the legacy REGISTER FSM is retired.

**Depth proof**

Without CarrierBehavior, mapping, serializer choice, transport, protected
opt-in, retry rules, and messaging presentation reappear in runtimehost,
imscore, and voiceclient. One resolved decision gives every caller Leverage and
concentrates carrier wire changes in one Locality.

### ProtectedChannel

**Current path**

After authentication, imscore creates ipsec3gpp.Policy and Transport. UDP returns
a secure connection. TCP creates a runtime, listener, client flow, and then
performs two ownership transfers before messaging attachment.

**Move into the owner**

- ipsec3gpp.Transport, SecureChannelConn, ProtectedTCPStack, and
  ProtectedLinkEndpoint as private Implementation;
- runtime ownership, listener, flow, and close/join from
  protected_tcp_runtime.go;
- adopt/replace/retire from protected_runtime_holder.go;
- port generation and release-once rules;
- generation/policy/exclusivity checks from protected_register_sequence.go.

imscore retains REGISTER orchestration and receives one opaque current channel
handle instead of policy/transform/connection pointer bundles.

**Delete when migration is complete**

- the registerResult union of secureConn, protectedTCP, protectedClientConn,
  transport, and ipsecPolicy;
- takeProtectedTCPOwnership, adoptProtectedTCPResult, and equivalent
  pointer-transfer helpers;
- the imscore protectedRuntimeHolder after replacement moves;
- no-caller protected-dial prototype symbols;
- the legacy transportRuntime after a reachability oracle proves no non-packet
  producer remains.

**Depth proof**

Without ProtectedChannel, policy pairing, two transport Adapters, port roles,
generation, replay, ownership transfer, and joined teardown reappear in
REGISTER, Service lifecycle, and messaging attachment. This is the highest-
Depth and highest-risk Module.

### SWUSession

**Current path**

The candidate loop owns context cancellation, startSWuSession owns the concrete
session and Connect goroutine, a four-field result escapes, host stores cancel
and MOBIKE separately, and the concrete session owns its own done and cleanup
lifecycle.

**Move into the owner**

- candidate-scoped config composition, Connect task, ready gate, and snapshot;
- cancel, Shutdown, WaitDone, and bounded join;
- dataplane and MOBIKE lifetime;
- one lease returned to the candidate loop and held by RuntimeInstance;
- third_party/swu-go/pkg/swu.Session retained as the protocol Adapter for IKE,
  EAP, Child SA, rekey, and ESP.

**Delete when migration is complete**

- the four-field swuStartResult bundle;
- StartRequest.swuSessionCancel;
- Instance.swuCancel, Instance.swuMobike, and their install/get helpers;
- the five-return-value startSWuSession shape;
- duplicate swuInnerDataplane and voiceclient.PacketDataplane ownership;
- the lifecycle-incomplete swuSession test Interface.

**Depth proof**

Without the lease, cancel/join, readiness, snapshot, dataplane, MOBIKE, and
candidate cleanup reappear in candidate, session-start, host, and IMS network
callers. A lifecycle-owning Module hides real complexity.

### StatePublication/Reconcile

**Current path**

Store selects startup/live state, StateHub signals, callers manually combine
mutation and broadcast, and device/host exchange reconcile callbacks and result
mutations.

**Move into the owner**

- attempt-aware transition, startup/live authority, snapshot, and coalesced
  notification from store.go, state_pubsub.go, and runtime observers;
- desired-state dedupe, in-flight ownership, backoff, result classification, and
  freshness from reconcile.go and recover_state.go;
- device code reduced to a worker/card/switch/rebuild eligibility Adapter and a
  desired-state nudge;
- APDU-busy recovery represented as a reconcile reason instead of independent
  timers.

**Delete when migration is complete**

- public/manual BroadcastState;
- separate ClearStartupState and ClearStartupStateAndBroadcast paths;
- device record/clear/broadcastVoWiFiState* wrappers;
- DesiredRecoverRequest.OnResult;
- caller-facing BeginDesiredRecover, MarkDesiredRecoverFailed, and
  ClearDesiredRecoverState;
- device result/clear wrappers and APDU-busy retry timers;
- wall-clock-only stale authority; UpdatedAt remains metadata.

**Depth proof**

Without this Module, atomic state selection, stale suppression, notification,
dedupe, backoff, and result classification reappear in runtime observers,
device loops, error handling, and subscribers. Absorbing the shallow StateHub
and callback loop creates real Locality.

## Legacy deletion ledger

### Must delete after the named gate

| Path or symbol | Gate before deletion |
| --- | --- |
| vowifi-go/internal/vowifi/imscore/adapter.go | Confirm zero internal and external consumers of NewVoiceClientAdapter |
| voiceclient.Dial and the second REGISTER FSM | External Interface census plus active imscore REGISTER parity |
| voiceclient/swu_packetconn.go | Legacy Dial retired; active netstack UDP/raw path remains covered |
| no-caller protected-dial prototype symbols | Activation rules moved behind ProtectedChannel |
| transport_runtime.go and Service.transportRuntime | Reachability oracle proves no non-packet secureConn producer |
| imscore protected holder/transfer helpers | ProtectedChannel owns adopt/replace/retire |
| SWU result/cancel/MOBIKE bundles | SWUSession lease owns complete lifecycle |
| template-ID branches and hard-coded messaging profile | CarrierBehavior contract proves identical decisions and bytes |

### Must not delete as part of cleanup

- voiceclient/secure_attach.go: active UDP/TCP messaging Adapters;
- Contact and MESSAGE presentation behavior still used from
  voiceclient/register_profile.go until migrated;
- voiceclient/swu_netstack.go and swu_raw_conn.go: active userspace dataplane;
- ipsec3gpp.Transport, SecureChannelConn, ProtectedTCPStack, and
  ProtectedLinkEndpoint: target ProtectedChannel Implementation;
- third_party/swu-go/pkg/swu.Session: target SWUSession protocol Adapter;
- exported third-party manager symbols until an external Interface census is
  complete.

## Three-stage migration

Each stage is a sequence of narrow Goals, not one large change.

### Stage 1: close leaf bypasses and centralize pure decisions

1. Route production SMS through the existing stop-safe Instance path; add a
   production-call-chain contract for SMSReady=false, stale instance, in-flight
   Stop, and exactly-one successful dispatch.
2. Characterize USSD readiness separately before removing its raw Service path.
3. Deepen CarrierBehavior and migrate one pure decision site at a time:
   normalization, unprotected candidates, protected opt-in/opt-out, serializer
   selection, then messaging presentation.
4. Do not alter smsModeVoWiFi timing or current messaging profile bytes in this
   stage.

Stage gate:

- dual-carrier contract and Vodafone raw/header-order tests;
- generic protected TCP and Vodafone protected UDP tests;
- explicit-status fail-closed tests;
- MessagingCapability readiness/Stop/race tests;
- no new permanent wrapper and no legacy deletion yet.

### Stage 2: concentrate runtime and state lifecycle

1. Introduce RuntimeAttempt internally around the existing generation and epoch;
   preserve behavior before hiding old tokens.
2. Make StatePublication transition plus notification atomic and bind accepted
   updates to RuntimeAttempt identity.
3. Move Reconcile dedupe, result, and backoff fully into the owner; reduce device
   code to eligibility facts and nudges.
4. Last in this stage, replace split SWu cancel/result/MOBIKE ownership with one
   SWUSession lease held by RuntimeInstance.

Stage gate:

- Enable/Restart/Switch/Recover ordering, stale claim, old-instance disposal,
  and per-device serialization;
- startup/live state authority, exactly-one coalesced notification, reconcile
  success/failure/policy-blocked backoff, and multi-device concurrency;
- SWu candidate order/budget, timeout cancel/join, group 14 direct success,
  bounded group 15 feedback, negotiated-group rekey, and dataplane lifecycle;
- original token paths deleted only after equivalent owner contracts pass.

### Stage 3: move protected ownership and retire legacy paths

1. Wrap current UDP and TCP paths behind one ProtectedChannel owner without
   changing selection or wire construction.
2. Move policy/transform pairing, port generation, listener, flows, holder,
   replacement, replay, and close/join one invariant at a time.
3. Replace raw registerResult ownership fields with one opaque channel handle.
4. Run reachability and external Interface censuses, then execute the legacy
   deletion ledger.

Stage gate:

- independent ESP, fragmentation, winning-candidate, TCP framing, MSS, listener
  ordering, SA replacement, and ownership oracles;
- one carrier, one inbound pump, and one replay window per current SA;
- protected failures never retry another transport or registrar;
- complete root, vowifi-go, and local swu-go offline gates;
- real-device checks only after separate user authorization.

## Independent review checklist

- Does every mutable resource have exactly one owner?
- Does each target Module pass the deletion test?
- Is every old path paired with a measurable deletion gate?
- Are carrier preset input and CarrierBehavior wire policy still distinct?
- Are token domains related without being merged?
- Can both protected transport Adapters remain byte-compatible?
- Can SMS/USSD callers operate without receiving a raw messaging implementation?
- Can a failed or stale attempt publish state, own a SWUSession, or borrow a
  MessagingCapability? The answer must be no.
- Can a clean clone reproduce and test all local Modules before Stage 1 begins?

## Recommended next Goal

After independent review, begin only Stage 1's MessagingCapability slice:
route Pool.SendVoWiFiSMSWithOptions through the existing RuntimeInstance.SendSMS
Seam, with production-call-chain contracts proving zero Adapter calls before
SMSReady, stale-instance rejection, Stop joining, and exactly one unchanged
successful dispatch.

Do not combine that slice with CarrierBehavior, RuntimeAttempt, SWUSession,
ProtectedChannel, smsMode timing, or legacy deletion.
