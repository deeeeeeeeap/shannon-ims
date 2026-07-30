# Shannon IMS runtime context

This context names the runtime ownership concepts that keep one modem, one SWu
tunnel, one IMS registration, and one messaging path coherent. The terms are
the accepted vocabulary for the owner-first architecture. They describe domain
Modules and do not require same-named Go types, packages, Interfaces, or
wrappers.

## Language

### Runtime ownership

**RuntimeAttempt**:
One admitted intent to enable, replace, recover, switch, or stop a device's VoWiFi runtime.
_Avoid_: lifecycle generation, startup epoch, start job

**RuntimeInstance**:
The admitted in-process runtime that advances through SIM, access, tunnel, IMS, and messaging readiness.
_Avoid_: active session, VoWiFi service

**SWUSession**:
One candidate-scoped ePDG connection lifecycle containing IKE, Child SA, dataplane, cancellation, and joined cleanup.
_Avoid_: tunnel goroutine, SWU result bundle

**ProtectedChannel**:
One generation of negotiated 3GPP IPsec policy, transforms, protected flows, and their joined teardown.
_Avoid_: secure connection, ESP wrapper

### IMS behavior

**CarrierBehavior**:
The normalized home-PLMN decision that fixes REGISTER presentation, retry rules, transport policy, and post-register messaging presentation.
_Avoid_: carrier preset, REGISTER template ID

**MessagingCapability**:
The current runtime's ready, borrowable, and stop-safe ability to send or receive IMS messaging.
_Avoid_: raw messaging service, active VoWiFi

### State and recovery

**StatePublication**:
The authoritative current-attempt snapshot plus its coalesced change notification.
_Avoid_: broadcast helper, cached startup state

**Reconcile**:
The deduplicated and backed-off process that moves an eligible device toward its desired VoWiFi state.
_Avoid_: retry timer, auto-start goroutine

## Relationships

- A device has at most one current **RuntimeAttempt** and at most one claimed **RuntimeInstance**.
- A **RuntimeAttempt** may claim one **RuntimeInstance** only while the attempt is current.
- A **RuntimeInstance** owns at most one **SWUSession**, one current **ProtectedChannel**, and one **MessagingCapability**.
- A **CarrierBehavior** is resolved once per **RuntimeAttempt** and is consumed without reinterpreting its identifier downstream.
- **StatePublication** accepts state only from the current **RuntimeAttempt** or its claimed **RuntimeInstance**.
- **Reconcile** may request a new **RuntimeAttempt**, but device/card eligibility remains supplied by the device Adapter.
- Device Worker generation, **RuntimeAttempt** identity, RuntimeInstance-private generation, and ProtectedChannel SA generation are distinct domains.

## Current implementation map

- **RuntimeAttempt** is implemented by `internal/vowifihost.Manager`, `Store`,
  and `LifecycleController`; its concrete tokens remain lifecycle generation and
  startup epoch rather than a new `RuntimeAttempt` struct.
- **StatePublication** and **Reconcile** are implemented by the same host
  `Store`/`Manager`. Runtime publication checks the current epoch and claimed
  instance. `BroadcastState` carries no state and only tells subscribers to
  reread device facts.
- **CarrierBehavior** is the concrete typed policy in
  `vowifi-go/internal/vowifi/policy` and is resolved once when a runtime starts.
- **SWUSession** is the unexported `swuSessionLease` in
  `vowifi-go/runtimehost`; the local swu-go `Session` remains its protocol
  Adapter.
- **ProtectedChannel** is implemented by `ProtectedChannelOwner`, its
  generation-bound lease/handle, and private UDP/TCP Implementation in
  `vowifi-go/internal/vowifi/ipsec3gpp`.
- **MessagingCapability** is the stop-safe SMS/USSD Interface on
  `vowifi-go/runtimehost.Instance`; production callers do not receive the raw
  messaging Adapter.

## Example dialogue

> **Developer:** "The RuntimeInstance is active. Can I send SMS now?"
> **Domain expert:** "Only if its MessagingCapability is ready; admission is not the same as SMS readiness."
>
> **Developer:** "Can Reconcile reuse the previous generation after a worker replacement?"
> **Domain expert:** "No. It requests a new RuntimeAttempt; Worker, attempt, instance, and SA generations are never interchangeable."

## Flagged ambiguities

- "generation" previously referred to Worker, lifecycle, startup, Instance, and SA freshness. These remain separate token domains; the target architecture does not merge them into one counter.
- "active" means a RuntimeInstance has been admitted, not that Tunnel, IMS, or SMS readiness has completed.
- "carrier preset" and REGISTER behavior were used interchangeably. Runtime carrier overrides remain input metadata; **CarrierBehavior** uniquely owns wire-policy decisions.
- "service" referred both to a raw messaging implementation and to a safe capability. Production callers must use **MessagingCapability**, never a raw messaging implementation.
