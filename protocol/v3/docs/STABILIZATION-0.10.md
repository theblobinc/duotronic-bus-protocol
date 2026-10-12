# Draft 0.10 Pre-RC Stabilization Review

Draft 0.10 follows an adversarial review of Draft 0.9. The review contained both genuine defects and assumptions that were not true of the repository. The release fixes the real mechanics and explicitly documents boundaries that belong outside the protocol runtime.

| Review area | Draft 0.10 disposition |
| --- | --- |
| stale generated Python/Rust registries | CI runs the generator in `--check` mode, regenerates all derived artifacts, and fails on a dirty tree |
| quarantine reboot/readmission loophole | automatic cooldown readmission removed; fresh challenge + monotonic generation + session commitment + Witness reference + externally verified authenticator + probation required |
| mass quarantine under shared line noise | correlated faults degrade the shared path; hard security faults still quarantine peers and never lower quorum |
| formal lock as proof substitute | lock remains a drift detector only; release CI also runs strict TLA+ and Lean gates |
| profile/formal vs generated-code gap | generated-artifact freshness, registry coherence, semantic profile verification, resolved manifests and differential vectors are separate required gates |
| Python/Rust runtime cost asymmetry | each runtime uses its own conservative admission model; differential testing checks that both implementations agree on the Rust model rather than pretending heap costs are identical |
| asymmetric timeout behavior | protocol work is bounded by deterministic work units; each runtime also enforces a local monotonic deadline and must refuse workloads it cannot complete within the profile |
| long-offline merge convergence | production reconciliation supports storage-backed immutable snapshots and resumable byte segments; page work is bounded, total historical horizon is not |
| FEC zero/sub-minimum resources | explicit workspace/work-unit admission fails closed before recovery begins |
| multicast recovery amplification | fanout, fragments, recipient capability, recovery bytes/work and parallel FEC groups are bounded before transmission |
| FFI unsafe-pointer concern | current repo has no Python/Rust FFI and Rust forbids unsafe code; any future FFI requires a new audited safety boundary |
| hardware "poison frame"/disconnect assumptions | not claimed; physical fail-silent isolation belongs to an out-of-process supervisor/firmware/hardware watchdog |
| unbounded at-most-once state | idempotency ledger has a fixed capacity and fails closed instead of evicting command keys |
| unbounded in-memory history sorting | in-memory reconciliation has a hard item ceiling; large deployments use a storage-backed `MergeSnapshot` contract |

## Security principle

Draft 0.10 continues to enforce:

```text
wire validity
  != authenticated transport
  != admitted evidence
  != delegated authority
  != policy authorization
  != execution
  != verified outcome
```

The same rule applies to human operators, Xavi-UTM services, WG-RNNs and autonomous DBP principals.
