# SelectorCache Write-Lock Contention E2E Test

Attempts to reproduce the write-lock contention bug that causes unbounded
memory growth in cilium-agent's `AccumulateMapChanges` queue.

**Status: Bug not yet reproduced in test environments.** The production issue
(70 GiB on a single agent) has only been observed in large clusters under
specific conditions. See "Findings" below.

## Requirements

- `kubectl`, `go`, `curl`
- Kind mode additionally: `kind`, `helm`, `docker`

## Usage

### Kind mode (local testing)

```bash
./run.sh [version]              # default: 1.14.19
./run.sh 1.16.0                 # test a different version
./run.sh --cleanup [version]    # delete the Kind cluster

# Quick smoke test
NUM_NAMESPACES=10 CHURN_DURATION=30 BURST_SIZE=5 ./run.sh 1.14.19
```

### External mode (real cluster)

```bash
# Point kubectl at your cluster
kubectx my-cluster

# Run against existing Cilium deployment
./run.sh --external

# With production-like scale
NUM_NAMESPACES=500 CHURN_DURATION=600 BURST_SIZE=100 ./run.sh --external
```

External mode:
- Assumes Cilium is already deployed
- Detects Cilium version and pprof availability
- Creates test namespaces/pods/CNPs, runs churn, measures memory
- Skips CCNP and server deployment (uses existing cluster policies)

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NUM_NAMESPACES` | 50 | Namespaces to create |
| `CNPS_PER_NS` | 2 | CNPs per namespace |
| `PODS_PER_LABEL` | 2 | Pods per label per namespace (total = ns x pods_per_label x 2) |
| `NUM_CIDR_ENTRIES` | 20 | `fromCIDR` entries per CNP |
| `BURST_SIZE` | 50 | Rapid updates per burst to the same CNP |
| `BURST_INTERVAL` | 2 | Seconds between bursts |
| `CHURN_DURATION` | 300 | Total churn duration in seconds |
| `SAMPLE_INTERVAL` | 15 | Seconds between cgroup memory samples |
| `MEMORY_GROWTH_THRESHOLD_MI` | 50 | Per-agent heap growth (MiB) to flag as FAIL |
| `DIVERGENCE_RATIO` | 2.0 | Worst/best agent growth ratio to flag as FAIL |
| `PPROF_PORT` | 6060 | pprof port on cilium-agent |

## What it does

1. Creates namespaces with pods (endpoints) and CiliumNetworkPolicies with `fromCIDR` rules
2. Repeatedly updates the **same CNP** with reordered `fromCIDR` entries (burst of 50 updates every 2s)
3. Samples cgroup memory from each cilium-agent every 15 seconds
4. After churn, measures Go heap via pprof (forces GC for accuracy)
5. Reports per-agent heap growth, detects divergence between agents
6. Captures heap profile from the worst agent for offline analysis

## Findings

### Kind cluster testing

| Scale | Heap Growth | Verdict |
|-------|------------|---------|
| 50 ns, 200 pods, 100 CNPs | +6 Mi | PASS — no leak visible |
| 50 ns, 200 pods, single CNP burst-updated | +6 Mi | PASS — no leak visible |
| 300 ns, 1200 pods, 600 CNPs | Cluster overloaded, API server unresponsive | N/A |

**Kind cannot reproduce the tipping point.** The API server throughput
limits CNP update rate to ~12/s. In production, the operator updates
~476 CNPs/s. The lock contention requires sustained high event rates
that Kind cannot deliver.

### Production observations (for reference)

On a production cluster (Cilium 1.14.19, 800+ endpoints, 2379 CNPs):
- 2 of ~200 nodes had cilium-agent at 70 GiB and 22 GiB
- All other nodes stable at ~5 GiB
- Heap profile: 97% in `AccumulateMapChanges`, 132M `MapStateEntry` objects
- All nodes received identical identity event rates (~2670 policy changes/s)
- An operator continuously updated CNPs by reordering `fromCIDR` entries

### What is confirmed

- **The lock pattern exists in the code** (verified against v1.14.19 source):
  - `ConsumeMapChanges` (`resolve.go:235`): `SelectorCache.mutex.Lock()` (WRITE)
  - `UpdateIdentities` (`selectorcache.go:1027`): `SelectorCache.mutex.Lock()` (WRITE)
  - `AccumulateMapChanges` (`mapstate.go:1326`): only `mc.mutex` (no SelectorCache lock)
- **The unit test demonstrates 68% consumer efficiency** under contention
  (see branch `nv/selectorcache-write-lock-contention-reproducer`, `pkg/policy/lock_contention_test.go`)
- **The fix exists**: PR [#34205](https://github.com/cilium/cilium/pull/34205) (Cilium 1.16) changes
  `ConsumeMapChanges` from `mutex.Lock()` to `mutex.RLock()`
- **1.16.0 heap profile shows zero `AccumulateMapChanges` allocations** (tested on Kind)

### What is NOT confirmed

- Whether the tipping point can be triggered outside of production
- Whether CNP update storms alone are sufficient, or if other factors
  (cluster size, identity count, CCNP fan-out) are required
- The exact conditions that cause some nodes to tip while others don't

## Debugging tips

If running against a real cluster where the bug is active:

```bash
# Grab heap profile from an affected agent
kubectl port-forward -n kube-system <cilium-pod> 6060:6060 &
curl -s http://localhost:6060/debug/pprof/heap > heap.prof
go tool pprof -top -inuse_space heap.prof

# Check identity event rate
kubectl logs -n kube-system <cilium-pod> --tail=10000 | \
  grep -c "Skipping Delete"

# Check goroutine stacks for lock contention
kubectl exec -n kube-system <cilium-pod> -- gops stack 1 | \
  grep -c "semacquire"
```

## Related

- [PR #34205](https://github.com/cilium/cilium/pull/34205) — Fix: ConsumeMapChanges Lock -> RLock (Cilium 1.16)
- Branch `nv/selectorcache-write-lock-contention-reproducer` — Unit test demonstrating lock contention with real Cilium types
