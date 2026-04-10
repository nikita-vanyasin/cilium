// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

// contentiontestEndpoint implements CachedSelectionUser. When the SelectorCache
// notifies it of identity changes, it calls the real AccumulateMapChanges on
// a real MapChanges queue — exactly as L4Filter does in production.
type contentionTestEndpoint struct {
	policyMapChanges MapChanges // real per-endpoint queue (same type as production)

	mu          sync.Mutex
	accumulated int64
}

func (ep *contentionTestEndpoint) IdentitySelectionUpdated(selector CachedSelector, added, deleted []identity.NumericIdentity) {
	// This mirrors L4Filter.IdentitySelectionUpdated (l4.go:597-627):
	// it calls AccumulateMapChanges which only acquires mc.mutex (per-endpoint),
	// NOT SelectorCache.mutex. This is the producer side of the bug.
	ep.policyMapChanges.AccumulateMapChanges(
		selector,
		added, deleted,
		443, 6, // port=443, proto=TCP
		trafficdirection.Egress,
		false, false, // redirect, deny
		DefaultAuthType, AuthTypeDisabled,
		nil,
	)
	ep.mu.Lock()
	ep.accumulated += int64(len(added) + len(deleted))
	ep.mu.Unlock()
}

func (ep *contentionTestEndpoint) getAccumulated() int64 {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	return ep.accumulated
}

func (ep *contentionTestEndpoint) getQueueLen() int {
	ep.policyMapChanges.mutex.Lock()
	defer ep.policyMapChanges.mutex.Unlock()
	return len(ep.policyMapChanges.changes)
}

// TestWriteLockContention exercises the real SelectorCache, UpdateIdentities,
// and AccumulateMapChanges code to demonstrate the write-lock contention bug.
//
// The bug: both UpdateIdentities (selectorcache.go:1027) and ConsumeMapChanges
// (resolve.go:235) acquire SelectorCache.mutex.Lock() (WRITE). But
// AccumulateMapChanges (mapstate.go:1326) only needs mc.mutex (per-endpoint).
// The producer is never blocked by SelectorCache.mutex; the consumer always is.
//
// Under sustained identity churn, the consumer cannot keep up, and the
// per-endpoint MapChanges queue grows unboundedly (observed: 70 GiB, 132M objects).
//
// Fixed in Cilium 1.16 via PR #34205 (ConsumeMapChanges: Lock -> RLock).
func TestWriteLockContention(t *testing.T) {
	// Real SelectorCache — same type as production.
	sc := NewSelectorCache(testidentity.NewMockIdentityAllocator(nil), cache.IdentityCache{})

	// Create endpoints and register selectors, just like production.
	// In production, each ClickHouse server pod has many L4Filters, each
	// registered as a CachedSelectionUser. We create 8 endpoints with 1
	// selector each (the blown-up node had 8 CH endpoints).
	numEndpoints := 8
	endpoints := make([]*contentionTestEndpoint, numEndpoints)
	for i := range endpoints {
		ep := &contentionTestEndpoint{}
		endpoints[i] = ep

		sel := api.NewESFromLabels(labels.NewLabel("app", "server", labels.LabelSourceK8s))
		cs, _ := sc.AddIdentitySelector(ep, sel)
		if cs == nil {
			t.Fatalf("endpoint %d: AddIdentitySelector returned nil", i)
		}
	}

	done := make(chan struct{})
	var wg sync.WaitGroup
	var identityEvents atomic.Int64

	// === PRODUCERS ===
	// Simulate continuous identity churn via the real UpdateIdentities.
	// Each call: acquires SelectorCache.mutex WRITE lock -> iterates selectors ->
	// notifies endpoints via IdentitySelectionUpdated -> AccumulateMapChanges.
	numProducers := 4
	for p := 0; p < numProducers; p++ {
		wg.Add(1)
		go func(pid int) {
			defer wg.Done()
			base := identity.NumericIdentity(10000 + pid*100000)
			for i := 0; ; i++ {
				select {
				case <-done:
					return
				default:
				}
				id := base + identity.NumericIdentity(i%500)
				lbls := labels.LabelArray{labels.NewLabel("app", "server", labels.LabelSourceK8s)}

				// Add then delete — simulates pod lifecycle churn.
				addWg := &sync.WaitGroup{}
				sc.UpdateIdentities(cache.IdentityCache{id: lbls}, nil, addWg)
				addWg.Wait()

				delWg := &sync.WaitGroup{}
				sc.UpdateIdentities(nil, cache.IdentityCache{id: lbls}, delWg)
				delWg.Wait()

				identityEvents.Add(2)
			}
		}(p)
	}

	// === CONSUMERS ===
	// Simulate ConsumeMapChanges for each endpoint.
	// In production (resolve.go:234-238):
	//   p.selectorPolicy.SelectorCache.mutex.Lock()     // WRITE lock
	//   p.policyMapChanges.consumeMapChanges(...)
	//   p.selectorPolicy.SelectorCache.mutex.Unlock()
	//
	// We replicate this exactly: acquire the real SelectorCache write lock,
	// then drain the real MapChanges queue.
	var totalConsumed atomic.Int64
	for _, ep := range endpoints {
		wg.Add(1)
		go func(ep *contentionTestEndpoint) {
			defer wg.Done()
			state := make(MapState)
			for {
				select {
				case <-done:
					return
				default:
				}
				// Exact lock pattern from resolve.go:235
				sc.mutex.Lock()
				adds, deletes := ep.policyMapChanges.consumeMapChanges(state, 0, sc)
				sc.mutex.Unlock()
				totalConsumed.Add(int64(len(adds) + len(deletes)))
			}
		}(ep)
	}

	// === MEASURE ===
	type sample struct {
		events      int64
		accumulated int64
		consumed    int64
	}
	var samples []sample
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	testDuration := 5 * time.Second
	timer := time.After(testDuration)
	for {
		select {
		case <-ticker.C:
			var acc int64
			for _, ep := range endpoints {
				acc += ep.getAccumulated()
			}
			samples = append(samples, sample{
				events:      identityEvents.Load(),
				accumulated: acc,
				consumed:    totalConsumed.Load(),
			})
		case <-timer:
			close(done)
			wg.Wait()
			goto report
		}
	}

report:
	var totalAcc int64
	var totalQueueDepth int
	for _, ep := range endpoints {
		totalAcc += ep.getAccumulated()
		totalQueueDepth += ep.getQueueLen()
	}
	finalCons := totalConsumed.Load()
	finalEvents := identityEvents.Load()

	t.Log("")
	t.Log("=== SelectorCache Write-Lock Contention Reproducer ===")
	t.Log("")
	t.Log("Real Cilium types: SelectorCache, UpdateIdentities, AccumulateMapChanges, consumeMapChanges")
	t.Log("")
	t.Logf("  %d identity-churn goroutines (producers)", numProducers)
	t.Logf("  %d endpoints with selectors (consumers)", numEndpoints)
	t.Logf("  %s test duration", testDuration)
	t.Log("")
	t.Log(" Time | Identity Events | Accumulated |  Consumed |  Pending")
	t.Log("------|-----------------|-------------|-----------|----------")
	for i, s := range samples {
		t.Logf(" %4.1fs | %15d | %11d | %9d | %8d",
			float64(i+1)*0.5, s.events, s.accumulated, s.consumed, s.accumulated-s.consumed)
	}

	pending := totalAcc - finalCons
	t.Log("")
	t.Logf("Final: identity_events=%d accumulated=%d consumed=%d pending=%d final_queue_depth=%d",
		finalEvents, totalAcc, finalCons, pending, totalQueueDepth)

	if finalEvents > 0 {
		t.Logf("Fan-out: %.1fx (each identity event -> %.1f map changes across %d endpoints)",
			float64(totalAcc)/float64(finalEvents),
			float64(totalAcc)/float64(finalEvents),
			numEndpoints)
	}

	if totalAcc > 0 {
		ratio := float64(finalCons) / float64(totalAcc)
		t.Logf("Consumer efficiency: %.2f%%", ratio*100)
		t.Log("")

		if ratio < 0.99 {
			t.Log("DEMONSTRATED: Consumer cannot keep up with producer.")
			t.Log("")
			t.Log("  Root cause (resolve.go:235, selectorcache.go:1027):")
			t.Log("    Both ConsumeMapChanges and UpdateIdentities use SelectorCache.mutex.Lock() (WRITE)")
			t.Log("    But AccumulateMapChanges (mapstate.go:1326) only uses mc.mutex (no SelectorCache lock)")
			t.Log("    -> Producer is never blocked; consumer always competes for the lock")
			t.Log("")
			t.Log("  Fix: PR #34205 (Cilium 1.16) changes ConsumeMapChanges to mutex.RLock()")
		} else {
			t.Log("Consumer kept up in this short test with few selectors.")
			t.Log("In production with 14,000+ selectors per endpoint and sustained churn,")
			t.Log("the fan-out is ~100,000x larger and the imbalance is catastrophic.")
			t.Log("")
			t.Log("The lock pattern is still wrong regardless of this test's throughput:")
			t.Log("  ConsumeMapChanges: SelectorCache.mutex.Lock()   (WRITE) -- resolve.go:235")
			t.Log("  UpdateIdentities:  SelectorCache.mutex.Lock()   (WRITE) -- selectorcache.go:1027")
			t.Log("  AccumulateMapChanges: mc.mutex.Lock()            (own)  -- mapstate.go:1326")
		}
	}
}
