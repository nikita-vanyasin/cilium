// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package lockcontention demonstrates the write-lock contention between
// UpdateIdentities and ConsumeMapChanges on SelectorCache.mutex in Cilium 1.14.
//
// The test simulates the exact lock acquisition pattern from the Cilium source:
//   - UpdateIdentities (selectorcache.go:1027): SelectorCache.mutex.Lock() [WRITE]
//   - ConsumeMapChanges (resolve.go:235): SelectorCache.mutex.Lock() [WRITE]
//   - AccumulateMapChanges (mapstate.go:1326): mc.mutex.Lock() [per-endpoint, NO SelectorCache lock]
//
// Run with: go test -v -timeout 60s ./pkg/policy/lockcontention/
package lockcontention

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestSelectorCacheWriteLockContention demonstrates the write-lock contention
// between UpdateIdentities and ConsumeMapChanges.
//
// In production, this was observed causing 70 GiB memory usage on a single
// cilium-agent with 132 million MapStateEntry objects queued in
// AccumulateMapChanges that were never consumed.
//
// Fixed in Cilium 1.16 via PR #34205: ConsumeMapChanges changed from
// mutex.Lock() to mutex.RLock().
func TestSelectorCacheWriteLockContention(t *testing.T) {
	// Simulate the SelectorCache.mutex -- an RWMutex shared between
	// UpdateIdentities and ConsumeMapChanges.
	var selectorCacheMutex sync.RWMutex

	// Simulate the per-endpoint MapChanges queue with its own mutex.
	// This is MapChanges.mutex in mapstate.go -- completely independent
	// of the SelectorCache mutex.
	var queueMu sync.Mutex
	var queue []int

	var totalProduced atomic.Int64
	var totalConsumed atomic.Int64

	done := make(chan struct{})
	var wg sync.WaitGroup

	// ========================================================================
	// PRODUCERS: simulate UpdateIdentities -> AccumulateMapChanges
	//
	// In Cilium 1.14, each identity event:
	//   1. Acquires SelectorCache.mutex WRITE LOCK (selectorcache.go:1027)
	//   2. Iterates selectors, queues notifications
	//   3. Releases SelectorCache.mutex
	//   4. handleUserNotifications goroutine calls IdentitySelectionUpdated
	//   5. Which calls AccumulateMapChanges with only mc.mutex (mapstate.go:1326)
	//
	// Steps 1-3 block ConsumeMapChanges. Step 5 does NOT.
	// ========================================================================
	numProducers := 4
	for p := 0; p < numProducers; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}

				// Step 1-3: UpdateIdentities holds the SelectorCache WRITE lock
				// while processing identity changes and notifying selectors.
				selectorCacheMutex.Lock()
				// Simulate work done under the lock: iterate selectors,
				// match identities, queue notifications.
				runtime.Gosched()
				selectorCacheMutex.Unlock()

				// Step 5: AccumulateMapChanges only uses mc.mutex.
				// This is the key insight: the producer appends to the queue
				// WITHOUT needing the SelectorCache lock.
				queueMu.Lock()
				queue = append(queue, 1)
				queueMu.Unlock()
				totalProduced.Add(1)
			}
		}()
	}

	// ========================================================================
	// CONSUMERS: simulate ConsumeMapChanges
	//
	// In Cilium 1.14 (resolve.go:234-238):
	//   func (p *EndpointPolicy) ConsumeMapChanges() (adds, deletes Keys) {
	//       p.selectorPolicy.SelectorCache.mutex.Lock()      // <-- WRITE LOCK
	//       defer p.selectorPolicy.SelectorCache.mutex.Unlock()
	//       return p.policyMapChanges.consumeMapChanges(...)
	//   }
	//
	// The consumer MUST acquire the SelectorCache WRITE lock before it can
	// drain the queue. It competes with UpdateIdentities for this lock.
	// ========================================================================
	numConsumers := 2
	for c := 0; c < numConsumers; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}

				// ConsumeMapChanges: acquire SelectorCache WRITE lock
				selectorCacheMutex.Lock()
				// Then drain the queue (also needs mc.mutex)
				queueMu.Lock()
				n := len(queue)
				queue = nil
				queueMu.Unlock()
				selectorCacheMutex.Unlock()

				totalConsumed.Add(int64(n))
				runtime.Gosched()
			}
		}()
	}

	// ========================================================================
	// MEASURE: track queue depth over time
	// ========================================================================
	type sample struct {
		produced int64
		consumed int64
		queueLen int
	}
	var samples []sample
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	testDuration := 5 * time.Second
	timer := time.After(testDuration)

	for {
		select {
		case <-ticker.C:
			queueMu.Lock()
			ql := len(queue)
			queueMu.Unlock()
			samples = append(samples, sample{
				produced: totalProduced.Load(),
				consumed: totalConsumed.Load(),
				queueLen: ql,
			})
		case <-timer:
			close(done)
			wg.Wait()
			goto report
		}
	}

report:
	queueMu.Lock()
	finalQueue := len(queue)
	queueMu.Unlock()
	finalProd := totalProduced.Load()
	finalCons := totalConsumed.Load()

	t.Log("=== SelectorCache Write-Lock Contention Reproducer ===")
	t.Log("")
	t.Log("Simulates the lock pattern from Cilium v1.14.19:")
	t.Log("  Producer: UpdateIdentities (WRITE lock) -> AccumulateMapChanges (no SC lock)")
	t.Log("  Consumer: ConsumeMapChanges (WRITE lock) -> drain queue")
	t.Log("")
	t.Logf("Config: %d producers, %d consumers, %s duration", numProducers, numConsumers, testDuration)
	t.Log("")
	t.Log(" Time |   Produced |  Consumed | Queue Depth")
	t.Log("------|------------|-----------|------------")
	for i, s := range samples {
		t.Logf(" %4.1fs | %10d | %9d | %11d",
			float64(i+1)*0.5, s.produced, s.consumed, s.queueLen)
	}
	t.Log("")
	t.Logf("Final: produced=%d consumed=%d pending=%d", finalProd, finalCons, finalQueue)

	if finalProd > 0 {
		ratio := float64(finalCons) / float64(finalProd)
		t.Logf("Consumer/Producer ratio: %.4f", ratio)
		t.Log("")

		if ratio < 0.99 {
			t.Logf("DEMONSTRATED: Consumer drained only %.1f%% of produced changes.", ratio*100)
			t.Log("Pending changes accumulate in the MapChanges queue.")
		} else {
			t.Log("Consumer kept up in this short test. In production with thousands")
			t.Log("of selectors per identity event, the fan-out makes the imbalance worse.")
		}
	}

	t.Log("")
	t.Log("=== Comparison: With RLock fix (PR #34205, Cilium 1.16) ===")
	t.Log("Run TestSelectorCacheWriteLockContentionFixed to see the difference.")
}

// TestSelectorCacheWriteLockContentionAmplified demonstrates the bug with
// realistic fan-out: each UpdateIdentities call generates N AccumulateMapChanges
// entries (one per selector per endpoint). In production, N is in the thousands
// (14k CNPs with toCIDR rules * endpoints on node).
func TestSelectorCacheWriteLockContentionAmplified(t *testing.T) {
	var selectorCacheMutex sync.RWMutex
	var queueMu sync.Mutex
	var queue []int

	var totalProduced atomic.Int64
	var totalConsumed atomic.Int64

	done := make(chan struct{})
	var wg sync.WaitGroup

	// Fan-out factor: each identity event generates this many queue entries.
	// In production: selectors_per_endpoint * endpoints_on_node.
	// With 14k CNPs and 8 endpoints, this is ~112k entries per identity event.
	// We use 500 here to keep the test fast but show the effect.
	fanOut := 500

	numProducers := 4
	for p := 0; p < numProducers; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}

				// UpdateIdentities: WRITE lock on SelectorCache
				selectorCacheMutex.Lock()
				runtime.Gosched()
				selectorCacheMutex.Unlock()

				// AccumulateMapChanges: fan-out to N entries, NO SelectorCache lock
				queueMu.Lock()
				for i := 0; i < fanOut; i++ {
					queue = append(queue, 1)
				}
				queueMu.Unlock()
				totalProduced.Add(int64(fanOut))
			}
		}()
	}

	// Consumers: WRITE lock on SelectorCache (v1.14 behaviour)
	// consumeMapChanges does O(n) work per entry (denyPreferredInsertWithChanges)
	// while holding the SelectorCache write lock.
	numConsumers := 2
	for c := 0; c < numConsumers; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sink := 0
			for {
				select {
				case <-done:
					return
				default:
				}
				selectorCacheMutex.Lock()
				queueMu.Lock()
				n := len(queue)
				// Simulate O(n) work per entry in consumeMapChanges:
				// denyPreferredInsertWithChanges, deleteKeyWithChanges, etc.
				for i := 0; i < n; i++ {
					sink += queue[i]
				}
				queue = nil
				queueMu.Unlock()
				selectorCacheMutex.Unlock()
				_ = sink
				totalConsumed.Add(int64(n))
				runtime.Gosched()
			}
		}()
	}

	type sample struct {
		produced int64
		consumed int64
		queueLen int
	}
	var samples []sample
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	testDuration := 5 * time.Second
	timer := time.After(testDuration)
	for {
		select {
		case <-ticker.C:
			queueMu.Lock()
			ql := len(queue)
			queueMu.Unlock()
			samples = append(samples, sample{
				produced: totalProduced.Load(),
				consumed: totalConsumed.Load(),
				queueLen: ql,
			})
		case <-timer:
			close(done)
			wg.Wait()
			goto report
		}
	}

report:
	queueMu.Lock()
	finalQueue := len(queue)
	queueMu.Unlock()
	finalProd := totalProduced.Load()
	finalCons := totalConsumed.Load()

	t.Log("=== SelectorCache Write-Lock Contention -- WITH FAN-OUT ===")
	t.Log("")
	t.Logf("Fan-out factor: %d entries per identity event", fanOut)
	t.Log("(In production: ~112k with 14k CNPs * 8 endpoints)")
	t.Log("")
	t.Logf("Config: %d producers, %d consumers, %s duration", numProducers, numConsumers, testDuration)
	t.Log("")
	t.Log(" Time |   Produced |  Consumed | Queue Depth")
	t.Log("------|------------|-----------|------------")
	for i, s := range samples {
		t.Logf(" %4.1fs | %10d | %9d | %11d",
			float64(i+1)*0.5, s.produced, s.consumed, s.queueLen)
	}
	t.Log("")
	t.Logf("Final: produced=%d consumed=%d pending=%d", finalProd, finalCons, finalQueue)

	if finalProd > 0 {
		ratio := float64(finalCons) / float64(finalProd)
		t.Logf("Consumer/Producer ratio: %.4f", ratio)

		if ratio < 0.99 {
			t.Log("")
			t.Logf("DEMONSTRATED: With fan-out=%d, consumer falls behind.", fanOut)
			t.Log("Queue depth grows over time. In production with fan-out >100k,")
			t.Log("this leads to GiBs of accumulated MapStateEntry objects.")
		}
	}
}

// TestSelectorCacheWriteLockContentionFixed shows what happens when
// ConsumeMapChanges uses RLock instead of Lock (the fix from PR #34205).
//
// With RLock, multiple consumers can drain concurrently, and consumers
// only block during UpdateIdentities (which still needs a write lock).
func TestSelectorCacheWriteLockContentionFixed(t *testing.T) {
	var selectorCacheMutex sync.RWMutex
	var queueMu sync.Mutex
	var queue []int

	var totalProduced atomic.Int64
	var totalConsumed atomic.Int64

	done := make(chan struct{})
	var wg sync.WaitGroup

	// PRODUCERS: identical to the unfixed version
	numProducers := 4
	for p := 0; p < numProducers; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				selectorCacheMutex.Lock()
				runtime.Gosched()
				selectorCacheMutex.Unlock()

				queueMu.Lock()
				queue = append(queue, 1)
				queueMu.Unlock()
				totalProduced.Add(1)
			}
		}()
	}

	// CONSUMERS: use RLock instead of Lock (the fix from PR #34205)
	numConsumers := 2
	for c := 0; c < numConsumers; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}

				// THE FIX: ConsumeMapChanges uses RLock instead of Lock
				selectorCacheMutex.RLock()
				queueMu.Lock()
				n := len(queue)
				queue = nil
				queueMu.Unlock()
				selectorCacheMutex.RUnlock()

				totalConsumed.Add(int64(n))
				runtime.Gosched()
			}
		}()
	}

	type sample struct {
		produced int64
		consumed int64
		queueLen int
	}
	var samples []sample
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	testDuration := 5 * time.Second
	timer := time.After(testDuration)

	for {
		select {
		case <-ticker.C:
			queueMu.Lock()
			ql := len(queue)
			queueMu.Unlock()
			samples = append(samples, sample{
				produced: totalProduced.Load(),
				consumed: totalConsumed.Load(),
				queueLen: ql,
			})
		case <-timer:
			close(done)
			wg.Wait()
			goto report
		}
	}

report:
	queueMu.Lock()
	finalQueue := len(queue)
	queueMu.Unlock()
	finalProd := totalProduced.Load()
	finalCons := totalConsumed.Load()

	t.Log("=== SelectorCache Write-Lock Contention -- WITH FIX (RLock) ===")
	t.Log("")
	t.Log("ConsumeMapChanges now uses RLock (PR #34205, Cilium 1.16)")
	t.Log("Multiple consumers can run concurrently; they only block during UpdateIdentities.")
	t.Log("")
	t.Logf("Config: %d producers, %d consumers, %s duration", numProducers, numConsumers, testDuration)
	t.Log("")
	t.Log(" Time |   Produced |  Consumed | Queue Depth")
	t.Log("------|------------|-----------|------------")
	for i, s := range samples {
		t.Logf(" %4.1fs | %10d | %9d | %11d",
			float64(i+1)*0.5, s.produced, s.consumed, s.queueLen)
	}
	t.Log("")
	t.Logf("Final: produced=%d consumed=%d pending=%d", finalProd, finalCons, finalQueue)

	if finalProd > 0 {
		ratio := float64(finalCons) / float64(finalProd)
		t.Logf("Consumer/Producer ratio: %.4f", ratio)

		if ratio > 0.99 {
			t.Log("")
			t.Log("CONFIRMED: With RLock, the consumer keeps up with the producer.")
			t.Log("Queue depth stays near zero. No unbounded memory growth.")
		}
	}
}
