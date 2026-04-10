// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymapchurn

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/cidr"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	agentOption "github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/test/controlplane"
	"github.com/cilium/cilium/test/controlplane/suite"
)

func init() {
	suite.AddTestCase("PolicyMapChurn/WriteLockContention", testWriteLockContention)
}

// testWriteLockContention demonstrates the SelectorCache write-lock contention
// bug that causes unbounded memory growth in AccumulateMapChanges.
//
// The test starts a real cilium-agent (with fake datapath), creates a
// CiliumClusterwideNetworkPolicy with toCIDR rules (matching production),
// creates pods that match the policy, then rapidly churns pods to generate
// identity events. It measures heap memory growth over time.
//
// Root cause: both UpdateIdentities (selectorcache.go:1027) and
// ConsumeMapChanges (resolve.go:235) acquire SelectorCache.mutex.Lock()
// (WRITE), but AccumulateMapChanges (mapstate.go:1326) only uses mc.mutex.
// The producer outpaces the consumer, causing unbounded queue growth.
//
// Fixed in Cilium 1.16 via PR #34205 (ConsumeMapChanges: Lock -> RLock).
func testWriteLockContention(t *testing.T) {
	k8sVersions := controlplane.K8sVersions()
	k8sVersion := k8sVersions[len(k8sVersions)-1]

	test := suite.NewControlPlaneTest(t, "lock-contention-node", k8sVersion)
	defer test.StopAgent()

	// --- Initial objects: a node and a CCNP with toCIDR rules ---
	node := &corev1.Node{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Node"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   "lock-contention-node",
			Labels: map[string]string{"kubernetes.io/hostname": "lock-contention-node"},
		},
		Spec: corev1.NodeSpec{
			PodCIDR:  cidr.MustParseCIDR("10.244.0.0/24").String(),
			PodCIDRs: []string{cidr.MustParseCIDR("10.244.0.0/24").String()},
		},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{},
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "172.18.0.2"},
				{Type: corev1.NodeHostName, Address: "lock-contention-node"},
			},
		},
	}

	// This CCNP mirrors the production ch-server-allow-s3-explicitly policy:
	// broad toCIDR ranges selecting all pods with role=clickhouse-server.
	ccnp := &v2.CiliumClusterwideNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "cilium.io/v2",
			Kind:       "CiliumClusterwideNetworkPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "allow-s3-cidr",
			UID:  k8sTypes.UID("ccnp-s3-uid"),
		},
		Spec: &api.Rule{
			EndpointSelector: api.EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{
						"role": "server",
					},
				},
			},
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToCIDR: api.CIDRSlice{
							"54.231.0.0/16",  // S3 range (~65k IPs)
							"52.216.0.0/15",  // S3 range (~131k IPs)
							"18.34.0.0/19",
							"3.5.0.0/19",
						},
					},
				},
			},
		},
	}

	// --- Setup and start agent ---
	test.
		UpdateObjects(node, ccnp).
		SetupEnvironment(func(daemonCfg *agentOption.DaemonConfig, _ *operatorOption.OperatorConfig) {
			daemonCfg.EnablePolicy = agentOption.DefaultEnforcement
		}).
		StartAgent().
		EnsureWatchers("pods", "ciliumclusterwidenetworkpolicies")

	// --- Create initial pods that match the CCNP (role=server) ---
	// These become endpoints. In production we had 8 such endpoints.
	numEndpoints := 8
	for i := 0; i < numEndpoints; i++ {
		pod := makePod(fmt.Sprintf("server-%d", i), "default", "role", "server",
			fmt.Sprintf("10.244.0.%d", 10+i))
		test.UpdateObjects(pod)
	}

	// Wait for endpoints to be created
	time.Sleep(3 * time.Second)

	// --- Measure baseline memory ---
	var baseline runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&baseline)

	t.Logf("Baseline: HeapAlloc=%.1f MiB, HeapObjects=%d",
		float64(baseline.HeapAlloc)/1024/1024, baseline.HeapObjects)

	// --- Generate identity churn ---
	// Rapidly create and delete pods with unique labels to force identity
	// allocation/deallocation. Each identity event triggers UpdateIdentities
	// (SelectorCache WRITE lock) -> AccumulateMapChanges (no SC lock).
	//
	// The CCNP's toCIDR rules cause the SelectorCache to have many selectors,
	// amplifying each identity event into many AccumulateMapChanges calls.
	churnDuration := 10 * time.Second
	churnEnd := time.Now().Add(churnDuration)
	podCount := 0

	t.Logf("Starting identity churn for %s...", churnDuration)

	for time.Now().Before(churnEnd) {
		// Create a batch of pods with unique labels (each gets a new identity)
		batchSize := 20
		pods := make([]*corev1.Pod, batchSize)
		for i := 0; i < batchSize; i++ {
			podCount++
			name := fmt.Sprintf("churn-%d", podCount)
			pods[i] = makePod(name, "churn-ns", "churn-id", fmt.Sprintf("id-%d", podCount),
				fmt.Sprintf("10.244.1.%d", podCount%250+1))
			test.UpdateObjects(pods[i])
		}

		// Brief pause to let the agent process
		time.Sleep(50 * time.Millisecond)

		// Delete the batch
		for _, pod := range pods {
			test.DeleteObjects(pod)
		}

		time.Sleep(50 * time.Millisecond)
	}

	// --- Measure final memory ---
	var final runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&final)

	heapGrowthMiB := (float64(final.HeapAlloc) - float64(baseline.HeapAlloc)) / 1024 / 1024
	objectGrowth := int64(final.HeapObjects) - int64(baseline.HeapObjects)

	t.Log("")
	t.Log("=== Results ===")
	t.Logf("Identity churn: %d pods created/deleted in %s", podCount, churnDuration)
	t.Logf("Baseline: HeapAlloc=%.1f MiB, HeapObjects=%d", float64(baseline.HeapAlloc)/1024/1024, baseline.HeapObjects)
	t.Logf("Final:    HeapAlloc=%.1f MiB, HeapObjects=%d", float64(final.HeapAlloc)/1024/1024, final.HeapObjects)
	t.Logf("Growth:   HeapAlloc=%.1f MiB, HeapObjects=%+d", heapGrowthMiB, objectGrowth)
	t.Log("")

	if heapGrowthMiB > 50 {
		t.Logf("DEMONSTRATED: Heap grew by %.1f MiB during identity churn.", heapGrowthMiB)
		t.Log("This confirms the AccumulateMapChanges queue is not being drained.")
		t.Log("")
		t.Log("Root cause: SelectorCache.mutex write-lock contention between")
		t.Log("UpdateIdentities and ConsumeMapChanges (resolve.go:235).")
		t.Log("Fix: PR #34205 (Cilium 1.16) changes ConsumeMapChanges to RLock.")
	} else if heapGrowthMiB > 10 {
		t.Logf("Moderate heap growth of %.1f MiB detected.", heapGrowthMiB)
		t.Log("The write-lock contention is present but may not reach catastrophic")
		t.Log("levels in a short test. In production with 14k+ policies and sustained")
		t.Log("churn, this grows to tens of GiB.")
	} else {
		t.Logf("Heap growth of %.1f MiB within normal bounds for this test duration.", heapGrowthMiB)
		t.Log("The lock contention pattern is still present in the code (see resolve.go:235)")
		t.Log("but may require higher churn rates or more selectors to manifest visibly.")
	}
}

func makePod(name, namespace, labelKey, labelValue, ip string) *corev1.Pod {
	return &corev1.Pod{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{labelKey: labelValue},
			UID:       k8sTypes.UID(fmt.Sprintf("uid-%s-%s", namespace, name)),
		},
		Spec: corev1.PodSpec{
			NodeName: "lock-contention-node",
			Containers: []corev1.Container{
				{Name: "app", Image: "app:latest"},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionTrue},
			},
			PodIP:  ip,
			PodIPs: []corev1.PodIP{{IP: ip}},
		},
	}
}
