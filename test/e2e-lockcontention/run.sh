#!/usr/bin/env bash
# Reproducer for SelectorCache write-lock contention causing unbounded memory
# growth in cilium-agent AccumulateMapChanges queue.
#
# Two modes:
#   Kind mode (default): creates a Kind cluster, installs Cilium, runs the test
#   External mode:       runs against an existing cluster with Cilium already deployed
#
# Requirements:
#   Kind mode:     kind, kubectl, helm, go, curl
#   External mode: kubectl (configured), go, curl
#
# Usage:
#   ./run.sh [version]                   # Kind mode (default: 1.14.19)
#   ./run.sh --external                  # External mode (uses current kubeconfig)
#   ./run.sh --cleanup [version]         # Delete Kind cluster
#
# Exit codes:
#   0 = no significant memory growth (healthy)
#   1 = setup error
#   2 = memory growth detected (bug confirmed)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# --- Mode detection ---
MODE="kind"
CILIUM_VERSION=""
if [[ "${1:-}" == "--external" ]]; then
    MODE="external"
    shift
elif [[ "${1:-}" == "--cleanup" ]]; then
    CILIUM_VERSION="${2:-1.14.19}"
    CLUSTER_NAME="cilium-lock-${CILIUM_VERSION//\./-}"
    log() { echo -e "\033[0;32m[+]\033[0m $*"; }
    log "Deleting kind cluster ${CLUSTER_NAME}..."
    kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
    rm -f "${SCRIPT_DIR}/.kubeconfig-${CILIUM_VERSION}"
    exit 0
else
    CILIUM_VERSION="${1:-1.14.19}"
fi

# --- Configuration ---
CHURN_DURATION="${CHURN_DURATION:-300}"
NUM_NAMESPACES="${NUM_NAMESPACES:-50}"
CNPS_PER_NS="${CNPS_PER_NS:-2}"
NUM_CIDR_ENTRIES="${NUM_CIDR_ENTRIES:-20}"
BURST_SIZE="${BURST_SIZE:-50}"
BURST_INTERVAL="${BURST_INTERVAL:-2}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-15}"
MEMORY_GROWTH_THRESHOLD_MI="${MEMORY_GROWTH_THRESHOLD_MI:-50}"
DIVERGENCE_RATIO="${DIVERGENCE_RATIO:-2.0}"
PODS_PER_LABEL="${PODS_PER_LABEL:-2}"
NUM_CNPS=$((NUM_NAMESPACES * CNPS_PER_NS))
TOTAL_PODS=$((NUM_NAMESPACES * PODS_PER_LABEL * 2))
PPROF_PORT="${PPROF_PORT:-6060}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[x]${NC} $*"; }

# --- Helpers ---

get_agent_heap_mi() {
    local port="$1"
    local tmpprof
    tmpprof=$(mktemp /tmp/heap-XXXXXX.prof)
    if ! curl -sf "http://localhost:${port}/debug/pprof/heap?gc=1" -o "${tmpprof}" 2>/dev/null; then
        rm -f "${tmpprof}"
        echo "0"
        return
    fi
    local total_mi
    total_mi=$(go tool pprof -text -inuse_space "${tmpprof}" 2>/dev/null | \
        awk '/of .* total/ {
            for(i=1;i<=NF;i++) {
                if ($(i+1) == "total") {
                    val = $i
                    if (val ~ /kB$/) { gsub(/kB/,"",val); printf "%.0f", val/1024; exit }
                    if (val ~ /MB$/) { gsub(/MB/,"",val); printf "%.0f", val; exit }
                    if (val ~ /GB$/) { gsub(/GB/,"",val); printf "%.0f", val*1024; exit }
                }
            }
        }')
    rm -f "${tmpprof}"
    echo "${total_mi:-0}"
}

get_agent_cgroup_mi() {
    local pod="$1"
    local mem
    mem=$(kubectl exec -n kube-system "$pod" -c cilium-agent -- \
        cat /sys/fs/cgroup/memory/memory.usage_in_bytes 2>/dev/null || \
        kubectl exec -n kube-system "$pod" -c cilium-agent -- \
        cat /sys/fs/cgroup/memory.current 2>/dev/null || echo "0")
    echo $((mem / 1048576))
}

get_cilium_pods() {
    kubectl get pods -n kube-system -l k8s-app=cilium -o jsonpath='{.items[*].metadata.name}' \
        --request-timeout=30s 2>/dev/null
}

get_all_agents_heap() {
    local base_port=16060
    local pids=()
    local pods=()
    local pod_list
    pod_list=$(get_cilium_pods)
    if [ -z "$pod_list" ]; then
        warn "Could not list cilium pods"
        return
    fi
    for pod in $pod_list; do
        local port=$((base_port + ${#pods[@]}))
        kubectl port-forward -n kube-system "$pod" "${port}:${PPROF_PORT}" >/dev/null 2>&1 &
        pids+=($!)
        pods+=("$pod:$port")
    done
    sleep 3
    for entry in "${pods[@]}"; do
        local pod="${entry%%:*}"
        local port="${entry##*:}"
        echo "${pod} $(get_agent_heap_mi "$port")"
    done
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait "${pids[@]}" 2>/dev/null || true
}

max_memory() { awk '{if ($2+0 > max) max=$2+0} END {print max+0}'; }
min_memory() { awk 'NR==1 || $2+0 < min {min=$2+0} END {print min+0}'; }

# ========================================================================
# KIND MODE: Create cluster and install Cilium
# ========================================================================
if [ "$MODE" = "kind" ]; then
    CLUSTER_NAME="cilium-lock-${CILIUM_VERSION//\./-}"
    export KUBECONFIG="${SCRIPT_DIR}/.kubeconfig-${CILIUM_VERSION}"

    log "Testing Cilium ${CILIUM_VERSION} (Kind mode, cluster: ${CLUSTER_NAME})"

    if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
        warn "Cluster already exists, reusing."
    else
        kind create cluster --name "${CLUSTER_NAME}" --config "${SCRIPT_DIR}/kind-config.yaml" --kubeconfig "${KUBECONFIG}"
    fi
    kind get kubeconfig --name "${CLUSTER_NAME}" > "${KUBECONFIG}" 2>/dev/null || true

    kubectl cluster-info >/dev/null 2>&1 || { err "Cannot connect to cluster"; exit 1; }

    # Pre-load images
    CILIUM_IMAGES=(
        "quay.io/cilium/cilium:v${CILIUM_VERSION}"
        "quay.io/cilium/operator-generic:v${CILIUM_VERSION}"
    )
    log "Pre-loading Cilium images into Kind nodes..."
    for img in "${CILIUM_IMAGES[@]}"; do
        docker image inspect "$img" >/dev/null 2>&1 || { log "Pulling ${img}..."; docker pull "$img"; }
        kind load docker-image "$img" --name "${CLUSTER_NAME}" 2>/dev/null || true
    done

    # Install Cilium
    log "Installing Cilium ${CILIUM_VERSION} via Helm..."
    helm repo add cilium https://helm.cilium.io/ 2>/dev/null || true
    helm repo update cilium >/dev/null
    helm upgrade --install cilium cilium/cilium \
        --version "${CILIUM_VERSION}" \
        --namespace kube-system \
        --set image.pullPolicy=IfNotPresent \
        --set ipam.mode=kubernetes \
        --set pprof.enabled=true \
        --set pprof.port="${PPROF_PORT}" \
        --set debug.enabled=true \
        --set prometheus.enabled=true \
        --wait --timeout 600s

    log "Waiting for Cilium agents..."
    kubectl rollout status daemonset/cilium -n kube-system --timeout=600s
    kubectl wait --for=condition=Ready pods -l k8s-app=cilium -n kube-system --timeout=600s

    # Apply CCNP
    log "Applying CiliumClusterwideNetworkPolicy with toCIDR rules..."
    kubectl apply -f "${SCRIPT_DIR}/ccnp-s3-cidr.yaml"

    # Deploy server pods matching the CCNP
    log "Deploying server pods (role=server, matching CCNP)..."
    kubectl apply -f "${SCRIPT_DIR}/server-deployment.yaml"
    kubectl rollout status deployment/server --timeout=600s

# ========================================================================
# EXTERNAL MODE: Use existing cluster with Cilium already deployed
# ========================================================================
else
    log "Testing against external cluster (mode: external)"
    log "Using current kubeconfig: ${KUBECONFIG:-~/.kube/config}"

    kubectl cluster-info >/dev/null 2>&1 || { err "Cannot connect to cluster"; exit 1; }

    # Verify Cilium is running
    AGENT_COUNT=$(kubectl get pods -n kube-system -l k8s-app=cilium --no-headers 2>/dev/null | grep -c Running || echo 0)
    if [ "$AGENT_COUNT" -eq 0 ]; then
        err "No running Cilium agents found in kube-system"
        exit 1
    fi
    log "Found ${AGENT_COUNT} running Cilium agents."

    # Detect Cilium version
    CILIUM_VERSION=$(kubectl exec -n kube-system "$(get_cilium_pods | awk '{print $1}')" \
        -c cilium-agent -- cilium version 2>/dev/null | awk '/cilium/ {print $2}' || echo "unknown")
    log "Detected Cilium version: ${CILIUM_VERSION}"

    # Check if pprof is reachable
    FIRST_POD=$(get_cilium_pods | awk '{print $1}')
    kubectl port-forward -n kube-system "$FIRST_POD" 16059:"${PPROF_PORT}" >/dev/null 2>&1 &
    PF_CHECK=$!
    sleep 2
    if curl -sf "http://localhost:16059/debug/pprof/" >/dev/null 2>&1; then
        log "pprof is available on port ${PPROF_PORT}."
    else
        warn "pprof not reachable on port ${PPROF_PORT}. Heap measurements will be 0."
        warn "Enable pprof: helm upgrade cilium --set pprof.enabled=true --set pprof.port=${PPROF_PORT}"
    fi
    kill "$PF_CHECK" 2>/dev/null || true

    # Skip CCNP and server-deployment — assume existing cluster has its own policies/workloads
    log "Skipping CCNP and server deployment (external mode)."
fi

# --- Wait for agents to stabilise ---
log "Waiting for agents to stabilise..."
sleep 10

# ========================================================================
# CREATE TEST WORKLOAD: namespaces + pods + CNPs
# ========================================================================
log "Creating test workload: ${NUM_NAMESPACES} ns x ${CNPS_PER_NS} CNPs x $((PODS_PER_LABEL * 2)) pods..."

# Create namespaces + pods
NS_BATCH=50
for ((batch_start=1; batch_start<=NUM_NAMESPACES; batch_start+=NS_BATCH)); do
    batch_end=$((batch_start + NS_BATCH - 1))
    [ "${batch_end}" -gt "${NUM_NAMESPACES}" ] && batch_end="${NUM_NAMESPACES}"

    YAML=$(mktemp)
    awk -v start="${batch_start}" -v end="${batch_end}" -v ppl="${PODS_PER_LABEL}" '
    BEGIN {
        split("server-a,server-b", labels, ",")
        for (ns = start; ns <= end; ns++) {
            printf "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: cnp-churn-%d\n---\n", ns
            for (l = 1; l <= 2; l++) {
                for (p = 1; p <= ppl; p++) {
                    printf "apiVersion: v1\nkind: Pod\nmetadata:\n"
                    printf "  name: pod-%s-%d\n  namespace: cnp-churn-%d\n", labels[l], p, ns
                    printf "  labels:\n    app: %s\nspec:\n  restartPolicy: Never\n", labels[l]
                    printf "  terminationGracePeriodSeconds: 0\n"
                    printf "  containers:\n    - name: c\n      image: busybox:latest\n      command: [\"sleep\", \"infinity\"]\n---\n"
                }
            }
        }
    }' /dev/null > "${YAML}"
    kubectl apply -f "${YAML}" --server-side >/dev/null 2>&1 || \
        kubectl apply -f "${YAML}" >/dev/null 2>&1 || true
    rm -f "${YAML}"
    echo -ne "\r  Namespaces+pods: ${batch_end}/${NUM_NAMESPACES} ns, ~$((batch_end * PODS_PER_LABEL * 2))/${TOTAL_PODS} pods..."
done
echo ""
log "${NUM_NAMESPACES} namespaces with ${TOTAL_PODS} pods created."

log "Waiting for pods to be scheduled..."
sleep 15

# Create CNPs
log "Creating ${NUM_CNPS} CNPs (${CNPS_PER_NS}/ns, ${NUM_CIDR_ENTRIES} fromCIDR each)..."
CNP_BATCH=50
for ((batch_start=1; batch_start<=NUM_NAMESPACES; batch_start+=CNP_BATCH)); do
    batch_end=$((batch_start + CNP_BATCH - 1))
    [ "${batch_end}" -gt "${NUM_NAMESPACES}" ] && batch_end="${NUM_NAMESPACES}"

    CNP_YAML=$(mktemp)
    awk -v start="${batch_start}" -v end="${batch_end}" -v cpn="${CNPS_PER_NS}" \
        -v num_cidrs="${NUM_CIDR_ENTRIES}" -v offset=0 '
    BEGIN {
        split("server-a,server-b", labels, ",")
        for (ns = start; ns <= end; ns++) {
            for (c = 1; c <= cpn; c++) {
                cnp_id = (ns - 1) * cpn + c
                app_label = labels[c]
                printf "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\n"
                printf "metadata:\n  name: churn-policy-%d\n  namespace: cnp-churn-%d\n", c, ns
                printf "spec:\n  endpointSelector:\n    matchLabels:\n      app: %s\n  ingress:\n", app_label
                for (j = 0; j < num_cidrs; j++) {
                    idx = (j + offset) % num_cidrs + 1
                    a = (cnp_id * 7 + idx * 13) % 256
                    b = (cnp_id * 11 + idx * 17) % 256
                    printf "    - fromCIDR:\n        - 10.69.%d.%d/32\n", a, b
                }
                printf "---\n"
            }
        }
    }' /dev/null > "${CNP_YAML}"
    kubectl apply -f "${CNP_YAML}" --server-side >/dev/null 2>&1 || \
        kubectl apply -f "${CNP_YAML}" >/dev/null 2>&1 || true
    rm -f "${CNP_YAML}"
    echo -ne "\r  CNPs created: $((batch_end * CNPS_PER_NS))/${NUM_CNPS}..."
done
echo ""
log "${NUM_CNPS} CNPs created."

# ========================================================================
# BASELINE
# ========================================================================
log "Waiting for agents to process all CNPs..."
sleep 30

log "Collecting baseline heap (pprof with forced GC)..."
BASELINE_DATA=$(get_all_agents_heap)

echo ""
echo "=== Baseline Cilium Agent Heap (after ${NUM_CNPS} CNPs loaded) ==="
echo "$BASELINE_DATA" | while read -r pod mem; do
    printf "  %-50s %4d Mi (heap inuse)\n" "$pod" "$mem"
done
echo ""

declare -A AGENT_BASELINE
while read -r pod mem; do
    AGENT_BASELINE["$pod"]="$mem"
done <<< "$BASELINE_DATA"

# ========================================================================
# CHURN
# ========================================================================
log "Starting CNP burst-update churn: ${CHURN_DURATION}s, bursts of ${BURST_SIZE} to same CNP every ${BURST_INTERVAL}s..."
echo ""

CNP_EVENTS_FILE="${SCRIPT_DIR}/cnp-events-${CILIUM_VERSION}.log"
kubectl get cnp -A -w --output-watch-events --no-headers > "${CNP_EVENTS_FILE}" 2>/dev/null &
CNP_WATCH_PID=$!

SAMPLE_FILE=$(mktemp)
(
    while true; do
        ts=$(date +%s)
        for pod in $(get_cilium_pods); do
            mem=$(get_agent_cgroup_mi "$pod")
            echo "${ts} ${pod} ${mem}" >> "${SAMPLE_FILE}"
        done
        sleep "${SAMPLE_INTERVAL}"
    done
) &
SAMPLER_PID=$!
trap "kill ${SAMPLER_PID} ${CNP_WATCH_PID} 2>/dev/null; rm -f ${SAMPLE_FILE}" EXIT

CHURN_START=$(date +%s)
CHURN_END=$((CHURN_START + CHURN_DURATION))
BURST_COUNT=0
TOTAL_UPDATES=0

while [ "$(date +%s)" -lt "${CHURN_END}" ]; do
    BURST_COUNT=$((BURST_COUNT + 1))

    TARGET_NS="cnp-churn-1"
    TARGET_CNP="churn-policy-1"
    TARGET_LABEL="server-a"
    CNP_SEED=1

    ROUND_START=$(date +%s)
    for ((b=1; b<=BURST_SIZE; b++)); do
        offset=$((BURST_COUNT * BURST_SIZE + b))
        YAML=$(mktemp)
        awk -v ns="${TARGET_NS}" -v name="${TARGET_CNP}" -v label="${TARGET_LABEL}" \
            -v num_cidrs="${NUM_CIDR_ENTRIES}" -v seed="${CNP_SEED}" -v offset="${offset}" '
        BEGIN {
            printf "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\n"
            printf "metadata:\n  name: %s\n  namespace: %s\n", name, ns
            printf "spec:\n  endpointSelector:\n    matchLabels:\n      app: %s\n  ingress:\n", label
            for (j = 0; j < num_cidrs; j++) {
                idx = (j + offset) % num_cidrs + 1
                a = (seed * 7 + idx * 13) % 256
                b_val = (seed * 11 + idx * 17) % 256
                printf "    - fromCIDR:\n        - 10.69.%d.%d/32\n", a, b_val
            }
        }' /dev/null > "${YAML}"
        kubectl apply -f "${YAML}" --server-side >/dev/null 2>&1 || \
            kubectl apply -f "${YAML}" >/dev/null 2>&1 || true
        rm -f "${YAML}"
    done
    TOTAL_UPDATES=$((TOTAL_UPDATES + BURST_SIZE))

    ROUND_END=$(date +%s)
    ROUND_SECS=$((ROUND_END - ROUND_START))
    REMAINING=$((CHURN_END - ROUND_END))
    RATE=$(awk "BEGIN { printf \"%.0f\", ${BURST_SIZE} / (${ROUND_SECS} > 0 ? ${ROUND_SECS} : 1) }")
    echo -ne "\r  Burst ${BURST_COUNT}: ${BURST_SIZE} updates to ${TARGET_NS}/${TARGET_CNP} in ${ROUND_SECS}s (~${RATE}/s), ${REMAINING}s left  "

    sleep "${BURST_INTERVAL}"
done
echo ""
log "Churn complete: ${BURST_COUNT} bursts, ${TOTAL_UPDATES} total CNP updates."

sleep 5

kill "${SAMPLER_PID}" 2>/dev/null || true
kill "${CNP_WATCH_PID}" 2>/dev/null || true
wait "${SAMPLER_PID}" 2>/dev/null || true
wait "${CNP_WATCH_PID}" 2>/dev/null || true

if [ -f "${CNP_EVENTS_FILE}" ]; then
    CNP_EVENT_COUNT=$(wc -l < "${CNP_EVENTS_FILE}" | tr -d ' ')
    log "CNP events observed: ${CNP_EVENT_COUNT} (see ${CNP_EVENTS_FILE})"
fi

# ========================================================================
# FINAL MEASUREMENT
# ========================================================================
log "Collecting final heap (pprof with forced GC)..."
FINAL_DATA=$(get_all_agents_heap)

echo ""
echo "=== Final Cilium Agent Heap ==="
echo "$FINAL_DATA" | while read -r pod mem; do
    printf "  %-50s %4d Mi (heap inuse)\n" "$pod" "$mem"
done
echo ""

echo "=== Per-Agent Growth ==="
MAX_GROWTH=0
MIN_GROWTH=999999
WORST_POD=""
declare -A AGENT_GROWTH

while read -r pod final_mem; do
    baseline_mem="${AGENT_BASELINE[$pod]:-0}"
    growth=$((final_mem - baseline_mem))
    AGENT_GROWTH["$pod"]="$growth"
    printf "  %-50s baseline=%4d  final=%4d  growth=%+4d Mi\n" "$pod" "$baseline_mem" "$final_mem" "$growth"
    if [ "$growth" -gt "$MAX_GROWTH" ]; then
        MAX_GROWTH="$growth"
        WORST_POD="$pod"
    fi
    if [ "$growth" -lt "$MIN_GROWTH" ]; then
        MIN_GROWTH="$growth"
    fi
done <<< "$FINAL_DATA"
echo ""

# Heap profile from worst agent
if [ -n "$WORST_POD" ]; then
    log "Capturing heap profile from worst agent (${WORST_POD}, +${MAX_GROWTH} Mi)..."
    HEAP_FILE="${SCRIPT_DIR}/heap_${CILIUM_VERSION}_$(date +%Y%m%d_%H%M%S).prof"
    kubectl port-forward -n kube-system "${WORST_POD}" 16060:"${PPROF_PORT}" >/dev/null 2>&1 &
    PF_PID=$!
    sleep 2
    if curl -sf "http://localhost:16060/debug/pprof/heap" -o "${HEAP_FILE}" 2>/dev/null; then
        log "Heap profile saved to ${HEAP_FILE}"
        log "Top allocators:"
        go tool pprof -top -inuse_space "${HEAP_FILE}" 2>/dev/null | head -15 || true
    else
        warn "pprof not available — skipping heap profile"
    fi
    kill "$PF_PID" 2>/dev/null || true
fi

# ========================================================================
# MEMORY TIMELINE
# ========================================================================
echo ""
echo "=== Memory Timeline (cgroup) ==="
echo ""
if [ -s "${SAMPLE_FILE}" ]; then
    START_TS=$(head -1 "${SAMPLE_FILE}" | awk '{print $1}')
    PODS=$(awk '{print $2}' "${SAMPLE_FILE}" | sort -u)
    printf "  %6s" "Time"
    for pod in $PODS; do
        short=$(echo "$pod" | sed 's/cilium-/c-/')
        printf " | %10s" "$short"
    done
    echo ""
    printf "  %6s" "------"
    for _ in $PODS; do printf " | %10s" "----------"; done
    echo ""
    prev_ts=""
    while IFS= read -r line; do
        ts=$(echo "$line" | awk '{print $1}')
        mem=$(echo "$line" | awk '{print $3}')
        if [ "$ts" != "$prev_ts" ] && [ -n "$prev_ts" ]; then echo ""; fi
        if [ "$ts" != "$prev_ts" ]; then
            printf "  %5ds" "$((ts - START_TS))"
            prev_ts="$ts"
        fi
        printf " | %7d Mi" "$mem"
    done < "${SAMPLE_FILE}"
    echo ""
fi

# ========================================================================
# VERDICT
# ========================================================================
DIVERGENCE="N/A"
if [ "$MIN_GROWTH" -gt 0 ]; then
    DIVERGENCE=$(awk "BEGIN { printf \"%.1f\", ${MAX_GROWTH} / ${MIN_GROWTH} }")
elif [ "$MAX_GROWTH" -gt 0 ]; then
    DIVERGENCE="inf"
fi

FAILED=false

echo ""
echo "============================================================"
echo "=== VERDICT ==="
echo "============================================================"
echo ""
echo "  Mode:                 ${MODE}"
echo "  Cilium version:       ${CILIUM_VERSION}"
echo "  Agents:               $(echo "$FINAL_DATA" | wc -l | tr -d ' ')"
echo "  CNP churn:            ${BURST_COUNT} bursts x ${BURST_SIZE} updates in ${CHURN_DURATION}s (${TOTAL_UPDATES} total)"
echo "  Layout:               ${NUM_NAMESPACES} ns x ${CNPS_PER_NS} CNPs/ns x $((PODS_PER_LABEL * 2)) pods/ns = ${TOTAL_PODS} endpoints"
echo "  CIDR entries/CNP:     ${NUM_CIDR_ENTRIES}"
echo ""
echo "  Worst agent growth:   ${MAX_GROWTH} Mi (${WORST_POD})"
echo "  Best agent growth:    ${MIN_GROWTH} Mi"
echo "  Divergence ratio:     ${DIVERGENCE}x"
echo "  Growth threshold:     ${MEMORY_GROWTH_THRESHOLD_MI} Mi"
echo "  Divergence threshold: ${DIVERGENCE_RATIO}x"
echo ""

if [ "${MAX_GROWTH}" -gt "${MEMORY_GROWTH_THRESHOLD_MI}" ]; then
    echo -e "  ${RED}FAIL: Worst agent grew by ${MAX_GROWTH} Mi (> ${MEMORY_GROWTH_THRESHOLD_MI} Mi)${NC}"
    FAILED=true
fi

if [ "$MIN_GROWTH" -gt 0 ] && [ "$(awk "BEGIN { print (${MAX_GROWTH} / ${MIN_GROWTH} > ${DIVERGENCE_RATIO}) }")" = "1" ]; then
    echo -e "  ${RED}FAIL: Agent divergence ${DIVERGENCE}x (> ${DIVERGENCE_RATIO}x) — some agents falling behind${NC}"
    FAILED=true
elif [ "$MIN_GROWTH" -eq 0 ] && [ "$MAX_GROWTH" -gt "${MEMORY_GROWTH_THRESHOLD_MI}" ]; then
    echo -e "  ${RED}FAIL: Divergence infinite — worst agent leaking while others stable${NC}"
    FAILED=true
fi

echo ""
if [ "$FAILED" = true ]; then
    echo "  The AccumulateMapChanges queue is growing faster than ConsumeMapChanges"
    echo "  can drain it, due to SelectorCache.mutex write-lock contention."
    echo ""
    echo "  Root cause: resolve.go:235 — ConsumeMapChanges uses mutex.Lock() (WRITE)"
    echo "  Fix: PR #34205 (Cilium 1.16) changes to mutex.RLock()"
    echo ""
    if [ -f "${HEAP_FILE:-}" ]; then
        echo "  Analyse the heap profile:"
        echo "    go tool pprof -top ${HEAP_FILE}"
        echo "    go tool pprof -http=:8080 ${HEAP_FILE}"
    fi
    echo ""
    if [ "$MODE" = "kind" ]; then
        warn "Run '${0} --cleanup ${CILIUM_VERSION}' to delete the cluster."
    else
        warn "Clean up test resources: kubectl delete ns -l app.kubernetes.io/part-of=cnp-churn-test"
    fi
    exit 2
else
    echo -e "  ${GREEN}PASS: No significant memory growth or divergence detected.${NC}"
    echo ""
    if [ "$MODE" = "kind" ]; then
        warn "Run '${0} --cleanup ${CILIUM_VERSION}' to delete the cluster."
    else
        warn "Clean up test resources: kubectl delete ns -l app.kubernetes.io/part-of=cnp-churn-test"
    fi
    exit 0
fi
