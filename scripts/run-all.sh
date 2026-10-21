#!/usr/bin/env bash
# run-all.sh
#
# Runs 50 simulations per scenario (S1-S6) and per topology (geant, iot, vanet).
# Each run writes to results/sN.csv (append mode).

set -euo pipefail

TOPOLOGIES=("geant" "iot" "vanet")
SCENARIOS=("s1" "s2" "s3" "s4" "s5" "s6")
RUNS=50

mkdir -p results

for topology in "${TOPOLOGIES[@]}"; do
    for scenario in "${SCENARIOS[@]}"; do
        echo "=== Running $scenario on $topology (50 runs) ==="
        for run in $(seq 0 $((RUNS - 1))); do
            case "$scenario" in
                s1)
                    ./waf --run "attack-s1-ph-tampering \
                        --topology=$topology --runId=$run --attackers=3" \
                        > /dev/null 2>&1
                    ;;
                s2)
                    ./waf --run "attack-s2-rhc-tampering \
                        --topology=$topology --runId=$run --attackers=3" \
                        > /dev/null 2>&1
                    ;;
                s3)
                    ./waf --run "attack-s3-replay \
                        --topology=$topology --runId=$run --attackers=3 --algorithm=circular" \
                        > /dev/null 2>&1
                    ./waf --run "attack-s3-replay \
                        --topology=$topology --runId=$run --attackers=3 --algorithm=legacy" \
                        > /dev/null 2>&1
                    ;;
                s4)
                    ./waf --run "attack-s4-ph-inflation \
                        --topology=$topology --runId=$run --attackers=3" \
                        > /dev/null 2>&1
                    ;;
                s5)
                    ./waf --run "attack-s5-byzantine \
                        --topology=$topology --runId=$run --attackers=5" \
                        > /dev/null 2>&1
                    ;;
                s6)
                    ./waf --run "attack-s6-hybrid \
                        --topology=$topology --runId=$run --attackers=5" \
                        > /dev/null 2>&1
                    ;;
            esac
        done
    done
done

echo "=== All simulations complete ==="
echo "Results in results/*.csv"