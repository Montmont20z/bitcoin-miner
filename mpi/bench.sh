#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# BMCS3003 MPI benchmark — runs every experiment section 2.2.3 promises.
# Usage:  bash bench.sh <old_mpi_main.cpp> <new_mpi_main.cpp>
# Output: results.csv  (one tidy table, ready for Excel / matplotlib)
# ---------------------------------------------------------------------------
set -u
OLD_SRC="${1:-mpi_main_old.cpp}"
NEW_SRC="${2:-mpi_main_lean.cpp}"
OUT="results.csv"
SCAN_HASHES="${SCAN_HASHES:-134217728}"  # the value used for every figure in the report
SOLVE_DIFF="${SOLVE_DIFF:-24}"          # 24 -> nonce 12071324, 12,071,325 hashes
case "$SOLVE_DIFF" in
  20) EXPECT_NONCE=755468 ;;   22) EXPECT_NONCE=3999586 ;;
  23|24|25) EXPECT_NONCE=12071324 ;;  26|27) EXPECT_NONCE=78891794 ;;
  28|29) EXPECT_NONCE=344220420 ;;    30) EXPECT_NONCE=361230273 ;;
  *) EXPECT_NONCE="?" ;;
esac

MPIRUN="mpirun --oversubscribe"
[ "$(id -u)" -eq 0 ] && MPIRUN="$MPIRUN --allow-run-as-root"
CORES=$(nproc)

echo "=============================================="
echo " Machine specification"
echo "=============================================="
lscpu | grep -E "^Model name|^CPU\(s\)|^Thread|^Core|^Socket|^CPU max MHz" || true
echo "SHA-NI: $(grep -o -m1 sha_ni /proc/cpuinfo || echo 'not present')"
free -h | head -2
echo "OS:       $(. /etc/os-release; echo "$PRETTY_NAME") / kernel $(uname -r)"
echo "Compiler: $(g++ --version | head -1)"
echo "MPI:      $(ompi_info --version 2>/dev/null | head -1 || mpirun --version 2>/dev/null | head -1)"
command -v nvidia-smi >/dev/null && nvidia-smi --query-gpu=name,memory.total --format=csv,noheader
echo

echo "Compiling..."
CORE="${CORE:-../core}"
mpic++ -O3 -march=native -I"$CORE" -std=c++17 "$OLD_SRC" "$CORE/sha256.cpp" -o miner_old
mpic++ -O3 -march=native -I"$CORE" -std=c++17 "$NEW_SRC" "$CORE/sha256.cpp" -o miner_new
echo "  ok"; echo

echo "experiment,midstate,decomp,np,difficulty,poll,hashes,seconds,rate_hs,nonce,valid,wasted" > "$OUT"

# grab the "mpi,..." csv line a run prints
run() { $MPIRUN -np "$1" "${@:2}" 2>/dev/null; }
field() { echo "$1" | cut -d, -f"$2"; }

# --- A. correctness: every configuration must return the same nonce ---------
echo "=============================================="
echo " A. Correctness  (all must return $EXPECT_NONCE)"
echo "=============================================="
FAIL=0
for np in 1 2 4; do
  for d in strided block; do
    line=$(run $np ./miner_new --mode solve --difficulty $SOLVE_DIFF --decomp $d | grep "^mpi,")
    n=$(field "$line" 8)
    if [ "$d" = strided ] && [ "$n" != "$EXPECT_NONCE" ]; then FAIL=1; fi
    printf "  np=%-2s %-8s nonce=%-12s %s\n" "$np" "$d" "$n" \
      "$([ "$n" = "$EXPECT_NONCE" ] && echo OK || echo DIFFERS)"
  done
done
[ $FAIL -eq 1 ] && echo "  !! strided returned a wrong nonce — stop and investigate"
echo

# --- B. strong scaling, fixed work (the speedup table) ---------------------
echo "=============================================="
echo " B. Strong scaling  (--mode scan, fixed work)"
echo "=============================================="
printf "  %-9s %-4s %14s %10s %8s %10s\n" midstate np rate_H/s seconds speedup efficiency
for ms in off on; do
  bin=./miner_old; [ "$ms" = on ] && bin=./miner_new
  base=""
  for np in 1 2 4 8; do
    [ "$np" -gt $((CORES * 4)) ] && continue
    line=$(run $np $bin --mode scan --hashes $SCAN_HASHES | grep "^mpi,")
    sec=$(field "$line" 6); hs=$(field "$line" 5)
    rate=$(python3 -c "print(f'{$hs/$sec:.0f}')")
    [ -z "$base" ] && base=$sec
    sp=$(python3 -c "print(f'{$base/$sec:.3f}')")
    ef=$(python3 -c "print(f'{100*$base/$sec/$np:.1f}%')")
    printf "  %-9s %-4s %14s %10s %8s %10s\n" "$ms" "$np" "$rate" "$sec" "${sp}x" "$ef"
    echo "scaling,$ms,strided,$np,-,-,$hs,$sec,$rate,,," >> "$OUT"
  done
done
echo

# --- C. polling interval vs wasted post-solution hashes --------------------
echo "=============================================="
echo " C. Polling interval  (np=$CORES, difficulty $SOLVE_DIFF)"
echo "=============================================="
printf "  %-8s %14s %12s %10s\n" poll total_hashes wasted "wasted%"
for p in 1 256 1024 4096 65536; do
  out=$(run $CORES ./miner_new --mode solve --difficulty $SOLVE_DIFF --poll $p)
  m=$(echo "$out" | grep "^mpi,"); w=$(echo "$out" | grep "^wasted,")
  printf "  %-8s %14s %12s %9s%%\n" "$p" "$(field "$w" 5)" "$(field "$w" 6)" "$(field "$w" 7)"
  echo "polling,on,strided,$CORES,$SOLVE_DIFF,$p,$(field "$m" 5),$(field "$m" 6),,$(field "$m" 8),$(field "$m" 9),$(field "$w" 6)" >> "$OUT"
done
echo

# --- D. decomposition strategy --------------------------------------------
echo "=============================================="
echo " D. Decomposition  (--mode solve, difficulty $SOLVE_DIFF)"
echo "=============================================="
printf "  %-8s %-4s %-12s %10s %14s\n" decomp np nonce seconds hashes
for d in strided block; do
  for np in 1 2 4; do
    line=$(run $np ./miner_new --mode solve --difficulty $SOLVE_DIFF --decomp $d | grep "^mpi,")
    printf "  %-8s %-4s %-12s %10s %14s\n" "$d" "$np" "$(field "$line" 8)" "$(field "$line" 6)" "$(field "$line" 5)"
    echo "decomp,on,$d,$np,$SOLVE_DIFF,-,$(field "$line" 5),$(field "$line" 6),,$(field "$line" 8),$(field "$line" 9)," >> "$OUT"
  done
done
echo

# --- E. midstate before / after, time-to-solution --------------------------
echo "=============================================="
echo " E. Midstate off vs on  (np=$CORES)"
echo "=============================================="
printf "  %-9s %-6s %10s %14s %14s\n" midstate bits seconds hashes rate_H/s
for bits in ${MIDSTATE_BITS:-20 24 26}; do
  for ms in off on; do
    bin=./miner_old; [ "$ms" = on ] && bin=./miner_new
    line=$(run $CORES $bin --mode solve --difficulty $bits | grep "^mpi,")
    sec=$(field "$line" 6); hs=$(field "$line" 5)
    rate=$(python3 -c "print(f'{$hs/$sec:.0f}')")
    printf "  %-9s %-6s %10s %14s %14s\n" "$ms" "$bits" "$sec" "$hs" "$rate"
    echo "midstate,$ms,-,$CORES,$bits,-,$hs,$sec,$rate,$(field "$line" 8),$(field "$line" 9)," >> "$OUT"
  done
done

echo
echo "=============================================="
echo " Done -> $OUT"
echo "=============================================="
