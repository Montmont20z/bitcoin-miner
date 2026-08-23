#!/usr/bin/env bash
# Strong-scaling measurement with warm-up, repeat runs and median reporting.
#   bash scaling.sh <binary> [hashes] [repeats] ["np list"]
# Defaults derive the np list from the physical core count, so the knee in the
# curve (where SMT takes over from real cores) is always sampled.
set -u
BIN="${1:-./miner_new}"
HASHES="${2:-33554432}"
REPS="${3:-5}"

MPIRUN="mpirun --oversubscribe"
[ "$(id -u)" -eq 0 ] && MPIRUN="$MPIRUN --allow-run-as-root"

PHYS=$(lscpu | awk -F: '/^Core\(s\) per socket/{c=$2} /^Socket\(s\)/{s=$2} END{print c*s}' | tr -d ' ')
LOGI=$(nproc)
[ -z "$PHYS" ] && PHYS=$LOGI

if [ $# -ge 4 ]; then
  NPLIST="$4"
else
  NPLIST=""
  for i in $(seq 1 "$PHYS"); do NPLIST="$NPLIST $i"; done
  [ "$LOGI" -gt "$PHYS" ] && NPLIST="$NPLIST $LOGI"
  NPLIST="$NPLIST $((LOGI * 2))"
fi

echo "=============================================="
echo " CPU topology"
echo "=============================================="
lscpu | grep -E "^Model name|^CPU\(s\)|^Thread\(s\) per core|^Core\(s\) per socket|^Socket"
echo "  physical cores : $PHYS   <-- speedup should plateau near here"
echo "  logical CPUs   : $LOGI"
echo "  SHA-NI         : $(grep -qm1 ' sha_ni' /proc/cpuinfo && echo PRESENT || echo absent)"
echo "  np sweep       :$NPLIST"
echo "  work per run   : $HASHES hashes x $REPS repeats"
echo

echo "np,rep,seconds,rate_hs" > scaling_raw.csv

# Warm-up: first run on a cold machine is always slow (cache, clock ramp).
echo "warming up..."
$MPIRUN -np "$LOGI" "$BIN" --mode scan --hashes "$HASHES" >/dev/null 2>&1
echo

median() { printf '%s\n' "$@" | sort -n | awk '{a[NR]=$1} END{print (NR%2)?a[(NR+1)/2]:(a[NR/2]+a[NR/2+1])/2}'; }

echo "=============================================="
echo " Strong scaling  (median of $REPS runs)"
echo "=============================================="
printf "  %-4s %11s %11s %11s %12s %9s %11s\n" np median_s best_s worst_s rate_H/s speedup efficiency
BASE=""
for np in $NPLIST; do
  times=()
  for r in $(seq 1 "$REPS"); do
    line=$($MPIRUN -np "$np" "$BIN" --mode scan --hashes "$HASHES" 2>/dev/null | grep "^mpi,")
    [ -z "$line" ] && continue
    t=$(echo "$line" | cut -d, -f6)
    times+=("$t")
    echo "$np,$r,$t,$(python3 -c "print(f'{$HASHES/$t:.0f}')")" >> scaling_raw.csv
  done
  [ ${#times[@]} -eq 0 ] && { printf "  %-4s  (failed)\n" "$np"; continue; }
  med=$(median "${times[@]}")
  best=$(printf '%s\n' "${times[@]}" | sort -n | head -1)
  worst=$(printf '%s\n' "${times[@]}" | sort -n | tail -1)
  [ -z "$BASE" ] && BASE=$med
  rate=$(python3 -c "print(f'{$HASHES/$med:.0f}')")
  sp=$(python3 -c "print(f'{$BASE/$med:.3f}')")
  ef=$(python3 -c "print(f'{100*$BASE/$med/$np:.1f}%')")
  spread=$(python3 -c "print(f'{100*($worst-$best)/$med:.1f}')")
  flag=""
  [ "$np" = "$PHYS" ] && flag="  <-- all physical cores"
  [ "$(python3 -c "print(1 if $spread>15 else 0)")" = "1" ] && flag="$flag  [noisy: ${spread}% spread]"
  printf "  %-4s %11s %11s %11s %12s %8sx %11s%s\n" "$np" "$med" "$best" "$worst" "$rate" "$sp" "$ef" "$flag"
done

echo
echo "Per-repeat timings -> scaling_raw.csv"
echo
echo "How to read it:"
echo "  * speedup should rise almost linearly to np=$PHYS, then flatten."
echo "  * np>$PHYS relies on SMT and typically adds only 0-20% more throughput."
echo "  * a [noisy] flag on a laptop usually means thermal throttling --"
echo "    plug in the charger, close background apps, and re-run."
