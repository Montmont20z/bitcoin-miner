#!/usr/bin/env bash
# Difficulty sweep: total hashes to first solution across the difficulty range.
#   bash difficulty_sweep.sh <binary> [np] ["bit list"]
set -u
BIN="${1:-./miner_new}"; NP="${2:-$(nproc)}"
BITS="${3:-12 16 20 24 26 28 30 32}"
MPIRUN="mpirun --oversubscribe"
[ "$(id -u)" -eq 0 ] && MPIRUN="$MPIRUN --allow-run-as-root"

echo "difficulty,np,hashes,seconds,rate_hs,nonce,valid,expected_2d,ratio" > difficulty_sweep.csv
printf "%-6s %16s %16s %9s %14s %8s\n" bits hashes "expected 2^d" ratio nonce time_s
prev_h=""; prev_d=""
for d in $BITS; do
  line=$($MPIRUN -np "$NP" "$BIN" --mode solve --difficulty "$d" 2>/dev/null | grep "^mpi,")
  h=$(echo "$line" | cut -d, -f5); s=$(echo "$line" | cut -d, -f6)
  n=$(echo "$line" | cut -d, -f8); v=$(echo "$line" | cut -d, -f9)
  e=$(python3 -c "print(2**$d)")
  r=$(python3 -c "print(f'{$h/$e:.3f}')")
  printf "%-6s %16s %16s %9s %14s %8s\n" "$d" "$h" "$e" "$r" "$n" "$s"
  echo "$d,$NP,$h,$s,$(python3 -c "print(f'{$h/$s:.0f}')"),$n,$v,$e,$r" >> difficulty_sweep.csv
  if [ -n "$prev_h" ]; then
    gap=$((d - prev_d))
    python3 -c "print(f'         {$prev_d}->{$d}:  expected {2**$gap:>6.0f}x   observed {$h/$prev_h:>7.2f}x')"
  fi
  prev_h=$h; prev_d=$d
done
echo; echo "-> difficulty_sweep.csv"
