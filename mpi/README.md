# MPI Bitcoin Block Mining (SHA-256 Proof-of-Work)
---

## Build

SHA-256 is implemented from scratch in `../core/` -- no crypto library is
linked. Both the header path and `core/sha256.cpp` are required:

```bash
mpic++ -O3 -march=native -I../core -std=c++17 -o miner_new \
       mpi_main.cpp ../core/sha256.cpp

mpic++ -O3 -march=native -I../core -std=c++17 -o miner_old \
       mpi_main_baseline.cpp ../core/sha256.cpp
```

Requires an MPI implementation only:

```bash
sudo apt install build-essential openmpi-bin libopenmpi-dev
```

Verify the build links no crypto library and still finds the known nonce:

```bash
ldd miner_new | grep -c crypto                          # must print 0
mpirun -np 1 ./miner_new --mode solve --difficulty 20   # Nonce: 755468
mpirun -np 1 ./miner_old --mode solve --difficulty 20   # Nonce: 755468
```

`mpi_main_baseline.cpp` is the pre-optimisation version used as the "midstate off"
reference in Section 4.7.3 of the report. Build it the same way.

Compiled binaries are deliberately not committed — they are linked against one specific
MPI build and will not run elsewhere. `.gitignore` excludes them; rebuild from source
with the command above.

---

## Run

```
Usage:
  miner --mode scan  [--hashes N] [--difficulty K]
  miner --mode solve [--max-nonce N] [--difficulty K] [--poll N] [--decomp strided|block]

Options:
  --mode scan|solve   Fixed-work benchmark, or early-exit mining
  --difficulty K      Required leading zero bits (default: 20)
  --hashes N          Total hashes in scan mode (default: 16777216)
  --max-nonce N       Largest nonce in solve mode (default: 4294967295)
  --poll N            Hashes between MPI message checks (default: 1024)
  --decomp strided|block
                      Nonce-space decomposition (default: strided)
  --csv-header        Print a CSV header before the result row
```

Two examples:

```bash
# Fixed-work throughput benchmark — the basis for all speedup figures
mpirun -np 4 ./miner --mode scan --hashes 134217728

# Mine until a nonce with 26 leading zero bits is found
mpirun -np 4 ./miner --mode solve --difficulty 26
```

On a machine where you are root (Google Colab, for instance) add
`--allow-run-as-root`. To run more processes than cores, add `--oversubscribe`.

---

## Reproducing the report

Each script writes a CSV; `data/` holds the output of the runs used in the report.

| Script | Produces | Used by |
|---|---|---|
| `bench.sh <baseline.cpp> <optimised.cpp>` | `results.csv` | correctness, scaling, polling, decomposition, midstate |
| `scaling.sh <binary> [hashes] [repeats]` | `scaling_raw.csv` | strong-scaling table, median of 5 |
| `difficulty_sweep.sh <binary> [np] ["bits"]` | `difficulty_sweep.csv` | hashes-to-solution vs difficulty |
| `make_figures.py` | `fig1`–`fig6` PNG | see the figure map below |

```bash
bash bench.sh mpi_main_baseline.cpp mpi_main.cpp | tee bench_log.txt
bash scaling.sh ./miner 134217728 5 | tee scaling.txt
bash difficulty_sweep.sh ./miner 1
python3 make_figures.py
```

`make_figures.py` reads the CSVs from `data/` and regenerates all six PNGs
byte-for-byte identical to the copies used in the report — no manual editing was applied
to any figure.

| PNG | Where it appears |
|---|---|
| `fig1_scaling.png` | Figure 4.5.1 in the report |
| `fig3_polling.png` | Figure 4.5.2 in the report |
| `fig4_midstate.png` | Section 4.7.3 in the report |
| `fig2_throughput.png` | supplementary — hash rate by process count, both platforms |
| `fig5_difficulty.png` | supplementary — the data behind Tables 4.5.4a/b, plotted |
| `fig6_decomposition.png` | supplementary — schematic of Table 4.5.3 |

The last three are not printed in the report; the same results are given there as tables.
They are kept here because they are produced from the committed CSVs by the same script.

`bench.sh` defaults to 134,217,728 hashes per scan, the value every reported figure was
measured at. Override with `SCAN_HASHES=... bash bench.sh ...` for a quicker smoke test.

`scaling.sh` runs each configuration five times after a warm-up and reports the median,
flagging any configuration whose best-to-worst spread exceeds 15% — on a laptop that
usually means thermal throttling rather than a real result.

Two notes on reading the archived logs:

* The `MPI:` line in `data/bench_log_pc.txt` is blank. `mpirun --version` aborts on
  Open MPI 5.x (a missing PRRTE help file); `bench.sh` now probes `ompi_info --version`
  instead. The laptop's version is Open MPI 5.0.10, as recorded in the table below.
* In the midstate experiment the baseline binary has no `--decomp` flag and always uses
  block decomposition, so it returns a **different** nonce (2,684,683,923) from the
  optimised binary. Its time-to-solution is therefore not comparable with the optimised
  one; only the `rate_hs` column is. Every speedup quoted in the report comes from
  `--mode scan`, where both binaries do exactly the same fixed work.

---

## Data

| File | Platform | Contents |
|---|---|---|
| `data/scaling_raw_pc.csv` | Laptop | 30 timed runs, np = 1/2/3/4/8/16 |
| `data/scaling_raw_colab.csv` | Colab | 15 timed runs, np = 1/2/4 |
| `data/results_pc.csv` | Laptop | scaling, polling, decomposition, midstate |
| `data/results_colab.csv` | Colab | same experiment set |
| `data/bench_log_pc.txt` | Laptop | full console output including machine spec |
| `data/bench_log_colab.txt` | Colab | full console output including machine spec |
| `data/difficulty_sweep.csv` | Laptop | hashes to first solution per difficulty |
| `data/first_hit_ground_truth.csv` | — | exhaustive enumeration of the 2^32 space |

`first_hit_ground_truth.csv` was produced by an offline sweep of every nonce for this fixed
header and gives, for each difficulty, the smallest satisfying nonce. It is the reference the
correctness checks in Section 4.5.3 compare against. The best nonce that exists anywhere in
the space is 1,264,605,058 at 33 leading zero bits; no solution exists at 34 bits or above,
which is why exhaustive runs at higher difficulties report no result.

---

## Test platforms

| | Platform A | Platform B |
|---|---|---|
| CPU | Intel Xeon @ 2.00GHz (Google Colab) | Intel Core i5-1135G7 @ 2.40GHz |
| Physical cores | 1 | 4 |
| Logical CPUs | 2 | 8 |
| Intel SHA Extensions | absent | present |
| OS | Ubuntu 22.04.5 | Ubuntu 26.04 (WSL2) |
| Compiler | GCC 11.4.0 | GCC 15.2.0 |
| Open MPI | 4.1.2 | 5.0.10 |

Speedup is always computed against a baseline measured on the same platform. Throughput in
hashes per second is the only quantity compared across platforms.
