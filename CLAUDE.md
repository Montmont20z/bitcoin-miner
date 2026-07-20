# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

This repository currently contains only a planning document — `bitcoin_mining_implementation_plan.md`. No source code, build system, or tests have been written yet. There is no git repository initialized either. Treat the plan document as the authoritative spec: when implementing, follow its architecture, file layout, and algorithmic decisions rather than improvising alternatives, since the report/assignment this project supports grades against that design.

## What the project is

A university parallel-computing assignment (course BMCS2103/BMCS3003): implement a Bitcoin-style SHA-256 proof-of-work block miner four times — a serial baseline, then parallelised with OpenMP (shared-memory CPU), CUDA (GPU), and MPI (distributed) — sharing one core library so the four backends are directly comparable. The point of the project is the parallelisation strategy and benchmark methodology, not the hashing algorithm itself (a public-domain SHA-256 implementation is meant to be a starting point, cited explicitly, not reimplemented from scratch).

## Intended architecture (from the plan — not yet built)

```
bitcoin-miner/
├── CMakeLists.txt
├── core/                        # shared by all backends
│   ├── sha256.h / sha256.cpp    # double SHA-256 (+ midstate variant)
│   ├── block.h / block.cpp      # Transaction, BlockHeader, Block
│   ├── merkle.h / merkle.cpp    # Merkle root of transactions
│   ├── difficulty.h             # target check: leading zero bits
│   └── bench.h                  # chrono timers, CSV logger
├── serial/main.cpp              # baseline miner
├── openmp/main.cpp
├── cuda/main.cu
├── mpi/main.cpp
├── viz/                         # minimal chain printer (console or ImGui)
├── scripts/run_benchmarks.sh    # difficulty sweep, repeats, CSV out
└── results/                     # raw CSVs + plots
```

CMake produces four targets: `miner_serial`, `miner_omp`, `miner_cuda`, `miner_mpi`. CUDA and MPI are optional, guarded by `find_package`, so the project builds even on machines lacking those toolchains.

### Core data model

- `Transaction { uint32_t id; std::string from, to; double amount; }` — generated once, serially, *before* mining starts. Never call `rand()`/`std::rand()` inside a parallel region (not thread-safe); use `<random>` (`std::mt19937`) seeded from a CLI flag for reproducibility.
- `BlockHeader` mirrors Bitcoin's real 80-byte layout: `version` (4B), `prev_hash` (32B, SHA-256d of previous header), `merkle_root` (32B), `timestamp` (4B), `bits` (4B, stores difficulty `k` directly rather than Bitcoin's compact encoding), `nonce` (4B — the search variable).
- Merkle root: pairwise double-SHA-256 up the tree, duplicating the last node on odd levels (Bitcoin convention).
- Difficulty check: count leading zero **bits** (not hex digits) of the 32-byte digest; expected work is `~2^k` per block, giving a fine-grained workload knob.

### SHA-256 core requirements

- Double SHA-256 (`SHA256(SHA256(x))`), `sha256d_80(const uint8_t header[80], uint8_t out[32])` fast path.
- Must compile as both plain C++ and CUDA device code (`__host__ __device__` guarded by `#ifdef __CUDACC__`) so CPU and GPU share one verified code path — do not fork the implementation per backend.
- Midstate optimization (extra-effort item): the first 64 bytes of the 80-byte header are constant while only the nonce varies, so the internal state after the first compression block can be precomputed once per block; each nonce attempt then only runs the final chunk + second hash.
- Validate against FIPS 180-4 test vectors *and* a real Bitcoin block header (e.g. block 125552) before any parallel work starts — a SHA-256 bug produces wrong hashes silently and would invalidate every subsequent benchmark.

### Per-backend decomposition strategy

- **Serial**: linear nonce scan; two timing modes are required everywhere — *solve mode* (time to first valid nonce; noisy) and *scan mode* (hash a fixed range regardless of hits; deterministic, benchmark-grade — this is the primary metric, see below).
- **OpenMP**: `#pragma omp parallel` with manual thread-id striding (`nonce = tid; nonce += nthreads`) rather than `parallel for`, because early termination requires breaking out of a work-shared loop, which OpenMP forbids. Use a shared `std::atomic<bool> found` flag checked each iteration (or batched every ~1024 iterations — the batching interval itself is a benchmark variable for atomic-load overhead).
- **CUDA**: grid-stride loop (`g = blockIdx.x*blockDim.x + threadIdx.x`), header copied once to `__constant__` memory. Early termination via a device-side flag polled with a relaxed read, set via `atomicExch`. Always check `cudaGetLastError()` after kernel launch — exceeding thread limits fails silently. Register pressure from SHA-256's 64-entry message schedule constrains occupancy; inspect with `--ptxas-options=-v`.
- **MPI**: coarse-grained contiguous ranges per rank (`[i·N/P, (i+1)·N/P)`), not interleaved, to keep messages rare. Header broadcast via `MPI_Bcast`. Early termination is the hard part: ranks poll for a stop message every M iterations with non-blocking `MPI_Iprobe`; the finder relays via point-to-point sends rather than a collective (collectives require every rank to participate, which conflicts with "everyone is busy mining" — a naive `MPI_Bcast`-based stop signal will deadlock).

## Benchmark methodology (load-bearing for the report — don't deviate casually)

- **Never use single-run solve time as speedup evidence** — time-to-solve is geometrically distributed and two identical runs can differ by 10×.
- **Primary metric: hash rate (MH/s)** via scan mode over a fixed range (e.g. `N = 2^28` CPU, `2^32` GPU), median of 5 runs. Speedup `S = rate_parallel / rate_serial`, efficiency `E = S / workers`.
- **Secondary metric: solve time**, mean ± stddev over ≥20 mined blocks per configuration, at difficulties `k ∈ {16, 20, 24, 28}`.
- Controls: fixed RNG seed (identical header across configurations), Release builds only (`-O2`; `-O0` benchmarks are meaningless), machine specs documented (CPU, GPU, RAM, OS, compiler versions).
- Every run appends a CSV row: `backend, workers, difficulty, mode, hashes, seconds, rate`. A `scripts/` plotting script (Python/matplotlib) turns these into the report figures.

## Team/task split

One parallel paradigm per member (A: OpenMP, B: CUDA, C: MPI), sharing the core library, serial baseline, bench harness, and viz. See §11 of the plan for the full task table if reconstructing scope ownership.
