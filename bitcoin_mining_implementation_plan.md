# Implementation Plan — Parallel Bitcoin Block Mining (SHA-256 Proof-of-Work)

**Course:** BMCS2103/BMCS3003 Distributed Systems and Parallel Computing
**Proposed title:** *Accelerating SHA-256 Proof-of-Work Block Mining Using OpenMP, CUDA and MPI*
**Team size:** 3 (one parallel paradigm per member, shared core)

---

## 1. Problem statement (for the proposal)

Bitcoin mining is a brute-force search: given an 80-byte block header, find a 32-bit nonce such that `SHA256(SHA256(header))` is below a difficulty target (equivalently, has *k* leading zero bits). A single SHA-256 invocation cannot be parallelised — the Merkle–Damgård construction makes each compression round depend on the previous one — but the search *across* nonces is embarrassingly parallel: every nonce can be tested independently. The project implements a serial miner as the baseline, then parallelises the nonce search on three platforms: shared-memory CPU (OpenMP), GPU (CUDA), and a distributed cluster (MPI), and evaluates speedup, efficiency, and scaling behaviour against difficulty.

This framing satisfies the assignment's "computationally expensive problem" requirement and gives the literature review its comparison axis (intra-hash parallelism: impossible; inter-nonce parallelism: ideal).

---

## 2. System architecture

One shared core library + four executables. All backends consume the same core so results are directly comparable.

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
├── openmp/main.cpp              # Member A
├── cuda/main.cu                 # Member B
├── mpi/main.cpp                 # Member C
├── viz/                         # minimal chain printer (console or ImGui)
├── scripts/run_benchmarks.sh    # difficulty sweep, repeats, CSV out
└── results/                     # raw CSVs + plots
```

CMake produces `miner_serial`, `miner_omp`, `miner_cuda`, `miner_mpi`. CUDA and MPI targets are optional (guarded by `find_package`) so every member can build on their own machine.

---

## 3. Data model
Description of the data structure of a single block.
Relationship: 
```TxIn, TxOut -> TxIns, TxOuts -> Transaction -> BlockHeader, Transactions -> Full Block```
### **Full Block**
| Field | Size | Data Type |
|---|---|---|
| Magic bytes (network only, not in serialized block) | 4 bytes | uint32 |
| Block size | 4 bytes | uint32 (little-endian) |
| **Block Header** | 80 bytes | (see below) |
| Transaction counter | 1–9 bytes | VarInt |
| Transactions | variable | array of Transaction structs |

### **BlockHeader** 

| Field | Size | Data Type | Notes |
|---|---|---|---|
| Version | 4 bytes | int32 (signed) | Bit flags signaling soft-fork support (BIP9) |
| Previous Block Hash | 32 bytes | char[32] / uint256 | SHA-256d of prior header, stored little-endian |
| Merkle Root | 32 bytes | char[32] / uint256 | Root of the transaction merkle tree |
| Timestamp | 4 bytes | uint32 | Unix epoch seconds |
| Bits (nBits) | 4 bytes | uint32 | Compact-format encoding of the target threshold |
| Nonce | 4 bytes | uint32 | The value miners increment (0 → 4,294,967,295) — this is your parallelizable search space |

**Merkle root** — pairwise double-SHA-256 up the tree, duplicating the last node on odd levels (Bitcoin convention). Serial is fine for correctness; parallelising tree levels with OpenMP is an optional extra-effort item.

**Difficulty check** — count leading zero **bits** (not hex digits) of the 32-byte digest. Expected work doubles per bit, giving a fine-grained workload knob: `expected_hashes ≈ 2^k`.

### Transaction structure (each entry in the block body)

| Field | Size | Data Type | Notes |
|---|---|---|---|
| Version | 4 bytes | int32 | |
| Marker + Flag (SegWit only) | 2 bytes | uint8, uint8 | `0x00 0x01` if witness data present |
| Input count | 1–9 bytes | VarInt | |
| Inputs | variable | array of TxIn | each: 32-byte prev txid, 4-byte output index, VarInt+script sig, 4-byte sequence |
| Output count | 1–9 bytes | VarInt | |
| Outputs | variable | array of TxOut | each: 8-byte int64 value (satoshis), VarInt+scriptPubKey |
| Witness data (SegWit only) | variable | array of witness stacks | one stack per input |
| Locktime | 4 bytes | uint32 | |


### VarInt encoding (used throughout)

| Prefix byte | Meaning |
|---|---|
| `< 0xFD` | value is the byte itself |
| `0xFD` | next 2 bytes = uint16 |
| `0xFE` | next 4 bytes = uint32 |
| `0xFF` | next 8 bytes = uint64 |

---

## 4. SHA-256 core

Implement double SHA-256 (`SHA256(SHA256(x))`) from the FIPS 180-4 specification, starting from a public-domain reference implementation (e.g. Brad Conte's) — **cite it explicitly in the report**; the parallelisation, not the hash, is the group's contribution. Requirements on the implementation:

1. Header-only or `.h/.cpp` pair compilable as both C++ and CUDA (`__host__ __device__` guarded by `#ifdef __CUDACC__`) so CPU and GPU share one verified code path.
2. A `sha256d_80(const uint8_t header[80], uint8_t out[32])` fast path.
3. **Midstate variant (extra-effort item):** the first 64 bytes of the header are constant while the nonce varies; precompute the internal state after the first compression block once per block, then each nonce attempt runs only the final chunk + the second hash — roughly halving work in hash #1. Benchmark with/without; this is the "revisit and improve" requirement of Part B and a genuine locality/ILP discussion.

**Validation:** unit-test against known SHA-256 vectors (FIPS test vectors, plus a real Bitcoin block header, e.g. block 125552, whose winning hash is public). All four miners must produce *a* valid hash for the same header at the same difficulty; the winning nonce may legitimately differ between backends — document why (search order differs; any nonce below target is correct).

---

## 5. Serial baseline

```
for nonce = 0 .. 2^32-1:
    header.nonce = nonce
    h = sha256d_80(header)
    if leading_zero_bits(h) >= k: return nonce
```

Two timing modes (both needed — see §9):
- **solve mode:** time until first valid nonce (demo-friendly, statistically noisy).
- **scan mode:** hash the *entire* fixed range `[0, N)` regardless of hits, report hashes/second (benchmark-grade, deterministic work).

---

## 6. OpenMP miner (Member A)

**Decomposition:** `#pragma omp parallel for schedule(static)` over the nonce range; static schedule because per-iteration cost is uniform. Alternatively per-thread strided loops (`nonce = tid; nonce += nthreads`) — benchmark both, discuss why they're near-identical here (uniform work) versus the matmul case.

**Early termination:** OpenMP forbids `break` out of a work-shared loop. Use a shared flag:

```cpp
std::atomic<bool> found{false};
std::atomic<uint32_t> winning{0};
#pragma omp parallel
{
    int tid = omp_get_thread_num(), T = omp_get_num_threads();
    for (uint64_t n = tid; n < RANGE && !found.load(std::memory_order_relaxed); n += T) {
        if (test_nonce(n)) {
            found.store(true, std::memory_order_relaxed);
            winning.store((uint32_t)n);
        }
    }
}
```

Check the flag every iteration vs every 1024 iterations (batched check) and measure the overhead of the atomic load — a concrete synchronisation-cost experiment for the report.

**Experiments:** thread count sweep 1→physical cores→logical cores (hyper-threading discussion), scan-mode hash rate, speedup & efficiency curves, static vs strided decomposition.

---

## 7. CUDA miner (Member B)

**Decomposition:** grid-stride loop; thread `g = blockIdx.x*blockDim.x + threadIdx.x` tests nonces `g, g+gridStride, …`. Header (80 B) copied to `__constant__` memory once per block — data transfer is negligible, which is why mining is a near-ideal GPU workload (contrast with the linear-regression example, where transfer mattered).

**Early termination:** a device-side `int *d_found` flag; each thread polls it (relaxed read) at the top of its stride loop and the finder sets it with `atomicExch`, writing the winning nonce to `d_nonce`. Host copies results back after kernel completion. Optionally chunk the range into multiple kernel launches so the host can stop early between launches — discuss the trade-off (launch overhead vs wasted work).

**Configuration experiments (RTX 3070):** block size sweep {128, 256, 512, 1024} threads; grid sized to saturate SMs (46 SMs on GA104 — cover occupancy). Reuse lessons from the CUDA coursework: silent launch failures on exceeding thread limits → always `cudaGetLastError()` after launch. Registers per thread will constrain occupancy since SHA-256 keeps a 64-entry message schedule; measure with `--ptxas-options=-v` and discuss — this is exactly the "conditionality" nuance the rubric's Excellent band wants.

**Experiments:** hash rate vs block size, GPU vs best CPU result, midstate on/off, occupancy analysis.

---

## 8. MPI miner (Member C)

**Decomposition:** coarse-grained. Rank *i* of *P* gets contiguous range `[i·N/P, (i+1)·N/P)` — contiguous, not interleaved, to keep messages rare. Rank 0 broadcasts the header (`MPI_Bcast`), all ranks search locally (optionally hybrid MPI+OpenMP inside each rank — a strong extra-effort item).

**Early termination (the interesting part):** a finder must stop all other ranks.
- Each rank checks for a termination message every M iterations with `MPI_Iprobe` (non-blocking).
- The finder sends the winning nonce to rank 0; rank 0 relays a stop message to all ranks (or the finder broadcasts directly with point-to-point sends to avoid a collective deadlock — collectives require all ranks to participate, which conflicts with "everyone is busy mining").
- Report discussion: check frequency M trades responsiveness (wasted hashes after solve) against probe overhead; measure both.

**Test environments:** single machine with multiple ranks (correctness + oversubscription discussion), then 2–3 lab PCs or laptops over LAN with a hostfile for the genuine distributed result. If cluster access is uncertain, results on one multi-core node with `-np {1,2,4,8}` are still acceptable — but flag the shared-memory caveat honestly in Discussion.

**Experiments:** rank count sweep, wasted-work measurement (total hashes across ranks ÷ expected 2^k), M sweep, optional hybrid MPI+OpenMP.

---

## 9. Benchmark methodology (write this into the proposal — it is the marks-heavy section)

**The statistical trap:** time-to-solve is geometrically distributed; two identical runs can differ by 10×. Never report single-run solve times as speedup evidence.

**Primary metric — hash rate (MH/s):** scan mode over a fixed range (e.g. `N = 2^28` on CPU, `2^32` on GPU), median of 5 runs. Fixed work → deterministic → clean speedup: `S = rate_parallel / rate_serial`, efficiency `E = S / workers`.

**Secondary metric — solve time:** mean over ≥20 mined blocks per configuration, reported with standard deviation, at difficulties k ∈ {16, 20, 24, 28} zero bits. Demonstrates the end-to-end system and lets you show the variance phenomenon itself (a good Discussion figure).

**Controls:** identical header per configuration (fixed RNG seed), Release builds (`-O2`; document that `-O0` benchmarks are meaningless), pinned CPU frequency where possible, machine specs table (CPU model/cores, RTX 3070, RAM, OS, compiler versions).

**Output:** every run appends a CSV row (`backend, workers, difficulty, mode, hashes, seconds, rate`); a Python/matplotlib script in `scripts/` generates the report figures (speedup curves, efficiency, rate vs difficulty, CUDA block-size sweep).

---

## 10. Visualization (keep it cheap — zero rubric weight)

Console (or minimal ImGui, matching the example report's style) block printout after each mined block:

```
┌─ Block #3 ─────────────────────────────────────┐
│ prev: 0000a1f3…            nonce: 8,144,022    │
│ merkle: 9c2e…              difficulty: 20 bits │
│ hash: 00000d7b…            3 transactions      │
└────────────────────────────────────────────────┘
        ▲ linked by prev_hash
```

Chain of 3–5 blocks with arrows is enough to show the blockchain linkage. Time-box: one afternoon.

---

## 11. Task allocation (Part A requirement)

| Member | Individual scope | Shared duties |
|--------|------------------|---------------|
| A | OpenMP miner, thread-count & scheduling experiments, atomic-flag overhead study | Serial baseline + `bench.h`; report §OpenMP |
| B | CUDA miner, block-size/occupancy study, midstate optimization | SHA-256 core + unit tests; report §CUDA |
| C | MPI miner, termination-protocol study, LAN deployment | Block/Merkle/difficulty core, viz, CSV+plots; report §MPI |
| All | — | Proposal writing, integrated Results & Discussion, presentation demo |

---

## 12. Timeline (mapped to deadlines)

| Week | Milestone |
|------|-----------|
| 1–2 | Literature review (Nakamoto 2008; FIPS 180-4; a GPU SHA-256 paper e.g. hashcat/CUDA crypto literature; parallel search / early-exit patterns). Confirm unique title with tutor. |
| 3 | **Part A proposal drafted & submitted (Week 4 deadline):** problem statement, algorithm comparison (intra-hash vs inter-nonce parallelism), methodology per §6–9, task table, Gantt chart, Harvard references incl. ≥1 journal. |
| 4–5 | Core library: SHA-256 + test vectors, block/Merkle/difficulty, serial miner, CSV bench harness. |
| 6 | OpenMP miner working + first speedup numbers (validates the whole methodology early). |
| 7–8 | CUDA miner; MPI miner (single-node ranks first, then LAN). |
| 9 | Midstate optimization; hybrid MPI+OpenMP if time; full benchmark sweep on frozen code. |
| 10 | Plots, Results & Discussion writing; visualization polish. |
| 11 | **Part B final report submitted;** demo rehearsal for Week 12/13 assessment (prepare Q&A: why atomics, why grid-stride, why contiguous MPI ranges, why hash rate not solve time). |

---

## 13. Risks & mitigations

1. **Noisy speedups** → scan-mode hash rate as primary metric (§9); decided upfront, not after bad data.
2. **No multi-machine access for MPI** → multi-rank single-node results acceptable; state the caveat; try 2 laptops over hotspot LAN as backup.
3. **CUDA register pressure kills occupancy** → measure with `-ptxas-options=-v`, discuss rather than hide; try `__launch_bounds__`.
4. **SHA-256 bug produces wrong hashes silently** → FIPS test vectors + a real Bitcoin block header in CI-style unit tests before any parallel work starts.
5. **Duplicate topic with another group** → register title in Week 1.
6. **Plagiarism exposure on the reference SHA-256** → cite the source implementation in both code comments and the reference list; keep the git history showing the group's parallelisation work.

---

## 14. Reference seed list (expand to Harvard format)

- Nakamoto, S. (2008). *Bitcoin: A Peer-to-Peer Electronic Cash System.*
- NIST (2015). *FIPS PUB 180-4: Secure Hash Standard.*
- A peer-reviewed paper on GPU-accelerated SHA-256 / password hashing (satisfies the "at least one journal" rubric line).
- Harris, M. *Optimizing Parallel Reduction in CUDA* (already familiar from the example report; relevant to occupancy discussion).
- OpenMP 5.x specification; MPI standard documentation.
