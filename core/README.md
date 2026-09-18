# core/ — 共用的自写 SHA-256

**不使用任何 crypto library。** serial / OpenMP / MPI 三个 backend 共用同一份实现，
所以三者的结果可以直接互相比较。CUDA backend 有自己的 device 版（已验证正确，不需要改动）。

```
core/
├── sha256.h          <- 介面 + hot path（inline）
├── sha256.cpp        <- cold path（一次性的 setup / 测试 / 格式化）
├── sha256_test.cpp   <- 验证程式（唯一会 link OpenSSL 的档案，只当裁判）
└── README.md
```

## 为什么 hot path 放在 .h

`transform()`、`Midstate::hash_words()`、`hash()`、`sha256d_80()` 这四个是挖矿迴圈里
每个 nonce 都会跑的，放在 `.cpp` 会因为跨档案无法 inline 而变慢。本机实测（8,388,608 hashes）：

| 做法 | 吞吐量 | 相对 |
|---|---|---|
| 全部 inline 在 .h | 2.16 MH/s | 基准 |
| 全部搬进 .cpp（无 LTO） | 1.85 MH/s | **−14%** |
| 全部搬进 .cpp + `-flto` | 1.91 MH/s | −11% |
| **现在这样（hot 在 .h，cold 在 .cpp）** | **2.19 MH/s** | **0%** |

放在 `.cpp` 的都是每次执行只跑一两次的东西：`sha256(std::string)`、
`leading_zero_bits()`、`to_hex()`、`self_test()`、`verify_midstate()`。

## 编译

```bash
# 从 repo 根目录
g++    -O3 -march=native -Icore           -o serial/miner    serial/main.cpp           core/sha256.cpp
g++    -O3 -march=native -Icore -fopenmp  -o openmp/miner    openmp/main.cpp           core/sha256.cpp
mpic++ -O3 -march=native -Icore -std=c++17 -o mpi/miner_new  mpi/mpi_main.cpp          core/sha256.cpp
mpic++ -O3 -march=native -Icore -std=c++17 -o mpi/miner_old  mpi/mpi_main_baseline.cpp core/sha256.cpp
```

**两件事**：每条编译指令都要 (1) 加 `-Icore`，(2) 把 `core/sha256.cpp` 一起丢进去。
漏掉第二项会出现 `undefined reference to sha2::self_test`。

不需要 `-lcrypto`。验证：

```bash
ldd serial/miner | grep -c crypto     # 四个 binary 都要是 0
```

## 验证

```bash
g++ -O2 -Icore -o core/sha256_test core/sha256_test.cpp core/sha256.cpp -lcrypto
./core/sha256_test
```

只有这支程式会 link OpenSSL，纯粹拿来当独立裁判。四个 miner 都不 link 它。
四个 miner 一开机也会自己跑一次 FIPS 向量，不过就不会开始挖矿。

实测输出：

```
=== 1. FIPS 180-4 official test vectors ===
  FIPS vector 1 PASS
  FIPS vector 2 PASS
  FIPS vector 3 PASS
=== 2. vs OpenSSL, messages of length 0..200 ===
  PASS (0/201 lengths differ)
=== 3. double SHA-256 of the project header, vs OpenSSL ===
  midstate OFF : PASS (0/100000 differ)
  midstate ON  : PASS (0/100000 differ)
=== 4. edge nonces (0, 2^31, 2^32-1, ...) ===
  midstate vs plain: 12/12 nonces agree
=== 5. header digest at nonce=0 ===
  6b32a4f50fa6064c1145cd32674ba3b331f2d0a3b969bda37175280da2bdcdfb
ALL CHECKS PASSED
```

## 端到端一致性（已实测）

| difficulty | serial | OpenMP | MPI baseline | MPI optimized |
|---|---|---|---|---|
| 20 | 755468 | 755468 | 755468 | 755468 |
| 24 | 12071324 | 12071324 | 12071324 | 12071324 |
| 26 | — | — | — | 78891794 |

nonce 跟机器、跟 thread / process 数量无关。**任何人改动 core 之后，这些数字必须不变。**

> MPI baseline 在 np≥2、difficulty 24 会回传 `2150369093`。这不是 bug：baseline 只有
> block decomposition，rank 1 从 2^31 开始，先撞到自己那一段里的解。
> optimized 加 `--decomp block` 会得到同一个数字，可以互相对照。

## API

```cpp
namespace sha2 {
    // hot path（inline 在 sha256.h）
    void transform(const uint8_t block[64], uint32_t state[8]);   // 压缩函数本体
    void hash(const void* data, size_t len, uint8_t out[32]);     // 任意长度
    void sha256d_80(const void* header80, uint8_t out[32], bool use_midstate = false);
    class Midstate {
        explicit Midstate(const void* header80);
        void hash_words(uint32_t nonce, uint32_t out[8]) const;   // 最快，给 8 个 word
        void hash(uint32_t nonce, uint8_t out[32]) const;
        bool matches(const void* header80) const;
    };
    int leading_zero_bits_words(const uint32_t w[8]);

    // cold path（定义在 sha256.cpp）
    std::string sha256(const std::string& in);   // 回传 32 raw bytes，不是 hex
    int         leading_zero_bits(const uint8_t*, size_t = 32);
    std::string to_hex(const uint8_t*, size_t = 32);
    bool        self_test(std::string* detail = nullptr);
    bool        verify_midstate(const void* header80, std::string* = nullptr);
}
```

**Thread safety**：所有 function 都是 pure 的，`Midstate` 的每个 method 都是 `const`，
scratch buffer 全部在 stack 上。一个 `Midstate` 物件可以给全部 OpenMP thread 共用。

**参数顺序**：`transform(block, state)` — block 是输入，state 就地更新。
跟 OpenSSL 的 `SHA256_Transform(ctx, block)` **相反**。这是最容易写错的地方。

## ⚠️ midstate 的数字要重测

本机（2 core，scan mode，8,388,608 hashes，np=1）：

| | 换成自写之前 | 换成自写之后 |
|---|---|---|
| midstate OFF | — | 1.470 MH/s |
| midstate ON | — | 2.228 MH/s |
| **倍率** | **6.42×** | **1.52×** |

旧的 6.42× 里只有约 1.5× 是演算法赢的，其余是 baseline 走 OpenSSL 3.x 的
EVP provider dispatch（每次呼叫约 228 ns 纯开销），而 optimized 用
`SHA256_Transform` 绕过了它。自写版两边都没有 dispatch，
所以 **1.52× 才是 midstate 的真实价值**，而且刚好贴着理论上限 3÷2 = 1.5×。

**要改的 slide**：所有 midstate on/off 的对比数字。
**不用改的**：strong scaling 的 speedup / efficiency、strided vs block、
polling interval、全部 nonce。

## 还可以改进

1. **64 轮展开** — `transform()` 的主迴圈加 `#pragma GCC unroll 16`，通常再快 10–20%，三个 backend 一起受惠。
2. **W[0..15] 预算** — block 1 的 16 个 word 只有 nonce 那个会变，其余 15 个每次重算是浪费。存进 `Midstate` 可以把 1.52× 再往上推。
3. **OpenMP 少一次 memcmp** — 改成在 `#pragma omp parallel` 里建 `sha2::Midstate ms(&bh);` 直接呼叫 `ms.hash(n, out)`，可省掉 `sha256d_80` 每次的 64-byte 快取比对。
4. **CUDA 共用** — `transform()` 前面加 `__host__ __device__`、`K[64]` 改 `__constant__` 就能真正 single source。CUDA 目前能跑且已验证，**建议交件前不要动**。
5. **regression gate** — 把 `--difficulty 26` 必须等于 `78891794` 写进 `bench.sh` 开头。
