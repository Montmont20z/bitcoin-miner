#include <cuda_runtime.h>

#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>

// ============================================================
// CUDA ERROR CHECKING
// ============================================================

#define CUDA_CHECK(call)                                                   \
do {                                                                       \
    cudaError_t err = (call);                                              \
    if (err != cudaSuccess) {                                              \
        std::cerr << "CUDA Error: " << cudaGetErrorString(err)             \
                  << " at " << __FILE__ << ":" << __LINE__ << "\n";        \
        exit(EXIT_FAILURE);                                                \
    }                                                                      \
} while (0)

// ============================================================
// BLOCK HEADER
// ============================================================

#pragma pack(push, 1)

struct BlockHeader
{
    int32_t version;
    uint8_t prev_hash[32];
    uint8_t merkle_root[32];
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
};

#pragma pack(pop)

static_assert(
    sizeof(BlockHeader) == 80,
    "BlockHeader must be exactly 80 bytes"
    );


// ============================================================
// CUDA CONSTANT MEMORY
// ============================================================

// Every GPU thread reads the same block header.
// Only nonce changes.
__constant__ uint8_t c_block_header[80];


// ============================================================
// SHA-256 CONSTANTS
// ============================================================

__device__ __constant__ uint32_t SHA256_K[64] =
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


// ============================================================
// SHA-256 BASIC FUNCTIONS
// ============================================================

__device__ __forceinline__
uint32_t rotr(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32 - n));
}


__device__ __forceinline__
uint32_t choose(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z);
}


__device__ __forceinline__
uint32_t majority(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}


__device__ __forceinline__
uint32_t big_sigma0(uint32_t x)
{
    return rotr(x, 2) ^
        rotr(x, 13) ^
        rotr(x, 22);
}


__device__ __forceinline__
uint32_t big_sigma1(uint32_t x)
{
    return rotr(x, 6) ^
        rotr(x, 11) ^
        rotr(x, 25);
}


__device__ __forceinline__
uint32_t small_sigma0(uint32_t x)
{
    return rotr(x, 7) ^
        rotr(x, 18) ^
        (x >> 3);
}


__device__ __forceinline__
uint32_t small_sigma1(uint32_t x)
{
    return rotr(x, 17) ^
        rotr(x, 19) ^
        (x >> 10);
}


// ============================================================
// SHA-256 COMPRESSION
// ============================================================

__device__
void sha256_transform(
    const uint8_t block[64],
    uint32_t state[8])
{
    uint32_t w[64];

    // --------------------------------------------------------
    // First 16 words
    // SHA-256 interprets the input as big endian.
    // --------------------------------------------------------

    for (int i = 0; i < 16; ++i)
    {
        int j = i * 4;

        w[i] =
            (static_cast<uint32_t>(block[j]) << 24) |
            (static_cast<uint32_t>(block[j + 1]) << 16) |
            (static_cast<uint32_t>(block[j + 2]) << 8) |
            (static_cast<uint32_t>(block[j + 3]));
    }

    // --------------------------------------------------------
    // Extend message schedule
    // --------------------------------------------------------

    for (int i = 16; i < 64; ++i)
    {
        w[i] =
            small_sigma1(w[i - 2]) +
            w[i - 7] +
            small_sigma0(w[i - 15]) +
            w[i - 16];
    }

    // --------------------------------------------------------
    // Working variables
    // --------------------------------------------------------

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    // --------------------------------------------------------
    // 64 SHA-256 rounds
    // --------------------------------------------------------

    for (int i = 0; i < 64; ++i)
    {
        uint32_t temp1 =
            h +
            big_sigma1(e) +
            choose(e, f, g) +
            SHA256_K[i] +
            w[i];

        uint32_t temp2 =
            big_sigma0(a) +
            majority(a, b, c);

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    // --------------------------------------------------------
    // Update state
    // --------------------------------------------------------

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}


// ============================================================
// INITIAL SHA-256 STATE
// ============================================================

__device__
void initialize_sha256_state(uint32_t state[8])
{
    state[0] = 0x6a09e667;
    state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372;
    state[3] = 0xa54ff53a;
    state[4] = 0x510e527f;
    state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab;
    state[7] = 0x5be0cd19;
}


// ============================================================
// SHA-256 FOR EXACTLY 80 BYTES
//
// Bitcoin BlockHeader = 80 bytes
// ============================================================

__device__
void sha256_80(
    const uint8_t input[80],
    uint8_t output[32])
{
    uint32_t state[8];

    initialize_sha256_state(state);

    // --------------------------------------------------------
    // Block 1 = first 64 bytes
    // --------------------------------------------------------

    uint8_t block1[64];

    for (int i = 0; i < 64; ++i)
    {
        block1[i] = input[i];
    }

    sha256_transform(block1, state);

    // --------------------------------------------------------
    // Block 2
    //
    // Remaining data:
    // 80 - 64 = 16 bytes
    //
    // Then:
    // 0x80
    // zeros
    // length = 80 * 8 = 640 bits
    // --------------------------------------------------------

    uint8_t block2[64];

    for (int i = 0; i < 64; ++i)
    {
        block2[i] = 0;
    }

    for (int i = 0; i < 16; ++i)
    {
        block2[i] = input[64 + i];
    }

    // padding start
    block2[16] = 0x80;

    // 640 bits = 0x280
    block2[62] = 0x02;
    block2[63] = 0x80;

    sha256_transform(block2, state);

    // --------------------------------------------------------
    // Convert state into 32-byte big-endian digest
    // --------------------------------------------------------

    for (int i = 0; i < 8; ++i)
    {
        output[i * 4] =
            static_cast<uint8_t>(state[i] >> 24);

        output[i * 4 + 1] =
            static_cast<uint8_t>(state[i] >> 16);

        output[i * 4 + 2] =
            static_cast<uint8_t>(state[i] >> 8);

        output[i * 4 + 3] =
            static_cast<uint8_t>(state[i]);
    }
}


// ============================================================
// SHA-256 FOR EXACTLY 32 BYTES
//
// Used for:
//
// SHA256(
//     first_SHA256_result
// )
//
// First SHA result is always 32 bytes.
// ============================================================

__device__
void sha256_32(
    const uint8_t input[32],
    uint8_t output[32])
{
    uint32_t state[8];

    initialize_sha256_state(state);

    uint8_t block[64];

    for (int i = 0; i < 64; ++i)
    {
        block[i] = 0;
    }

    // original 32 bytes
    for (int i = 0; i < 32; ++i)
    {
        block[i] = input[i];
    }

    // padding
    block[32] = 0x80;

    // message length:
    //
    // 32 * 8 = 256 bits = 0x100
    block[62] = 0x01;
    block[63] = 0x00;

    sha256_transform(block, state);

    for (int i = 0; i < 8; ++i)
    {
        output[i * 4] =
            static_cast<uint8_t>(state[i] >> 24);

        output[i * 4 + 1] =
            static_cast<uint8_t>(state[i] >> 16);

        output[i * 4 + 2] =
            static_cast<uint8_t>(state[i] >> 8);

        output[i * 4 + 3] =
            static_cast<uint8_t>(state[i]);
    }
}


// ============================================================
// BITCOIN DOUBLE SHA-256
//
// SHA256(SHA256(header))
// ============================================================

__device__
void sha256d_80(
    const uint8_t header[80],
    uint8_t output[32])
{
    uint8_t first_hash[32];

    sha256_80(
        header,
        first_hash
    );

    sha256_32(
        first_hash,
        output
    );
}


// ============================================================
// LEADING ZERO BITS
//
// Same concept as your CPU implementation.
// ============================================================

__device__
int leading_zero_bits_device(
    const uint8_t hash[32])
{
    int count = 0;

    for (int i = 0; i < 32; ++i)
    {
        uint8_t byte = hash[i];

        if (byte == 0)
        {
            count += 8;
            continue;
        }

        for (int bit = 7; bit >= 0; --bit)
        {
            if ((byte >> bit) & 1)
            {
                return count;
            }

            ++count;
        }
    }

    return count;
}


// ============================================================
// CUDA MINING KERNEL
// ============================================================

__global__
void mine_kernel(
    int target_zero_bits,
    uint32_t max_nonce,
    int* found,
    uint32_t* winning_nonce,
    uint8_t* winning_hash,
    unsigned long long* total_hashes)
{
    // --------------------------------------------------------
    // Unique global thread ID
    // --------------------------------------------------------

    uint64_t thread_id =
        static_cast<uint64_t>(blockIdx.x) *
        blockDim.x +
        threadIdx.x;

    // --------------------------------------------------------
    // Total number of CUDA threads
    //
    // This becomes the GRID STRIDE.
    // --------------------------------------------------------

    uint64_t grid_stride =
        static_cast<uint64_t>(blockDim.x) *
        gridDim.x;

    // --------------------------------------------------------
    // Copy constant header into local thread storage
    // --------------------------------------------------------

    uint8_t header[80];

    for (int i = 0; i < 80; ++i)
    {
        header[i] = c_block_header[i];
    }

    // Count hashes completed by this thread locally.
    // We only use atomicAdd when the thread exits, avoiding one global
    // atomic operation for every SHA256d calculation.
    unsigned long long local_hash_count = 0;

    // ========================================================
    // GRID-STRIDE LOOP
    //
    // Example:
    //
    // Thread 0:
    // 0, stride, 2*stride...
    //
    // Thread 1:
    // 1, stride+1, 2*stride+1...
    // ========================================================

    for (
        uint64_t n = thread_id;
        n <= static_cast<uint64_t>(max_nonce);
        n += grid_stride)
    {
        // ----------------------------------------------------
        // Stop if another thread already found a nonce
        // ----------------------------------------------------

        if (atomicAdd(found, 0) != 0)
        {
            if (local_hash_count > 0)
                atomicAdd(total_hashes, local_hash_count);
            return;
        }

        uint32_t nonce =
            static_cast<uint32_t>(n);

        // ----------------------------------------------------
        // BlockHeader layout:
        //
        // version       0 - 3
        // prev hash     4 - 35
        // merkle root  36 - 67
        // timestamp    68 - 71
        // bits         72 - 75
        // nonce        76 - 79
        //
        // x86 / Bitcoin fields use little endian here.
        // ----------------------------------------------------

        header[76] =
            static_cast<uint8_t>(nonce);

        header[77] =
            static_cast<uint8_t>(nonce >> 8);

        header[78] =
            static_cast<uint8_t>(nonce >> 16);

        header[79] =
            static_cast<uint8_t>(nonce >> 24);

        // ----------------------------------------------------
        // Double SHA-256
        // ----------------------------------------------------

        uint8_t hash[32];

        sha256d_80(
            header,
            hash
        );

        ++local_hash_count;

        // ----------------------------------------------------
        // Check difficulty
        // ----------------------------------------------------

        int zero_bits =
            leading_zero_bits_device(hash);

        if (zero_bits >= target_zero_bits)
        {
            // atomicExch ensures only the first winner
            // stores the result.

            if (atomicExch(found, 1) == 0)
            {
                *winning_nonce = nonce;

                for (int i = 0; i < 32; ++i)
                {
                    winning_hash[i] = hash[i];
                }
            }

            if (local_hash_count > 0)
                atomicAdd(total_hashes, local_hash_count);
            return;
        }
    }

    // Thread exhausted its assigned nonce sequence without finding a winner.
    if (local_hash_count > 0)
        atomicAdd(total_hashes, local_hash_count);
}


// ============================================================
// CPU UTILITY
// ============================================================

void hex_to_array(
    const std::string& hex,
    uint8_t* output,
    size_t output_length)
{
    if (hex.size() != output_length * 2)
    {
        std::cerr
            << "Invalid hex length.\n";

        return;
    }

    for (size_t i = 0; i < output_length; ++i)
    {
        output[i] =
            static_cast<uint8_t>(
                std::stoi(
                    hex.substr(i * 2, 2),
                    nullptr,
                    16
                )
                );
    }
}


std::string hash_to_hex(
    const uint8_t hash[32])
{
    std::stringstream ss;

    for (int i = 0; i < 32; ++i)
    {
        ss
            << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(hash[i]);
    }

    return ss.str();
}


// ============================================================
// MAIN
// ============================================================

int main(int argc, char* argv[])
{
    // ========================================================
    // 1. CREATE THE SAME BLOCK HEADER AS CPU VERSION
    // ========================================================

    BlockHeader bh{};

    bh.version = 123;

    hex_to_array(
        "0000000000000000000000000000000000000000000000000000000000000000",
        bh.prev_hash,
        32
    );

    hex_to_array(
        "0000000000000000000000000000000000000000000000000000000000000000",
        bh.merkle_root,
        32
    );

    bh.timestamp = 1262304000;

    bh.bits = 0x1d00ffff;

    bh.nonce = 0;


    // ========================================================
    // 2. DIFFICULTY - RUNTIME CUSTOMIZABLE
    //
    // Usage:
    //   BitcoinCUDA_multi_batch 32 10
    //   BitcoinCUDA_multi_batch 36 100
    //   BitcoinCUDA_multi_batch 40 1000
    //
    // argv[1] = target leading-zero bits
    // argv[2] = maximum number of distinct header batches
    //
    // If no command-line argument is given, the program asks
    // for the target zero bits interactively.
    // ========================================================

    unsigned int target_zero_bits = 0;
    uint64_t max_batches = 100;

    if (argc >= 2)
    {
        try
        {
            int value = std::stoi(argv[1]);

            if (value < 0 || value > 256)
            {
                std::cerr << "Target zero bits must be between 0 and 256.\n";
                return EXIT_FAILURE;
            }

            target_zero_bits = static_cast<unsigned int>(value);
        }
        catch (...)
        {
            std::cerr << "Invalid target zero bits. Example: BitcoinCUDA.exe 24\n";
            return EXIT_FAILURE;
        }
    }
    else
    {
        std::cout << "Enter target zero bits (0-256): ";

        int value = 0;
        if (!(std::cin >> value) || value < 0 || value > 256)
        {
            std::cerr << "Invalid target zero bits. Please enter a value from 0 to 256.\n";
            return EXIT_FAILURE;
        }

        target_zero_bits = static_cast<unsigned int>(value);
    }

    if (argc >= 3)
    {
        try
        {
            unsigned long long value = std::stoull(argv[2]);

            if (value == 0)
            {
                std::cerr << "Max batches must be greater than 0.\n";
                return EXIT_FAILURE;
            }

            max_batches = static_cast<uint64_t>(value);
        }
        catch (...)
        {
            std::cerr << "Invalid max batches. Example: BitcoinCUDA_multi_batch 36 100\n";
            return EXIT_FAILURE;
        }
    }

    std::cout << "Target zero bits selected: "
              << target_zero_bits << "\n";
    std::cout << "Maximum header batches: "
              << max_batches << "\n\n";


    // ========================================================
    // 3. COPY BLOCK HEADER TO GPU CONSTANT MEMORY
    // ========================================================

    CUDA_CHECK(
        cudaMemcpyToSymbol(
            c_block_header,
            &bh,
            sizeof(BlockHeader)
        )
    );


    // ========================================================
    // 4. ALLOCATE RESULT MEMORY
    // ========================================================

    int* d_found = nullptr;

    uint32_t* d_winning_nonce = nullptr;

    uint8_t* d_winning_hash = nullptr;

    unsigned long long* d_total_hashes = nullptr;


    CUDA_CHECK(
        cudaMalloc(
            reinterpret_cast<void**>(&d_found),
            sizeof(int)
        )
    );

    CUDA_CHECK(
        cudaMalloc(
            reinterpret_cast<void**>(&d_winning_nonce),
            sizeof(uint32_t)
        )
    );

    CUDA_CHECK(
        cudaMalloc(
            reinterpret_cast<void**>(&d_winning_hash),
            32
        )
    );

    CUDA_CHECK(
        cudaMalloc(
            reinterpret_cast<void**>(&d_total_hashes),
            sizeof(unsigned long long)
        )
    );


    // ========================================================
    // 5. INITIALIZE GPU RESULT
    // ========================================================

    CUDA_CHECK(
        cudaMemset(
            d_found,
            0,
            sizeof(int)
        )
    );

    CUDA_CHECK(
        cudaMemset(
            d_winning_nonce,
            0,
            sizeof(uint32_t)
        )
    );

    CUDA_CHECK(
        cudaMemset(
            d_winning_hash,
            0,
            32
        )
    );

    CUDA_CHECK(
        cudaMemset(
            d_total_hashes,
            0,
            sizeof(unsigned long long)
        )
    );


    // ========================================================
    // 6. GET GPU INFORMATION
    // ========================================================

    int device = 0;

    CUDA_CHECK(
        cudaGetDevice(&device)
    );

    cudaDeviceProp properties{};

    CUDA_CHECK(
        cudaGetDeviceProperties(
            &properties,
            device
        )
    );

    std::cout
        << "GPU: "
        << properties.name
        << "\n";

    std::cout
        << "Streaming Multiprocessors: "
        << properties.multiProcessorCount
        << "\n";


    // ========================================================
    // 7. CUDA CONFIGURATION
    //
    // First experiment:
    //
    // blockSize:
    // 128
    // 256
    // 512
    // 1024
    //
    // Your implementation plan specifically requires this.
    // ========================================================

    int block_size = 256;

    int number_of_blocks =
        properties.multiProcessorCount * 32;


    std::cout
        << "CUDA blocks: "
        << number_of_blocks
        << "\n";

    std::cout
        << "Threads per block: "
        << block_size
        << "\n";

    std::cout
        << "Total active logical CUDA threads: "
        << number_of_blocks * block_size
        << "\n";


    // ========================================================
    // 8. CUDA EVENTS + MULTI-HEADER / MULTI-BATCH SEARCH
    //
    // Each batch searches the complete 32-bit nonce range.
    // If no solution is found, timestamp is incremented so the
    // next batch hashes a different 80-byte block header.
    // ========================================================

    cudaEvent_t start;
    cudaEvent_t stop;

    CUDA_CHECK(cudaEventCreate(&start));
    CUDA_CHECK(cudaEventCreate(&stop));

    int found = 0;
    uint32_t winning_nonce = 0;
    uint8_t winning_hash[32]{};

    unsigned long long grand_total_hashes = 0;
    double grand_total_ms = 0.0;

    uint64_t batches_searched = 0;
    uint32_t winning_timestamp = 0;

    const uint32_t base_timestamp = bh.timestamp;

    for (uint64_t batch = 0; batch < max_batches; ++batch)
    {
        // Change the header between batches so the same nonce range
        // produces a completely new set of SHA-256d values.
        bh.timestamp = base_timestamp + static_cast<uint32_t>(batch);
        bh.nonce = 0;

        CUDA_CHECK(
            cudaMemcpyToSymbol(
                c_block_header,
                &bh,
                sizeof(BlockHeader)
            )
        );

        // Reset per-batch outputs.
        CUDA_CHECK(cudaMemset(d_found, 0, sizeof(int)));
        CUDA_CHECK(cudaMemset(d_winning_nonce, 0, sizeof(uint32_t)));
        CUDA_CHECK(cudaMemset(d_winning_hash, 0, 32));
        CUDA_CHECK(cudaMemset(d_total_hashes, 0, sizeof(unsigned long long)));

        CUDA_CHECK(cudaEventRecord(start));

        mine_kernel<<<number_of_blocks, block_size>>>(
            target_zero_bits,
            0xFFFFFFFFu,
            d_found,
            d_winning_nonce,
            d_winning_hash,
            d_total_hashes
        );

        CUDA_CHECK(cudaGetLastError());
        CUDA_CHECK(cudaEventRecord(stop));
        CUDA_CHECK(cudaEventSynchronize(stop));

        float batch_ms = 0.0f;
        CUDA_CHECK(cudaEventElapsedTime(&batch_ms, start, stop));

        unsigned long long batch_hashes = 0;

        CUDA_CHECK(
            cudaMemcpy(
                &found,
                d_found,
                sizeof(int),
                cudaMemcpyDeviceToHost
            )
        );

        CUDA_CHECK(
            cudaMemcpy(
                &batch_hashes,
                d_total_hashes,
                sizeof(unsigned long long),
                cudaMemcpyDeviceToHost
            )
        );

        grand_total_hashes += batch_hashes;
        grand_total_ms += static_cast<double>(batch_ms);
        batches_searched = batch + 1;

        std::cout
            << "Batch " << batch
            << " | timestamp: " << bh.timestamp
            << " | hashes: " << batch_hashes
            << " | time: " << std::fixed << std::setprecision(2)
            << batch_ms << " ms";

        if (found)
        {
            CUDA_CHECK(
                cudaMemcpy(
                    &winning_nonce,
                    d_winning_nonce,
                    sizeof(uint32_t),
                    cudaMemcpyDeviceToHost
                )
            );

            CUDA_CHECK(
                cudaMemcpy(
                    winning_hash,
                    d_winning_hash,
                    32,
                    cudaMemcpyDeviceToHost
                )
            );

            winning_timestamp = bh.timestamp;
            std::cout << " | FOUND\n";
            break;
        }

        std::cout << " | no solution\n";
    }

    // ========================================================
    // 9. PRINT FINAL RESULT
    // ========================================================

    std::cout << "\n";
    std::cout << "============================\n";
    std::cout << "CUDA Mining Result\n";
    std::cout << "============================\n";

    if (found)
    {
        std::cout << "Nonce: " << winning_nonce << "\n";
        std::cout << "Timestamp: " << winning_timestamp << "\n";
        std::cout << "Hash: " << hash_to_hex(winning_hash) << "\n";
    }
    else
    {
        std::cout << "No valid nonce found in all configured batches.\n";
    }

    std::cout << "Target zero bits: " << target_zero_bits << "\n";
    std::cout << "Header batches searched: " << batches_searched << "\n";
    std::cout << "Total GPU kernel time: "
              << std::fixed << std::setprecision(2)
              << grand_total_ms << " ms\n";
    std::cout << "Total Hash: " << grand_total_hashes << "\n";

    const double grand_total_seconds = grand_total_ms / 1000.0;
    const double hashes_per_second =
        (grand_total_seconds > 0.0)
            ? static_cast<double>(grand_total_hashes) / grand_total_seconds
            : 0.0;

    std::cout << "Hash/sec: "
              << std::fixed << std::setprecision(2)
              << hashes_per_second << " H/s\n";

    // ========================================================
    // 13. CLEANUP
    // ========================================================

    CUDA_CHECK(
        cudaEventDestroy(start)
    );

    CUDA_CHECK(
        cudaEventDestroy(stop)
    );

    CUDA_CHECK(
        cudaFree(d_found)
    );

    CUDA_CHECK(
        cudaFree(d_winning_nonce)
    );

    CUDA_CHECK(
        cudaFree(d_winning_hash)
    );

    CUDA_CHECK(
        cudaFree(d_total_hashes)
    );


    return 0;
}