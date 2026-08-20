
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <random>
#include <ratio>
#include <sstream>
#include <vector>
#include <openssl/evp.h>
#include <chrono>
#include <fstream>
#include <omp.h>
#include <atomic>

constexpr int32_t VERSION = 29; 
constexpr int SEED = 1234; 
constexpr char PUBLIC_KEY[] = "0350929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d51bfbcef1a81c3b16";
constexpr int target_zero_bits = 28;
constexpr char CSV_LOG_PATH[] = "mining_benchmark.csv";


struct VarInt {
    uint64_t value;

    uint8_t encoded_size() const {
        if (value < 0xFD) return 1;
        if (value <= 0xFFFF) return 3; // 0xFD + 2 bytes
        if (value <= 0xFFFFFFFF) return 5; // 0xFE + 4 bytes
        return 9;                       // 0xFF + 8 bytes
    } 
    // serialize()/deserialize(uint8_t* buf) go here
};

struct TxIn {
    uint8_t prev_txid[32]; // hash of prior tx (binary, not text — same reasoning as prev_hash)
    uint32_t prev_index;   // output index being spent (0xFFFFFFFF for coinbase)
    VarInt   script_sig_len;
    std::vector<uint8_t> script_sig;    // raw opcode/data bytes — NOT std::string
    uint32_t sequence;
};

struct TxOut {
    int64_t  value;                     // satoshis; signed (Bitcoin Core's CAmount is int64_t, not uint64_t)
    VarInt   script_pubkey_len;
    std::vector<uint8_t> script_pubkey; // raw locking script bytes
};

struct Transaction {
    int32_t version;
    // VarInt input_count; // this field is dropped, use inputs.size()
    std::vector<TxIn> inputs; 
    // VarInt output_count; // this field is dropped, use outputs.size()
    std::vector<TxOut> outputs; 
    uint32_t locktime;
};

#pragma pack(push, 1) // ensure no padding is added, BlockHeader is always 80 Byte
struct BlockHeader {
    int32_t version;
    uint8_t prev_hash[32]; //32 Byte // not using std::string because memory structure does not fit CUDA
    uint8_t merkle_root[32]; // 32 Byte
    uint32_t timestamp;
    uint32_t bits; // encode difficulty //  count leading zero bits (not hex digits)
    uint32_t nonce;
};  
#pragma pack(pop)
static_assert(sizeof(BlockHeader) == 80, "header must be exactly 80 bytes");

struct Block {
    uint32_t block_size;
    BlockHeader header;
    VarInt transaction_counter;
    std::vector<Transaction> transactions; // list of transaction
};

int leading_zero_bits(const std::string& hash /* raw bytes */){
    int count = 0;
    for (unsigned char byte : hash){
        if (byte == 0){ count += 8; continue; } // currently 1 byte is 0 ~= 0b0000 0000

        for (int bit = 7; bit >= 0; --bit){
           if ((byte >> bit) & 1) return count; 
           count++;
        }
    }
    // return the total amount of leading zero in int 
    return count;
}

int leading_zero_bits_bytes(const uint8_t* hash, size_t len){
    int count = 0;
    for (size_t i = 0; i < len; ++i){
        uint8_t byte = hash[i];
        if (byte == 0){ count += 8; continue; }

        for (int bit = 7; bit >= 0; --bit){
           if ((byte >> bit) & 1) return count; 
           count++;
        }
    }
    // return the total amount of leading zero in int 
    return count;
}

std::string sha256(const std::string& input){
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (!context) return "";
    
    const EVP_MD* md = EVP_sha256();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length_of_hash = 0;
    
    // if failed to initialize
    if (EVP_DigestInit_ex(context, md, nullptr) != 1 ||
        EVP_DigestUpdate(context, input.c_str(), input.size()) != 1 ||
        EVP_DigestFinal_ex(context, hash, &length_of_hash) != 1
    ){
        EVP_MD_CTX_free(context);
        return "";
    }
    
    EVP_MD_CTX_free(context);

    return std::string(reinterpret_cast<char*>(hash), length_of_hash);  // raw 32 byte
}

// RAII holder for a per-thread EVP_MD_CTX. Paired with the `thread_local`
// instance inside sha256d_80(), this means each OpenMP thread allocates its
// digest context exactly once (not once per nonce) and it is freed
// automatically when the thread exits — no leak, no per-hash malloc/free.
struct Sha256Ctx {
    EVP_MD_CTX* ctx;
    Sha256Ctx() : ctx(EVP_MD_CTX_new()) {}
    ~Sha256Ctx() { EVP_MD_CTX_free(ctx); }
};

// Fast-path double-SHA256 specialized for the fixed 80-byte block header.
// Unlike sha256(), this never touches std::string: it reads straight out of
// the caller's 80-byte buffer and writes straight into a 32-byte output
// buffer, and it reuses one thread-local EVP_MD_CTX across every nonce a
// thread tries instead of allocating a fresh context per call. This is the
// function the hot mining loop should call.
void sha256d_80(const uint8_t header[80], uint8_t out[32]){
    thread_local Sha256Ctx tls_ctx;
    EVP_MD_CTX* ctx = tls_ctx.ctx;
    
    uint8_t first[32];
    unsigned int len = 0;
    
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, header, 80);
    EVP_DigestFinal_ex(ctx, first, &len);
 
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, first, 32);
    EVP_DigestFinal_ex(ctx, out, &len);
}

std::string byte_to_hex(const std::string& raw){
    std::stringstream ss;
    for (unsigned char c: raw){
        ss << 
        std::hex << // use base16
        std::setw(2) << // print 2 character for each byte
        std::setfill('0') << // ensure F become 0F to keep 64 character long 
        (int)c; // cast raw byte to int
    }
    return ss.str();
}

// for public key convert
std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        bytes.push_back(
            static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16))
        );
    }
    return bytes;
}

// for block header
void hex_to_array(const std::string& hex, uint8_t* out, size_t out_len) {
    if (hex.size() != out_len * 2) {
        std::cerr << "hex_to_array: expected " << out_len * 2 << " hex chars, got " << hex.size() << "\n";
        return;
    }
    for (size_t i = 0; i < out_len; ++i)
        out[i] = static_cast<uint8_t>(std::stoi(hex.substr(i * 2, 2), nullptr, 16));
}


// Appends one benchmark run to a CSV log, writing the header row the first
// time the file is created. Safe to call every run — subsequent runs just
// append a new row so results accumulate across executions.
void log_csv_result(const std::string& path, int threads, int target_bits,
                     double elapsed_ms, double hashes_per_sec,
                     uint64_t hash_count, uint32_t nonce_found,
                     const std::string& hash_hex){
    bool file_exists = std::ifstream(path).good();
    std::ofstream ofs(path, std::ios::app);
    if (!ofs){
        std::cerr << "log_csv_result: failed to open " << path << " for writing\n";
        return;
    }
    if (!file_exists){
        ofs << "timestamp,threads,target_zero_bits,elapsed_ms,hashes_per_sec,hash_count,nonce,hash_hex\n";
    }
 
    std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    ofs << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S") << ","
        << threads << ","
        << target_bits << ","
        << std::fixed << std::setprecision(3) << elapsed_ms << ","
        << std::fixed << std::setprecision(2) << hashes_per_sec << ","
        << hash_count << ","
        << nonce_found << ","
        << hash_hex << "\n";
}

// Result of a mining attempt: whether a solution was found, its nonce/hash,
// and the total number of hashes computed across all threads (needed to
// report hashes/second back in main()).
struct MiningResult {
    bool found = false;
    uint32_t nonce = 0;
    std::string hash_hex;
    uint64_t hash_count = 0;
};

MiningResult solve_for_nonce_parallel(BlockHeader bh, int target_zero_bits, uint32_t max_nonce = 0xFFFFFFFF){
    int total_threads = omp_get_max_threads();
    std::atomic<bool> found{false};
    std::atomic<uint64_t> total_hashes{0};
    MiningResult result;
    
    // Static chunk iteration: split the nonce space [0, max_nonce] into one
    // contiguous block per thread (thread ID picks its own [chunk_start,
    // chunk_end) range and walks it sequentially), instead of the previous
    // round-robin stride (n += total_threads) where every thread touched
    // interleaved nonces. Contiguous per-thread chunks keep bh.nonce
    // incrementing by 1 within a thread, which is friendlier to branch
    // prediction and keeps each thread's work assignment fixed and
    // predictable up front rather than interleaved.
    uint64_t range = static_cast<uint64_t>(max_nonce) + 1;
    uint64_t chunk_size = (range + static_cast<uint64_t>(total_threads) - 1) / total_threads;
    
    #pragma omp parallel firstprivate(bh)
    {
        int ID = omp_get_thread_num();
        uint64_t chunk_start = static_cast<uint64_t>(ID) * chunk_size;
        uint64_t chunk_end = std::min(chunk_start + chunk_size, range); // exclusive
        uint64_t local_hashes = 0;

        for (uint64_t n = chunk_start; n < chunk_end && !found.load(std::memory_order_relaxed); ++n){
            bh.nonce = static_cast<uint32_t>(n);
            
            uint8_t hash[32];
            sha256d_80(reinterpret_cast<const uint8_t*>(&bh), hash); // fast path: no string alloc
            ++local_hashes;


            if (leading_zero_bits_bytes(hash, 32) >= target_zero_bits){
                bool expected = false;
                if (found.compare_exchange_strong(expected, true)){
                    #pragma omp critical
                    {
                        result.hash_hex = byte_to_hex(std::string(reinterpret_cast<char*>(hash), 32));
                        result.nonce = bh.nonce;
                        result.found = true;
                        std::cout << "nonce: " << n << " hash: " << result.hash_hex << "\n"; // TODO: remove when optimize for performance
                    }
                }
                break;
            }
            
        }
        total_hashes.fetch_add(local_hashes, std::memory_order_relaxed);
    }
    result.hash_count = total_hashes.load();
    return result; // hash_hex empty / found == false if exhausted without a solution
    
}

std::string solve_for_nonce_parallel_stride( BlockHeader bh, int target_zero_bits, uint32_t max_nonce = 0xFFFFFFFF){
    int total_threads = omp_get_max_threads();
    std::atomic<bool> found{false};
    std::string solution = "";
    #pragma omp parallel firstprivate(bh)
    {
        int ID = omp_get_thread_num();
        for (uint64_t n = ID; n <= max_nonce && !found.load(std::memory_order_relaxed); n += total_threads){
            bh.nonce = static_cast<uint32_t>(n);
            std::string header_byte(reinterpret_cast<const char*>(&bh), sizeof(bh)); // interpret bh as byte not struct
            std::string hash = sha256(sha256(header_byte)); // double hash
            
            if (leading_zero_bits(hash) >= target_zero_bits){
                bool expected = false;
                if (found.compare_exchange_strong(expected, true)){
                    #pragma omp critical
                    {
                        solution = byte_to_hex(hash);
                        std::cout << "nonce: " << n << " hash: " << solution << "\n"; // TODO: remove when optimize for performance
                    }
                }
                break;
            }
        }
    }
    return solution; // empty if exhausted without a solution
}

int main(){
    // Initialize the standard 32-bit Mersenne Twister engine with the seed
    std::mt19937 gen(SEED);
    // Uniform distribution for integers in [1, 100]
    std::uniform_int_distribution<int> dist(1,100);

    // for(int i = 0; i < 5; ++i) {
    //     std::cout << "Rand Number: " << dist(gen) << "\n"; 
    // }
    
    /**------------------------ Create A Full Block -------------------- */ 
    // TxIn & TxOut
    TxIn txin {
        {0},               // prev_txid: 32 zero bytes → coinbase
        0xFFFFFFFF,        // prev_index: coinbase marker
        VarInt{1},         // script_sig_len — must match script_sig.size()
        {0x0F},            // script_sig: 1 byte of data
        0xFFFFFFFF         // sequence
    };
    
    // create public key and format it to be able to store in txout
    std::vector<uint8_t> pubkey = hex_to_bytes(
            PUBLIC_KEY
    );
    std::vector<uint8_t> script_pubkey;
    script_pubkey.push_back(0x21); // push 33-byte opcode
    script_pubkey.insert(script_pubkey.end(), pubkey.begin(), pubkey.end());
    script_pubkey.push_back(0xAC); // OP_CHECKSIG

    TxOut txout {
          5000000000,  // in satoshi 
          VarInt{ static_cast<uint64_t>(script_pubkey.size()) }, 
          script_pubkey
    };


    // TxIns & TxOuts
    std::vector<TxIn> txins;
    txins.push_back(txin);
    std::vector<TxOut> txouts;
    txouts.push_back(txout);

    // Transaction 
    Transaction transaction { VERSION, txins, txouts, 1262304000 };

    // Transactions
    std::vector<Transaction> transactions;
    transactions.push_back(transaction); 

    // Block Header 
    std::string merkle_root_hex = "0000000000000000000000000000000000000000000000000000000000000000"; // filler for now
    BlockHeader bh1{};
    bh1.version = 123;
    hex_to_array("0000000000000000000000000000000000000000000000000000000000000000", bh1.prev_hash, 32);
    hex_to_array(merkle_root_hex, bh1.merkle_root, 32);   // real 64-hex-char merkle root
    bh1.timestamp = 1262304000;
    bh1.bits      = 0x1d00ffff;
    bh1.nonce     = 0x4;

    // Genesis Block
    Block genesis_block { 
        0,  // real size TBD until serialize() exists
        bh1,
        VarInt{ static_cast<uint64_t>(transactions.size()) },
        transactions
     };
    
    // benchmark the time
    auto start = std::chrono::steady_clock::now();
    MiningResult mining_result = solve_for_nonce_parallel(bh1, target_zero_bits); // target zero bits are in int now and manually set, it should from bh.bits
    auto end = std::chrono::steady_clock::now();
    // calculate duration
    std::chrono::duration<double, std::milli> elapsed = end - start;
    
    double elapsed_sec = elapsed.count() / 1000.0;
    double hashes_per_sec = elapsed_sec > 0.0
        ? static_cast<double>(mining_result.hash_count) / elapsed_sec
        : 0.0;


    std::cout << "Elapsed time: " << elapsed.count() << " ms\n";
    std::cout << "Target zero bits: " << target_zero_bits << " \n";
    std::cout << "Threads: " << omp_get_max_threads() << "\n";
    std::cout << "Hashes computed: " << mining_result.hash_count << "\n";
    std::cout << "Hashes/sec: " << std::fixed << std::setprecision(2) << hashes_per_sec << "\n";
    
    log_csv_result(CSV_LOG_PATH, omp_get_max_threads(), target_zero_bits,
               elapsed.count(), hashes_per_sec, mining_result.hash_count,
               mining_result.nonce, mining_result.hash_hex);


    return 0;
}