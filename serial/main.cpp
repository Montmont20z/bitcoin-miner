#include <cstdint>
#include <iostream>
#include <iomanip>
#include <random>
#include <ratio>
#include <sstream>
#include <vector>
#include <openssl/evp.h>
#include <chrono>

constexpr int32_t VERSION = 29; 
constexpr int SEED = 1234; 
constexpr char PUBLIC_KEY[] = "0350929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d51bfbcef1a81c3b16";

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
        if (byte == 0){ count += 8; continue; } // currently 1 byte is 0 ~= 0000 0000

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

struct MiningResult {
    bool found = false;
    uint32_t nonce = 0;
    std::string hash_hex;
    uint64_t total_hashes = 0;
};

MiningResult solve_for_nonce(BlockHeader bh, int target_zero_bits, uint32_t max_nonce = 0xFFFFFFFFu){
    MiningResult result;

    for (uint32_t n = 0;; ++n){
        bh.nonce = n;
        std::string header_byte(reinterpret_cast<const char*>(&bh), sizeof(bh));
        std::string hash = sha256(sha256(header_byte));

        ++result.total_hashes;

        if (leading_zero_bits(hash) >= target_zero_bits){
            result.found = true;
            result.nonce = n;
            result.hash_hex = byte_to_hex(hash);
            return result;
        }

        if (n == max_nonce) break;
    }

    return result;
}

int main(int argc, char* argv[]){
    int target_zero_bits = 24;

    if (argc >= 2) {
        try {
            target_zero_bits = std::stoi(argv[1]);
        } catch (...) {
            std::cerr << "Invalid leading zero bits. Example: ./bitcoin_cpu 24\n";
            return 1;
        }
    }

    if (target_zero_bits < 0 || target_zero_bits > 256) {
        std::cerr << "Leading zero bits must be between 0 and 256.\n";
        return 1;
    }

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
    
    
    // std::string input = "Hello World";
    // std::string hash = to_hex(sha256(input));
    // std::string raw_hash = sha256(input);
    // std::string double_hash = to_hex(sha256(sha256(input)));
    
    // std::cout << "input: " << genesis_block.block_size << "\n"; 
    // std::cout << "hash: " << hash << "\n"; 
    // std::cout << "raw hash: " << raw_hash << "\n"; 
    // std::cout << "double hash: " << double_hash << "\n"; 
    
    // std::cout << "input: " << txin.prev_index<< "\n"; 
    
    
    // benchmark the time
    auto start = std::chrono::steady_clock::now();
    MiningResult result = solve_for_nonce(bh1, target_zero_bits);
    auto end = std::chrono::steady_clock::now();

    std::chrono::duration<double, std::milli> elapsed = end - start;
    const double elapsed_seconds = elapsed.count() / 1000.0;
    const double hashes_per_second =
        (elapsed_seconds > 0.0)
            ? static_cast<double>(result.total_hashes) / elapsed_seconds
            : 0.0;

    std::cout << "\n============================\n";
    std::cout << "CPU Mining Result\n";
    std::cout << "============================\n";

    if (result.found) {
        std::cout << "Nonce: " << result.nonce << "\n";
        std::cout << "Hash: " << result.hash_hex << "\n";
        std::cout << "Valid: Yes\n";
    } else {
        std::cout << "No valid nonce found.\n";
        std::cout << "Valid: No\n";
    }

    std::cout << "Target zero bits: " << target_zero_bits << "\n";
    std::cout << "Elapsed time: " << std::fixed << std::setprecision(3)
              << elapsed.count() << " ms\n";
    std::cout << "Total Hash: " << result.total_hashes << "\n";
    std::cout << "Hash/sec: " << std::fixed << std::setprecision(2)
              << hashes_per_second << " H/s\n";

    return 0;
}