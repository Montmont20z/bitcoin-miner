#include <cstdint>
#include <iostream>
#include <iomanip>
#include <openssl/core_dispatch.h>
#include <random>
#include <sstream>
#include <sys/types.h>
#include <vector>
#include <openssl/evp.h>

constexpr int SEED = 1234; 

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

std::string to_hex(const std::string& raw){
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


    // TxIns & TxOuts

    // Transaction 


    // 
    
    BlockHeader bh1 {123, "0xFF96437", "0x123098", 1262304000, 0x0, 0x4};
    // Genesis Block
    
    
    // std::string input = "Hello World";
    // std::string hash = to_hex(sha256(input));
    // std::string raw_hash = sha256(input);
    // std::string double_hash = to_hex(sha256(sha256(input)));
    
    // std::cout << "input: " << input << "\n"; 
    // std::cout << "hash: " << hash << "\n"; 
    // std::cout << "raw hash: " << raw_hash << "\n"; 
    // std::cout << "double hash: " << double_hash << "\n"; 
    
    std::cout << "input: " << txin.prev_index<< "\n"; 
    // combine all the data and hash the actual block



    return 0;
}