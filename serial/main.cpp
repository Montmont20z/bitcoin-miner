#include <cstdint>
#include <iostream>
#include <iomanip>
#include <openssl/core_dispatch.h>
#include <sstream>
#include <vector>
#include <openssl/evp.h>

struct Transaction {
    uint32_t id;
    std::string from;
    std::string to;
    double amount;
};

struct BlockHeader {
    uint32_t version;
    uint8_t prev_hash[32]; //32 Byte // not using std::string because memory structure does not fit CUDA
    uint8_t merkle_root[32]; // 32 Byte
    uint32_t timestamp;
    uint32_t bits; // encode difficulty //  count leading zero bits (not hex digits)
    uint32_t nonce;
};  

struct Block {
    BlockHeader header;
    std::vector<Transaction> transactions; // list of transaction
    std::string winning_hash;
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
    Transaction t1{123, "John", "Jane", 50.5060};
    BlockHeader bh1 {123, "0xFF96437", "0x123098", 1262304000, 1, 4};
    
    std::string input = "Hello World";
    std::string hash = to_hex(sha256(input));
    std::string raw_hash = sha256(input);
    std::string double_hash = to_hex(sha256(sha256(input)));
    
    std::cout << "input: " << input << "\n"; 
    std::cout << "hash: " << hash << "\n"; 
    std::cout << "raw hash: " << raw_hash << "\n"; 
    std::cout << "double hash: " << double_hash << "\n"; 
    return 0;
}