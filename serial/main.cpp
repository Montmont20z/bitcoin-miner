#include <cstdint>
#include <iostream>
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
    
    

    return "";
}

int main(){
    Transaction t1{123, "John", "Jane", 50.5060};
    BlockHeader bh1 {123, "0xFF96437", "0x123098", 1262304000, 1, 4};
    
    
    // std::cout << "Hello World!\n"; 
    // std::cout << sizeof(std::string) << "\n";
    std::cout << t1.from<< "\n"; 
    std::cout << bh1.nonce<< "\n"; 
    return 0;
}