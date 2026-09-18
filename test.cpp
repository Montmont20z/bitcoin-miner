#include <iostream>
#include "core/sha256.h"


int main(){
    std::string text = "hello";

    std::string hash = sha2::sha256(text);
    std::string hash2 = sha2::sha256(hash);
    

    std::cout << "hash: " << sha2::to_hex(reinterpret_cast<const uint8_t*>(hash.data()), hash.size()) << std::endl;
    std::cout << "hash: " << sha2::to_hex(reinterpret_cast<const uint8_t*>(hash2.data()), hash2.size()) << std::endl;


    return 0;
}