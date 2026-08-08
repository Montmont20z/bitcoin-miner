cmake_minimum_required(VERSION 3.14)
project(bitcoin_miner CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
#find_package(<new dependency>)

add_executable(miner serial/main.cpp)
target_link_libraries(miner PRIVATE 
    OpenSSL::Crypto 
    OpenSSL::SSL
    # more dependency
)