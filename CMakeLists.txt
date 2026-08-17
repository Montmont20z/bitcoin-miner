cmake_minimum_required(VERSION 3.14)
project(bitcoin_miner CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(OpenSSL REQUIRED)
find_package(OpenMP REQUIRED)
#find_package(<new dependency>)

add_executable(miner serial/main.cpp)
add_executable(miner_openmp openmp/main.cpp)
target_link_libraries(miner PRIVATE 
    OpenSSL::Crypto 
    OpenSSL::SSL
    # more dependency
)
target_link_libraries(miner PUBLIC OpenMP::OpenMP_CXX)

target_link_libraries(miner_openmp PRIVATE OpenSSL::Crypto OpenSSL::SSL)
target_link_libraries(miner_openmp PUBLIC OpenMP::OpenMP_CXX)