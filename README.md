# Installation 
## Linux
One-Time Setup:
```bash
sudo apt update && sudo apt install build-essential cmake libssl-dev
```
Build and Run
```bash
# 1. Generate build files into a 'build' directory
cmake -B build

# 2. Compile the project
cmake --build build

# 3. Run the binary
./build/miner
```

## Windows
Install OpenSSL via vcpkg
```bash
vcpkg install openssl:x64-windows
```
Build & Run:
```PowerShell
# 1. Generate build files linked to your vcpkg toolchain
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE="C:/vcpkg/scripts/buildsystems/vcpkg.cmake"

# 2. Compile in Release mode
cmake --build build --config Release

# 3. Run the compiled executable
.\build\Release\miner.exe
```



# Run

Run AMD
```bash
hipify-perl cuda/BitcoinCUDA.cu > cuda/BitcoinHIP.cpp
hipcc -x hip cuda/BitcoinHIP.cpp -o hip_miner -O3 --offload-arch=gfx1200
./hip_miner


```