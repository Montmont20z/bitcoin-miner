# Installation

## Linux
One-Time Setup:
```bash
sudo apt update && sudo apt install build-essential cmake libssl-dev
```

Build and Run:
```bash
# 1. Generate build files into a 'build' directory
cmake -B build
# 2. Compile the project
cmake --build build
# 3. Run the binary
./build/miner
```

## Windows

### One-Time Setup

1. Install [Visual Studio 2022](https://visualstudio.microsoft.com/) with the **Desktop development with C++** workload (includes CMake and Ninja).
2. Install [vcpkg](https://github.com/microsoft/vcpkg) as a standalone clone (don't use the copy bundled inside Visual Studio — it isn't a git checkout and can't be updated with `git pull`):
```powershell
   cd C:\
   git clone https://github.com/microsoft/vcpkg.git
   cd vcpkg
   .\bootstrap-vcpkg.bat
```
3. Set `VCPKG_ROOT` to point at your clone (open a new terminal afterward):
```powershell
   setx VCPKG_ROOT "C:\vcpkg"
```
4. OpenSSL is declared in `vcpkg.json` and installs automatically in manifest mode — no manual `vcpkg install` step needed.

### Option A — Visual Studio (recommended)

1. **File → Open → Folder...** → select the project root (do **not** open any `.sln`; this project builds via CMake directly).
2. Visual Studio reads `CMakeLists.txt` + `CMakeSettings.json` and configures automatically, including the vcpkg toolchain and OpenSSL dependency.
3. In the toolbar, use **Select Startup Item...** → choose `miner.exe`.
4. **Ctrl+F5** to run, or **F5** to run with the debugger.

If CMake generation fails after changing dependencies or settings, use **Project → Delete Cache and Reconfigure** to force a clean regenerate (stale caches are the most common cause of "package not found" errors).

### Option B — Command line

```powershell
# 1. Generate build files linked to your vcpkg toolchain
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE="C:/vcpkg/scripts/buildsystems/vcpkg.cmake"
# 2. Compile in Release mode
cmake --build build --config Release
# 3. Run the compiled executable
.\build\Release\miner.exe
```

# Run

## AMD (HIP)
```bash
hipify-perl cuda/BitcoinCUDA.cu > cuda/BitcoinHIP.cpp
hipcc -x hip cuda/BitcoinHIP.cpp -o hip_miner -O3 --offload-arch=gfx1200
./hip_miner
```