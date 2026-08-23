#include <mpi.h>
#include <openssl/sha.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// MPI Bitcoin-style nonce miner for the PDC assignment.
// It intentionally uses the same fixed 80-byte header as serial/main.cpp and
// BitcoinCUDA.cu so that correctness results are directly comparable.

#pragma pack(push, 1)
struct BlockHeader {
    int32_t version;
    uint8_t prev_hash[32];
    uint8_t merkle_root[32];
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
};
#pragma pack(pop)

static_assert(sizeof(BlockHeader) == 80, "BlockHeader must be exactly 80 bytes");

namespace {

constexpr int TAG_RESULT = 100;
constexpr int TAG_STOP = 101;
constexpr int TAG_DONE = 102;
constexpr uint64_t NO_NONCE = std::numeric_limits<uint64_t>::max();

struct Options {
    std::string mode = "scan";
    int difficulty = 20;
    uint64_t hashes = 1ULL << 24;
    uint64_t max_nonce = std::numeric_limits<uint32_t>::max();
    uint64_t poll_interval = 1024;
    bool csv_header = false;
};

void print_usage(const char* program) {
    std::cout
        << "Usage:\n"
        << "  " << program << " --mode scan  [--hashes N] [--difficulty K]\n"
        << "  " << program << " --mode solve [--max-nonce N] [--difficulty K] [--poll N]\n\n"
        << "Options:\n"
        << "  --mode scan|solve   Fixed-work benchmark or early-exit mining\n"
        << "  --difficulty K      Required leading zero bits (default: 20)\n"
        << "  --hashes N          Total hashes in scan mode (default: 16777216)\n"
        << "  --max-nonce N       Largest nonce in solve mode (default: 4294967295)\n"
        << "  --poll N            Hashes between MPI message checks (default: 1024)\n"
        << "  --csv-header        Print a CSV header before the result row\n"
        << "  --help              Show this message\n";
}

uint64_t parse_u64(const std::string& text, const char* option) {
    std::size_t used = 0;
    uint64_t value = 0;
    try {
        value = std::stoull(text, &used, 0);
    } catch (...) {
        throw std::runtime_error(std::string("Invalid value for ") + option + ": " + text);
    }
    if (used != text.size()) {
        throw std::runtime_error(std::string("Invalid value for ") + option + ": " + text);
    }
    return value;
}

Options parse_options(int argc, char** argv) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto require_value = [&](const char* name) -> std::string {
            if (++i >= argc) {
                throw std::runtime_error(std::string("Missing value after ") + name);
            }
            return argv[i];
        };

        if (arg == "--mode") {
            options.mode = require_value("--mode");
        } else if (arg == "--difficulty") {
            options.difficulty = static_cast<int>(parse_u64(require_value("--difficulty"), "--difficulty"));
        } else if (arg == "--hashes") {
            options.hashes = parse_u64(require_value("--hashes"), "--hashes");
        } else if (arg == "--max-nonce") {
            options.max_nonce = parse_u64(require_value("--max-nonce"), "--max-nonce");
        } else if (arg == "--poll") {
            options.poll_interval = parse_u64(require_value("--poll"), "--poll");
        } else if (arg == "--csv-header") {
            options.csv_header = true;
        } else if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            std::exit(0);
        } else {
            throw std::runtime_error("Unknown option: " + arg);
        }
    }

    if (options.mode != "scan" && options.mode != "solve") {
        throw std::runtime_error("--mode must be scan or solve");
    }
    if (options.difficulty < 0 || options.difficulty > 256) {
        throw std::runtime_error("--difficulty must be between 0 and 256");
    }
    if (options.hashes == 0) {
        throw std::runtime_error("--hashes must be greater than zero");
    }
    if (options.max_nonce > std::numeric_limits<uint32_t>::max()) {
        throw std::runtime_error("--max-nonce must fit in uint32_t");
    }
    if (options.poll_interval == 0) {
        throw std::runtime_error("--poll must be greater than zero");
    }
    return options;
}

BlockHeader make_shared_header() {
    BlockHeader header{};
    header.version = 123;
    std::memset(header.prev_hash, 0, sizeof(header.prev_hash));
    std::memset(header.merkle_root, 0, sizeof(header.merkle_root));
    header.timestamp = 1262304000;
    header.bits = 0x1d00ffff;
    header.nonce = 0;
    return header;
}

void double_sha256(BlockHeader header, uint32_t nonce, uint8_t output[SHA256_DIGEST_LENGTH]) {
    header.nonce = nonce;
    uint8_t first[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(&header), sizeof(header), first);
    SHA256(first, sizeof(first), output);
}

int leading_zero_bits(const uint8_t hash[SHA256_DIGEST_LENGTH]) {
    int count = 0;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        const uint8_t byte = hash[i];
        if (byte == 0) {
            count += 8;
            continue;
        }
        for (int bit = 7; bit >= 0; --bit) {
            if ((byte >> bit) & 1U) return count;
            ++count;
        }
    }
    return count;
}

std::string hash_to_hex(const uint8_t hash[SHA256_DIGEST_LENGTH]) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        out << std::setw(2) << static_cast<unsigned int>(hash[i]);
    }
    return out.str();
}

// Split [0,total) into contiguous, non-overlapping ranges.
void rank_range(uint64_t total, int rank, int size, uint64_t& begin, uint64_t& end) {
    const uint64_t base = total / static_cast<uint64_t>(size);
    const uint64_t remainder = total % static_cast<uint64_t>(size);
    begin = static_cast<uint64_t>(rank) * base
          + std::min<uint64_t>(static_cast<uint64_t>(rank), remainder);
    end = begin + base + (static_cast<uint64_t>(rank) < remainder ? 1ULL : 0ULL);
}

void print_result(const Options& options, int ranks, uint64_t hashes,
                  double seconds, uint64_t nonce, bool valid,
                  const std::string& hash_hex) {
    const double rate_mhs = seconds > 0.0
        ? static_cast<double>(hashes) / seconds / 1.0e6
        : 0.0;

    std::cout << std::fixed << std::setprecision(6);
    std::cout << "\nMPI Mining Result\n"
              << "Mode: " << options.mode << "\n"
              << "Ranks: " << ranks << "\n"
              << "Difficulty: " << options.difficulty << "\n"
              << "Hashes: " << hashes << "\n"
              << "Elapsed seconds: " << seconds << "\n"
              << "Hash rate: " << rate_mhs << " MH/s\n";
    if (options.mode == "solve") {
        if (valid) {
            std::cout << "Nonce: " << nonce << "\n"
                      << "Hash: " << hash_hex << "\n"
                      << "Valid: yes\n";
        } else {
            std::cout << "No valid nonce found in the selected range.\n"
                      << "Valid: no\n";
        }
    }

    if (options.csv_header) {
        std::cout << "backend,ranks,difficulty,mode,hashes,seconds,rate_mhs,nonce,valid\n";
    }
    std::cout << "mpi," << ranks << ',' << options.difficulty << ',' << options.mode
              << ',' << hashes << ',' << seconds << ',' << rate_mhs << ',';
    if (options.mode == "solve" && valid) std::cout << nonce;
    std::cout << ',' << (options.mode == "solve" ? (valid ? "yes" : "no") : "na") << "\n";
}

void run_scan(const Options& options, const BlockHeader& header, int rank, int size) {
    uint64_t begin = 0, end = 0;
    rank_range(options.hashes, rank, size, begin, end);

    MPI_Barrier(MPI_COMM_WORLD);
    const double start = MPI_Wtime();

    uint8_t hash[SHA256_DIGEST_LENGTH];
    uint64_t local_hashes = 0;
    // Volatile checksum prevents an optimizing compiler from treating this as dead work.
    uint64_t checksum = 0;
    for (uint64_t n = begin; n < end; ++n) {
        double_sha256(header, static_cast<uint32_t>(n), hash);
        checksum += hash[0];
        ++local_hashes;
    }

    const double local_seconds = MPI_Wtime() - start;
    uint64_t total_hashes = 0, total_checksum = 0;
    double elapsed = 0.0;
    MPI_Reduce(&local_hashes, &total_hashes, 1, MPI_UINT64_T, MPI_SUM, 0, MPI_COMM_WORLD);
    MPI_Reduce(&checksum, &total_checksum, 1, MPI_UINT64_T, MPI_SUM, 0, MPI_COMM_WORLD);
    MPI_Reduce(&local_seconds, &elapsed, 1, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);

    if (rank == 0) {
        // Keep checksum observable while leaving the CSV schema clean.
        if (total_checksum == NO_NONCE) std::cerr << "checksum: " << total_checksum << '\n';
        print_result(options, size, total_hashes, elapsed, NO_NONCE, false, "");
    }
}

void send_stop_to_workers(int size, uint64_t winner) {
    std::vector<MPI_Request> requests;
    requests.reserve(size > 1 ? static_cast<std::size_t>(size - 1) : 0);
    for (int destination = 1; destination < size; ++destination) {
        MPI_Request request{};
        MPI_Isend(&winner, 1, MPI_UINT64_T, destination, TAG_STOP, MPI_COMM_WORLD, &request);
        requests.push_back(request);
    }
    if (!requests.empty()) {
        MPI_Waitall(static_cast<int>(requests.size()), requests.data(), MPI_STATUSES_IGNORE);
    }
}

void run_solve(const Options& options, const BlockHeader& header, int rank, int size) {
    const uint64_t total = options.max_nonce + 1ULL;
    uint64_t begin = 0, end = 0;
    rank_range(total, rank, size, begin, end);
    uint64_t next = begin;
    uint64_t local_hashes = 0;
    uint64_t winner = NO_NONCE;

    MPI_Barrier(MPI_COMM_WORLD);
    const double start = MPI_Wtime();

    if (rank == 0) {
        int completed_ranks = 0;
        bool root_done = false;
        uint8_t hash[SHA256_DIGEST_LENGTH];

        while (winner == NO_NONCE && completed_ranks < size) {
            if (!root_done) {
                const uint64_t chunk_end = std::min(end, next + options.poll_interval);
                for (; next < chunk_end; ++next) {
                    double_sha256(header, static_cast<uint32_t>(next), hash);
                    ++local_hashes;
                    if (leading_zero_bits(hash) >= options.difficulty) {
                        winner = next;
                        ++next;
                        break;
                    }
                }
                if (next >= end && !root_done) {
                    root_done = true;
                    ++completed_ranks;
                }
            }

            int flag = 0;
            MPI_Status status{};
            do {
                MPI_Iprobe(MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &flag, &status);
                if (!flag) break;
                uint64_t message = NO_NONCE;
                MPI_Recv(&message, 1, MPI_UINT64_T, status.MPI_SOURCE,
                         status.MPI_TAG, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
                if (status.MPI_TAG == TAG_RESULT && winner == NO_NONCE) {
                    winner = message;
                } else if (status.MPI_TAG == TAG_DONE) {
                    ++completed_ranks;
                }
            } while (flag);
        }

        send_stop_to_workers(size, winner);
    } else {
        uint8_t hash[SHA256_DIGEST_LENGTH];
        bool finished = false;
        while (!finished) {
            int stop_waiting = 0;
            MPI_Iprobe(0, TAG_STOP, MPI_COMM_WORLD, &stop_waiting, MPI_STATUS_IGNORE);
            if (stop_waiting) {
                MPI_Recv(&winner, 1, MPI_UINT64_T, 0, TAG_STOP,
                         MPI_COMM_WORLD, MPI_STATUS_IGNORE);
                break;
            }

            const uint64_t chunk_end = std::min(end, next + options.poll_interval);
            for (; next < chunk_end; ++next) {
                double_sha256(header, static_cast<uint32_t>(next), hash);
                ++local_hashes;
                if (leading_zero_bits(hash) >= options.difficulty) {
                    const uint64_t found_nonce = next;
                    MPI_Send(&found_nonce, 1, MPI_UINT64_T, 0, TAG_RESULT, MPI_COMM_WORLD);
                    MPI_Recv(&winner, 1, MPI_UINT64_T, 0, TAG_STOP,
                             MPI_COMM_WORLD, MPI_STATUS_IGNORE);
                    finished = true;
                    break;
                }
            }
            if (!finished && next >= end) {
                const uint64_t done = 1;
                MPI_Send(&done, 1, MPI_UINT64_T, 0, TAG_DONE, MPI_COMM_WORLD);
                MPI_Recv(&winner, 1, MPI_UINT64_T, 0, TAG_STOP,
                         MPI_COMM_WORLD, MPI_STATUS_IGNORE);
                finished = true;
            }
        }
    }

    const double local_seconds = MPI_Wtime() - start;
    uint64_t total_hashes = 0;
    double elapsed = 0.0;
    MPI_Reduce(&local_hashes, &total_hashes, 1, MPI_UINT64_T, MPI_SUM, 0, MPI_COMM_WORLD);
    MPI_Reduce(&local_seconds, &elapsed, 1, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);

    if (rank == 0) {
        bool valid = false;
        std::string hash_hex;
        if (winner != NO_NONCE) {
            uint8_t winning_hash[SHA256_DIGEST_LENGTH];
            double_sha256(header, static_cast<uint32_t>(winner), winning_hash);
            valid = leading_zero_bits(winning_hash) >= options.difficulty;
            hash_hex = hash_to_hex(winning_hash);
        }
        print_result(options, size, total_hashes, elapsed, winner, valid, hash_hex);
    }
}

} // namespace

int main(int argc, char** argv) {
    MPI_Init(&argc, &argv);

    int rank = 0, size = 1;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    char processor_name[MPI_MAX_PROCESSOR_NAME] = {};
int processor_name_length = 0;

MPI_Get_processor_name(
    processor_name,
    &processor_name_length
);

std::vector<char> all_processor_names;

if (rank == 0) {
    all_processor_names.resize(
        size * MPI_MAX_PROCESSOR_NAME
    );
}

MPI_Gather(
    processor_name,
    MPI_MAX_PROCESSOR_NAME,
    MPI_CHAR,
    rank == 0 ? all_processor_names.data() : nullptr,
    MPI_MAX_PROCESSOR_NAME,
    MPI_CHAR,
    0,
    MPI_COMM_WORLD
);

if (rank == 0) {
    std::cout << "\nMPI Rank Placement\n";

    for (int r = 0; r < size; ++r) {
        const char* machine_name =
            all_processor_names.data()
            + r * MPI_MAX_PROCESSOR_NAME;

        std::cout << "Rank " << r
                  << " runs on machine "
                  << machine_name << "\n";
    }

    std::cout << std::endl;
}

    try {
        const Options options = parse_options(argc, argv);
        BlockHeader header{};
        if (rank == 0) header = make_shared_header();
        MPI_Bcast(&header, sizeof(header), MPI_BYTE, 0, MPI_COMM_WORLD);

        if (options.mode == "scan") {
            if (options.hashes > (1ULL << 32)) {
                throw std::runtime_error("--hashes cannot exceed the 32-bit nonce space");
            }
            run_scan(options, header, rank, size);
        } else {
            run_solve(options, header, rank, size);
        }
    } catch (const std::exception& error) {
        if (rank == 0) {
            std::cerr << "Error: " << error.what() << "\n\n";
            print_usage(argv[0]);
        }
        MPI_Abort(MPI_COMM_WORLD, 1);
    }

    MPI_Finalize();
    return 0;
}
