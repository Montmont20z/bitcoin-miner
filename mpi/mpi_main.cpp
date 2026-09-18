#include <mpi.h>

// SHA-256 is implemented from scratch in core/sha256.h
#include "sha256.h"

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

// Supplied by <openssl/sha.h> before
constexpr int SHA256_DIGEST_LENGTH = 32;

static_assert(sizeof(BlockHeader) == 80, "BlockHeader must be exactly 80 bytes");

namespace {

constexpr int TAG_FOUND = 100;
constexpr int TAG_STOP = 101;
constexpr int TAG_DONE = 102;
constexpr uint64_t NO_NONCE = std::numeric_limits<uint64_t>::max();

struct Options {
    std::string mode = "scan";
    int difficulty = 20;
    uint64_t hashes = 1ULL << 24;
    uint64_t max_nonce = std::numeric_limits<uint32_t>::max();
    uint64_t poll_interval = 1024;
    std::string decomp = "strided";
    bool csv_header = false;
};

void print_usage(const char* program) {
    std::cout
        << "Usage:\n"
        << "  " << program << " --mode scan  [--hashes N] [--difficulty K]\n"
        << "  " << program << " --mode solve [--max-nonce N] [--difficulty K] [--poll N]\n"
        << "  " << program << " --mode sweep [--max-nonce N]\n\n"
        << "Options:\n"
        << "  --mode scan|solve   Fixed-work benchmark or early-exit mining\n"
        << "  --difficulty K      Required leading zero bits (default: 20)\n"
        << "  --hashes N          Total hashes in scan mode (default: 16777216)\n"
        << "  --max-nonce N       Largest nonce in solve mode (default: 4294967295)\n"
        << "  --poll N            Hashes between MPI message checks (default: 1024)\n"
        << "  --decomp strided|block\n"
        << "                      Nonce-space decomposition (default: strided)\n"
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
        } else if (arg == "--decomp") {
            options.decomp = require_value("--decomp");
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
    if (options.decomp != "strided" && options.decomp != "block") {
        throw std::runtime_error("--decomp must be strided or block");
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
    //sha256 implement, none midstate
    sha2::sha256d_80(&header, output, /*got midstate = */false);
}

class MidstateHasher {
public:
    explicit MidstateHasher(const BlockHeader& header) : impl_(&header) {}

    inline int hash(uint32_t nonce, uint32_t out[8]) {
        impl_.hash_words(nonce, out);
        return sha2::leading_zero_bits_words(out);
    }

    static inline int leading_zero_bits_words(const uint32_t words[8]) {
        return sha2::leading_zero_bits_words(words);
    }

    static void words_to_bytes(const uint32_t words[8], uint8_t out[SHA256_DIGEST_LENGTH]) {
        sha2::words_to_bytes(words, out);
    }

private:
    sha2::Midstate impl_;
};

void verify_midstate(const BlockHeader& header) {
    // Layer 1: the hand-written SHA-256 core against the FIPS 180-4 vectors.
    if (!sha2::self_test()) {
        throw std::runtime_error("SHA-256 core failed the FIPS 180-4 test vectors");
    }
    // Layer 2: the midstate fast path against the plain path.

    MidstateHasher hasher(header);
    const uint32_t probes[] = {0u, 1u, 255u, 256u, 65535u, 1000000u,
                               0x7fffffffu, 0x80000000u, 0xffffffffu};
    for (uint32_t nonce : probes) {
        uint8_t reference[SHA256_DIGEST_LENGTH], fast[SHA256_DIGEST_LENGTH];
        uint32_t words[8];
        double_sha256(header, nonce, reference);
        hasher.hash(nonce, words);
        MidstateHasher::words_to_bytes(words, fast);
        if (std::memcmp(reference, fast, SHA256_DIGEST_LENGTH) != 0) {
            throw std::runtime_error("midstate self-test failed at nonce "
                                     + std::to_string(nonce));
        }
    }
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

    MidstateHasher hasher(header);
    uint32_t words[8];
    uint64_t local_hashes = 0;
    // The checksum is reduced and printed on mismatch, so the loop is never dead work.
    uint64_t checksum = 0;
    for (uint64_t n = begin; n < end; ++n) {
        hasher.hash(static_cast<uint32_t>(n), words);
        checksum += (words[0] >> 24);   // same value the old code took from hash[0]
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

// Point-to-point rather than MPI_Bcast: a collective needs every rank to enter
// it together, which cannot happen while workers are inside a mining loop.
void send_stop_to_workers(int size, uint64_t winner, int winner_rank, double found_time) {
    static double payload[3];
    payload[0] = (winner == NO_NONCE) ? -1.0 : static_cast<double>(winner);
    payload[1] = static_cast<double>(winner_rank);
    payload[2] = found_time;
    std::vector<MPI_Request> requests;
    requests.reserve(size > 1 ? static_cast<std::size_t>(size - 1) : 0);
    for (int destination = 1; destination < size; ++destination) {
        MPI_Request request{};
        MPI_Isend(payload, 3, MPI_DOUBLE, destination, TAG_STOP, MPI_COMM_WORLD, &request);
        requests.push_back(request);
    }
    if (!requests.empty()) {
        MPI_Waitall(static_cast<int>(requests.size()), requests.data(), MPI_STATUSES_IGNORE);
    }
}

void run_solve(const Options& options, const BlockHeader& header, int rank, int size) {
    const uint64_t total = options.max_nonce + 1ULL;
    const bool strided = (options.decomp == "strided");

    // Strided: rank r takes r, r+P, r+2P, ...  Every rank walks the whole space
    // at 1/P density, so the globally smallest solution is reached first and the
    // answer matches the serial reference for any P.
    // Block: rank r takes one contiguous slice. Ranks that own high slices can
    // report a LARGER nonce than serial, and when the solution lies in rank 0's
    // slice the other ranks contribute nothing to time-to-solution.
    uint64_t begin = 0, end = 0, step = 1;
    if (strided) {
        begin = static_cast<uint64_t>(rank);
        end = total;
        step = static_cast<uint64_t>(size);
    } else {
        rank_range(total, rank, size, begin, end);
    }
    uint64_t next = begin;
    uint64_t local_hashes = 0;
    uint64_t winner = NO_NONCE;
    int winner_rank = -1;
    double found_time = 0.0;      // MPI_Wtime() at which a solution first existed

    MPI_Barrier(MPI_COMM_WORLD);
    const double start = MPI_Wtime();

    MidstateHasher hasher(header);

    if (rank == 0) {
        int completed_ranks = 0;
        bool root_done = false;
        uint32_t words[8];
        winner_rank = 0;

        while (winner == NO_NONCE && completed_ranks < size) {
            if (!root_done) {
                const uint64_t chunk_end =
                    std::min(end, next + options.poll_interval * step);
                for (; next < chunk_end; next += step) {
                    ++local_hashes;
                    if (hasher.hash(static_cast<uint32_t>(next), words) >= options.difficulty) {
                        winner = next;
                        winner_rank = 0;
                        found_time = MPI_Wtime();
                        next += step;
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
                double message[3] = {-1.0, 0.0, 0.0};
                MPI_Recv(message, 3, MPI_DOUBLE, status.MPI_SOURCE,
                         status.MPI_TAG, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
                if (status.MPI_TAG == TAG_FOUND && winner == NO_NONCE) {
                    winner = static_cast<uint64_t>(message[0]);
                    winner_rank = static_cast<int>(message[1]);
                    found_time = message[2];
                } else if (status.MPI_TAG == TAG_DONE) {
                    ++completed_ranks;
                }
            } while (flag);
        }

        send_stop_to_workers(size, winner, winner_rank, found_time);
    } else {
        uint32_t words[8];
        // Once a worker has reported, it stops hashing but keeps polling, so it
        // never blocks waiting on the coordinator's reply.
        bool reported = false;
        double payload[3] = {-1.0, static_cast<double>(rank), 0.0};
        MPI_Request report_request = MPI_REQUEST_NULL;

        for (;;) {
            int stop_waiting = 0;
            MPI_Iprobe(0, TAG_STOP, MPI_COMM_WORLD, &stop_waiting, MPI_STATUS_IGNORE);
            if (stop_waiting) {
                double stop[3] = {-1.0, 0.0, 0.0};
                MPI_Recv(stop, 3, MPI_DOUBLE, 0, TAG_STOP,
                         MPI_COMM_WORLD, MPI_STATUS_IGNORE);
                winner = (stop[0] < 0.0) ? NO_NONCE : static_cast<uint64_t>(stop[0]);
                winner_rank = static_cast<int>(stop[1]);
                found_time = stop[2];
                break;
            }
            if (reported) continue;

            const uint64_t chunk_end =
                std::min(end, next + options.poll_interval * step);
            for (; next < chunk_end; next += step) {
                ++local_hashes;
                if (hasher.hash(static_cast<uint32_t>(next), words) >= options.difficulty) {
                    payload[0] = static_cast<double>(next);
                    payload[2] = MPI_Wtime();
                    MPI_Isend(payload, 3, MPI_DOUBLE, 0, TAG_FOUND,
                              MPI_COMM_WORLD, &report_request);
                    reported = true;
                    break;
                }
            }
            if (!reported && next >= end) {
                payload[0] = 1.0;
                MPI_Isend(payload, 3, MPI_DOUBLE, 0, TAG_DONE,
                          MPI_COMM_WORLD, &report_request);
                reported = true;
            }
        }
        if (report_request != MPI_REQUEST_NULL) {
            MPI_Wait(&report_request, MPI_STATUS_IGNORE);
        }
    }

    const double local_seconds = MPI_Wtime() - start;
    uint64_t total_hashes = 0;
    double elapsed = 0.0;
    MPI_Reduce(&local_hashes, &total_hashes, 1, MPI_UINT64_T, MPI_SUM, 0, MPI_COMM_WORLD);
    MPI_Reduce(&local_seconds, &elapsed, 1, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);

    // Hashes this rank computed after a solution already existed somewhere,
    // estimated from its own average rate over the overrun window. This is
    // exactly the quantity --poll trades away.
    double local_wasted = 0.0;
    if (found_time > 0.0 && local_seconds > 0.0) {
        const double overrun = (start + local_seconds) - found_time;
        if (overrun > 0.0) {
            local_wasted = static_cast<double>(local_hashes) / local_seconds
                         * std::min(overrun, local_seconds);
        }
    }
    double total_wasted = 0.0;
    MPI_Reduce(&local_wasted, &total_wasted, 1, MPI_DOUBLE, MPI_SUM, 0, MPI_COMM_WORLD);

    if (rank == 0) {
        bool valid = false;
        std::string hash_hex;
        if (winner != NO_NONCE) {
            uint8_t winning_hash[SHA256_DIGEST_LENGTH];
            double_sha256(header, static_cast<uint32_t>(winner), winning_hash);
            valid = leading_zero_bits(winning_hash) >= options.difficulty;
            hash_hex = hash_to_hex(winning_hash);
        }
        const uint64_t wasted = static_cast<uint64_t>(total_wasted + 0.5);
        const double wasted_pct = total_hashes > 0
            ? 100.0 * static_cast<double>(wasted) / static_cast<double>(total_hashes) : 0.0;
        std::cout << "Winning rank: " << winner_rank << "\n"
                  << "Wasted post-solution hashes: " << wasted
                  << " (" << std::setprecision(2) << wasted_pct << "%)\n"
                  << std::setprecision(6);

        print_result(options, size, total_hashes, elapsed, winner, valid, hash_hex);
        std::cout << "wasted," << size << ',' << options.difficulty << ','
                  << options.poll_interval << ',' << total_hashes << ','
                  << wasted << ',' << wasted_pct << '\n';
    }
}

} // namespace

int main(int argc, char** argv) {
    MPI_Init(&argc, &argv);

    int rank = 0, size = 1;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    char processor_name[MPI_MAX_PROCESSOR_NAME] = {};
    int name_length = 0;
    MPI_Get_processor_name(processor_name, &name_length);
    std::vector<char> all_names(rank == 0 ? size * MPI_MAX_PROCESSOR_NAME : 0);
    MPI_Gather(processor_name, MPI_MAX_PROCESSOR_NAME, MPI_CHAR,
               rank == 0 ? all_names.data() : nullptr, MPI_MAX_PROCESSOR_NAME,
               MPI_CHAR, 0, MPI_COMM_WORLD);
    if (rank == 0) {
        std::cout << "\nMPI Rank Placement\n";
        for (int r = 0; r < size; ++r) {
            std::cout << "Rank " << r << " runs on machine "
                      << (all_names.data() + r * MPI_MAX_PROCESSOR_NAME) << "\n";
        }
        std::cout << std::endl;
    }

    try {
        const Options options = parse_options(argc, argv);
        BlockHeader header{};
        if (rank == 0) header = make_shared_header();
        MPI_Bcast(&header, sizeof(header), MPI_BYTE, 0, MPI_COMM_WORLD);

        // Microseconds; proves the midstate fast path is bit-identical to OpenSSL.
        verify_midstate(header);

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
