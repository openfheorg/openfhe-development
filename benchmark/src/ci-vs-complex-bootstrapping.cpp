//==================================================================================
// BSD 2-Clause License
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
// All rights reserved.
//==================================================================================

//
// Two-way bootstrap benchmark (plan Section 11), reals only, matched ring dimension:
//   C  -- native conjugate-invariant (CI) CKKS bootstrap: N real slots, rank N, no ring switch.
//   A  -- standard complex CKKS bootstrap fed real data: N/2 usable real slots.
// Reports per-bootstrap latency, amortized time per real slot, useful real-slots/sec,
// #Galois keys, log2(Q), and recovered precision. Demonstrates the 2x real-slot packing
// advantage of CI. Run: ./bin/benchmark/ci-vs-complex-bootstrapping [logN] [iters]
//
// NOTE (honest framing, plan Section 12): the CI path here uses the O(sqrt N)-rotation BSGS
// linear transform with per-bootstrap diagonal encoding; the level-collapsed FFT schedule,
// FFT-accelerated Setup-precompute, and EvalMod precision tuning are documented future work,
// so this is a moderate-N demonstration, not yet the 2^16 / iso-precision final table.
//

#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <vector>

#include "openfhe.h"

using namespace lbcrypto;
using Clock = std::chrono::steady_clock;

static double SecSince(Clock::time_point t0) {
    return std::chrono::duration<double>(Clock::now() - t0).count();
}

struct Result {
    std::string label;
    uint32_t ringDim;
    uint32_t realSlots;
    uint32_t numGaloisKeys;
    double logQ;
    double keygenSec;
    double bootSec;  // median over iters
    double recoveredBits;
};

static double RecoveredBits(const std::vector<double>& orig, const std::vector<std::complex<double>>& got, uint32_t n) {
    double maxerr = 0;
    for (uint32_t i = 0; i < n; ++i)
        maxerr = std::max(maxerr, std::abs(got[i].real() - orig[i]));
    return (maxerr > 0) ? -std::log2(maxerr) : 60.0;
}

static double Median(std::vector<double> v) {
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

static double LogQ(const CryptoContext<DCRTPoly>& cc) {
    auto params = cc->GetCryptoParameters()->GetElementParams()->GetParams();
    double bits = 0;
    for (auto& p : params)
        bits += std::log2(p->GetModulus().ConvertToDouble());
    return bits;
}

// Config C: native CI bootstrap, N real slots.
static Result BenchCI(uint32_t N, uint32_t iters) {
    std::vector<uint32_t> levelBudget = {1, 1};  // single-level BSGS LT (fastest; the throughput win)
    uint32_t levelsAfter = 6;
    SecretKeyDist skd = UNIFORM_TERNARY;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetCKKSDataType(REAL_CI);
    parameters.SetRingDim(N);
    parameters.SetSecretKeyDist(skd);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetScalingModSize(50);
    parameters.SetFirstModSize(60);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetMultiplicativeDepth(levelsAfter + FHECKKSRNS::GetBootstrapDepth(levelBudget, skd));

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    uint32_t slots = N;  // N real slots
    cc->EvalBootstrapSetup(levelBudget, {0, 0}, slots);
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    auto t0 = Clock::now();
    cc->EvalBootstrapKeyGen(keys.secretKey, slots);
    double keygenSec = SecSince(t0);
    uint32_t nkeys = cc->GetEvalAutomorphismKeyMap(keys.secretKey->GetKeyTag()).size();

    std::vector<double> x(slots);
    for (uint32_t i = 0; i < slots; ++i)
        x[i] = 0.5 * std::sin(0.05 * (i + 1));
    auto pt = cc->MakeCKKSPackedPlaintext(x, 1, parameters.GetMultiplicativeDepth() - 1, nullptr, slots);
    auto ct = cc->Encrypt(keys.publicKey, pt);

    cc->EvalBootstrap(ct);  // warm-up: pay the lazy diagonal-precompute once (excluded)
    std::vector<double> times;
    double bits = 0;
    for (uint32_t it = 0; it < iters; ++it) {
        auto tb = Clock::now();
        auto ctAfter = cc->EvalBootstrap(ct);
        times.push_back(SecSince(tb));
        Plaintext res;
        cc->Decrypt(keys.secretKey, ctAfter, &res);
        res->SetLength(slots);
        bits = RecoveredBits(x, res->GetCKKSPackedValue(), slots);
    }
    return {"C (native CI)", N, slots, nkeys, LogQ(cc), keygenSec, Median(times), bits};
}

// Config A: standard complex CKKS bootstrap fed reals, N/2 usable real slots.
static Result BenchStd(uint32_t N, uint32_t iters) {
    std::vector<uint32_t> levelBudget = {3, 3};
    uint32_t levelsAfter = 6;
    SecretKeyDist skd = UNIFORM_TERNARY;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetRingDim(N);
    parameters.SetSecretKeyDist(skd);
    parameters.SetScalingTechnique(FIXEDMANUAL);  // iso-config with CI (which requires FIXEDMANUAL)
    parameters.SetScalingModSize(50);
    parameters.SetFirstModSize(60);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetMultiplicativeDepth(levelsAfter + FHECKKSRNS::GetBootstrapDepth(levelBudget, skd));

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    uint32_t slots = N / 2;  // N/2 complex slots = N/2 usable real values
    cc->EvalBootstrapSetup(levelBudget, {0, 0}, slots);
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    auto t0 = Clock::now();
    cc->EvalBootstrapKeyGen(keys.secretKey, slots);
    double keygenSec = SecSince(t0);
    uint32_t nkeys = cc->GetEvalAutomorphismKeyMap(keys.secretKey->GetKeyTag()).size();

    std::vector<double> x(slots);
    for (uint32_t i = 0; i < slots; ++i)
        x[i] = 0.5 * std::sin(0.05 * (i + 1));
    auto pt = cc->MakeCKKSPackedPlaintext(x, 1, 0, nullptr, slots);
    auto ct = cc->Encrypt(keys.publicKey, pt);

    cc->EvalBootstrap(ct);  // warm-up (excluded)
    std::vector<double> times;
    double bits = 0;
    for (uint32_t it = 0; it < iters; ++it) {
        auto tb = Clock::now();
        auto ctAfter = cc->EvalBootstrap(ct);
        times.push_back(SecSince(tb));
        Plaintext res;
        cc->Decrypt(keys.secretKey, ctAfter, &res);
        res->SetLength(slots);
        bits = RecoveredBits(x, res->GetCKKSPackedValue(), slots);
    }
    return {"A (std complex)", N, slots, nkeys, LogQ(cc), keygenSec, Median(times), bits};
}

static void PrintRow(const Result& r) {
    double amortUs = r.bootSec / r.realSlots * 1e6;
    double slotsPerSec = r.realSlots / r.bootSec;
    std::cout << std::left << std::setw(18) << r.label << std::right << std::setw(8) << r.ringDim << std::setw(11)
              << r.realSlots << std::setw(10) << r.numGaloisKeys << std::setw(10) << std::fixed << std::setprecision(0)
              << r.logQ << std::setw(11) << std::setprecision(2) << r.bootSec << std::setw(13) << std::setprecision(1)
              << amortUs << std::setw(14) << std::setprecision(0) << slotsPerSec << std::setw(10)
              << std::setprecision(1) << r.recoveredBits << "\n";
}

int main(int argc, char** argv) {
    uint32_t logN = (argc > 1) ? std::stoul(argv[1]) : 9;  // default N=512
    uint32_t iters = (argc > 2) ? std::stoul(argv[2]) : 2;
    uint32_t N = 1u << logN;

    std::cout << "\n=== Native CI vs standard CKKS bootstrap (reals only), ring dim N=" << N << ", iters=" << iters
              << " ===\n\n";
    std::cout << std::left << std::setw(18) << "config" << std::right << std::setw(8) << "ringDim" << std::setw(11)
              << "realSlots" << std::setw(10) << "#galKeys" << std::setw(10) << "log2Q" << std::setw(11) << "boot(s)"
              << std::setw(13) << "us/slot" << std::setw(14) << "slots/s" << std::setw(10) << "prec(b)" << "\n";
    std::cout << std::string(103, '-') << "\n";

    Result a = BenchStd(N, iters);
    PrintRow(a);
    Result c = BenchCI(N, iters);
    PrintRow(c);

    std::cout << "\nReal-slot throughput ratio (C/A): " << std::fixed << std::setprecision(2)
              << (c.realSlots / c.bootSec) / (a.realSlots / a.bootSec) << "x"
              << "   (CI packs " << (double)c.realSlots / a.realSlots << "x the real slots at matched ring dim)\n\n";
    return 0;
}
