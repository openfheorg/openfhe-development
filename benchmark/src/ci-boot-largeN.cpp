//==================================================================================
// Native CI CKKS bootstrap — single-config timing + precision probe.
// Args: [logN] [scaleModSize] [firstModSize]   (defaults 12 59 60)
// levelBudget = {4,4} if 4|logN, else {3,3} if 3|logN, else {1,1}. Input uniform in [-1,1].
// Multi-threaded via OMP_NUM_THREADS. Measures keygen + bootstrap latency and recovered bits.
//==================================================================================
#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <random>
#include <vector>

#include "openfhe.h"

using namespace lbcrypto;
using Clock = std::chrono::steady_clock;
static double Sec(Clock::time_point t0) {
    return std::chrono::duration<double>(Clock::now() - t0).count();
}

int main(int argc, char** argv) {
    uint32_t logN = (argc > 1) ? std::stoul(argv[1]) : 12;
    uint32_t scaleModSize = (argc > 2) ? std::stoul(argv[2]) : 59;
    uint32_t firstModSize = (argc > 3) ? std::stoul(argv[3]) : 60;
    uint32_t N = 1u << logN;

    std::vector<uint32_t> levelBudget = (logN % 4 == 0) ? std::vector<uint32_t>{4, 4} :
                                        (logN % 3 == 0) ? std::vector<uint32_t>{3, 3} :
                                                          std::vector<uint32_t>{1, 1};
    uint32_t levelsAfter = 6;
    SecretKeyDist skd = UNIFORM_TERNARY;

    std::cout << "\n=== Native CI CKKS bootstrap probe ===\n"
              << "logN=" << logN << " (N=" << N << "), scaleModSize=" << scaleModSize
              << ", firstModSize=" << firstModSize << ", levelBudget={" << levelBudget[0] << "," << levelBudget[1]
              << "}, threads=" << OpenFHEParallelControls.GetThreadLimit(1u << 20) << "\n";

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetCKKSDataType(REAL_CI);
    parameters.SetRingDim(N);
    parameters.SetSecretKeyDist(skd);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetSecurityLevel(HEStd_NotSet);
    uint32_t depth = levelsAfter + FHECKKSRNS::GetBootstrapDepth(levelBudget, skd);
    parameters.SetMultiplicativeDepth(depth);

    auto t0 = Clock::now();
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);
    std::cout << "context+depth(" << depth << ") built in " << std::fixed << std::setprecision(2) << Sec(t0)
              << "s; log2Q ~ " << depth * scaleModSize << " bits\n"
              << std::flush;

    uint32_t slots = N;  // full CI real packing
    t0 = Clock::now();
    cc->EvalBootstrapSetup(levelBudget, {0, 0}, slots);
    std::cout << "EvalBootstrapSetup: " << Sec(t0) << "s\n" << std::flush;

    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    t0 = Clock::now();
    cc->EvalBootstrapKeyGen(keys.secretKey, slots);
    double keygenSec = Sec(t0);
    uint32_t nkeys = cc->GetEvalAutomorphismKeyMap(keys.secretKey->GetKeyTag()).size();
    std::cout << "EvalBootstrapKeyGen: " << keygenSec << "s (" << nkeys << " Galois keys)\n" << std::flush;

    std::vector<double> x(slots);
    std::mt19937_64 rng(12345);
    for (uint32_t i = 0; i < slots; ++i)
        x[i] = 2.0 * (double)(rng() % 1000000) / 1000000.0 - 1.0;  // uniform in [-1,1]

    auto pt = cc->MakeCKKSPackedPlaintext(x, 1, depth - 1, nullptr, slots);
    auto ct = cc->Encrypt(keys.publicKey, pt);

    t0 = Clock::now();
    auto ctWarm = cc->EvalBootstrap(ct);  // warm-up: pays the (one-time) diagonal precompute
    std::cout << "first EvalBootstrap (incl. diagonal precompute): " << Sec(t0) << "s\n" << std::flush;

    std::vector<double> times;
    double bits = 0;
    for (int it = 0; it < 3; ++it) {
        auto tb = Clock::now();
        auto ctAfter = cc->EvalBootstrap(ct);
        times.push_back(Sec(tb));
        Plaintext res;
        cc->Decrypt(keys.secretKey, ctAfter, &res);
        res->SetLength(slots);
        double maxerr = 0;
        for (uint32_t i = 0; i < slots; ++i)
            maxerr = std::max(maxerr, std::abs(res->GetCKKSPackedValue()[i].real() - x[i]));
        bits = (maxerr > 0) ? -std::log2(maxerr) : 60.0;
    }
    std::sort(times.begin(), times.end());
    double med = times[times.size() / 2];

    std::cout << "\n--- RESULT ---\n"
              << "logN=" << logN << " N=" << N << " slots=" << slots << " levelBudget={" << levelBudget[0] << ","
              << levelBudget[1] << "}\n"
              << "bootstrap latency (median of 3, warm): " << std::setprecision(2) << med << " s\n"
              << "amortized: " << std::setprecision(1) << med / slots * 1e6 << " us / real-slot\n"
              << "recovered precision: " << std::setprecision(2) << bits << " bits (maxerr " << std::scientific
              << std::pow(2.0, -bits) << ")\n";
    return 0;
}
