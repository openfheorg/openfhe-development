//==================================================================================
// Single-bootstrap latency + precision probe, CI vs standard CKKS, 128-bit settings.
// Args: [scheme: ci|std] [logN] [dist: uniform|sparse] [scaleModSize] [secure: 0|1]
// levelBudget {4,4}. Encrypt at the most-depleted level (L-1), no homomorphic ops, then bootstrap.
// Reports crypto params, per-step level budget, end-to-end bootstrap latency (excl setup/keygen),
// throughput (us/real-slot), and recovered precision. Multi-threaded via OMP_NUM_THREADS.
//
// Precision = -log2( max_i | Re(decode(Dec(Boot(ct))))[i] - x[i] | ) over all real slots, where x
// is the input vector (reals in [-1,1]); i.e. -log2 of the worst-case absolute slot error.
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
    std::string scheme = (argc > 1) ? argv[1] : "std";
    uint32_t logN = (argc > 2) ? std::stoul(argv[2]) : 16;
    std::string distName = (argc > 3) ? argv[3] : "uniform";
    uint32_t scaleModSize = (argc > 4) ? std::stoul(argv[4]) : 59;
    bool secure = (argc > 5) ? (std::stoul(argv[5]) != 0) : true;
    uint32_t firstModSize = (argc > 6) ? std::stoul(argv[6]) : 60;
    uint32_t N = 1u << logN;
    bool isCI = (scheme == "ci");
    SecretKeyDist skd = (distName == "sparse") ? SPARSE_TERNARY : UNIFORM_TERNARY;
    std::vector<uint32_t> levelBudget = {3, 3};
    uint32_t levelsAfter = 2;  // a couple of usable levels after refresh

    std::cout << "\n=== " << (isCI ? "CI" : "std") << " CKKS bootstrap | logN=" << logN << " (N=" << N
              << ") | secret=" << distName << " | scaleMod=" << scaleModSize << " | budget={" << levelBudget[0] << ","
              << levelBudget[1] << "} | secure=" << (secure ? "HEStd_128" : "NotSet") << " ===\n";

    CCParams<CryptoContextCKKSRNS> parameters;
    if (isCI)
        parameters.SetCKKSDataType(REAL_CI);
    parameters.SetRingDim(N);
    parameters.SetSecretKeyDist(skd);
    // CI currently requires FIXEDMANUAL; std uses the standard robust FLEXIBLEAUTO for bootstrap.
    parameters.SetScalingTechnique(isCI ? FIXEDMANUAL : FLEXIBLEAUTO);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetSecurityLevel(secure ? HEStd_128_classic : HEStd_NotSet);
    uint32_t bootDepth = FHECKKSRNS::GetBootstrapDepth(levelBudget, skd);
    uint32_t depth = levelsAfter + bootDepth;
    parameters.SetMultiplicativeDepth(depth);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    uint32_t slots = isCI ? N : N / 2;
    double log2Q = 0;
    for (auto& p : cc->GetCryptoParameters()->GetElementParams()->GetParams())
        log2Q += std::log2(p->GetModulus().ConvertToDouble());

    // per-step level budget: ModRaise lifts to the top modulus (no usable levels spent);
    // CtS spends levelBudget[0], EvalMod spends the middle, StC spends levelBudget[1].
    uint32_t cts = levelBudget[0], stc = levelBudget[1];
    uint32_t evalMod = (bootDepth > cts + stc) ? bootDepth - cts - stc : 0;
    std::cout << "params: ringDim=" << cc->GetRingDimension() << " slots=" << slots << " scaleMod=" << scaleModSize
              << " firstMod=" << firstModSize << " log2(QP-chain)=" << std::fixed << std::setprecision(0) << log2Q
              << " multDepth=" << depth << "\n";
    std::cout << "bootstrap level budget: total=" << bootDepth << "  [ModRaise/ModUp: lifts to top (0 usable)"
              << " | CoeffsToSlots: " << cts << " | EvalMod(ModReduce): " << evalMod << " | SlotsToCoeffs: " << stc
              << "]\n"
              << std::flush;

    cc->EvalBootstrapSetup(levelBudget, {0, 0}, slots);
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    auto tkg = Clock::now();
    cc->EvalBootstrapKeyGen(keys.secretKey, slots);
    double keygenSec = Sec(tkg);
    std::cout << "(setup+keygen: " << std::setprecision(1) << keygenSec << "s, excluded from latency)\n" << std::flush;

    std::vector<double> x(slots);
    std::mt19937_64 rng(2026);
    for (uint32_t i = 0; i < slots; ++i)
        x[i] = 2.0 * (double)(rng() % 1000000) / 1000000.0 - 1.0;  // uniform reals in [-1,1]

    // encrypt at the most depleted level (L-1): noiseScaleDeg 1, level = depth-1 (1 tower left)
    auto pt = cc->MakeCKKSPackedPlaintext(x, 1, depth - 1, nullptr, slots);
    auto ct = cc->Encrypt(keys.publicKey, pt);
    std::cout << "input ct level=" << ct->GetLevel() << " (towers=" << ct->GetElements()[0].GetNumOfElements()
              << "), encrypted at most-depleted level\n"
              << std::flush;

    cc->EvalBootstrap(ct);  // warm-up (paid once; excluded)
    auto tb = Clock::now();
    auto ctAfter = cc->EvalBootstrap(ct);  // the single measured bootstrap
    double bootSec = Sec(tb);

    Plaintext res;
    cc->Decrypt(keys.secretKey, ctAfter, &res);
    res->SetLength(slots);
    double maxerr = 0;
    for (uint32_t i = 0; i < slots; ++i)
        maxerr = std::max(maxerr, std::abs(res->GetCKKSPackedValue()[i].real() - x[i]));
    double bits = (maxerr > 0) ? -std::log2(maxerr) : 60.0;

    std::cout << "\n--- RESULT (" << (isCI ? "CI" : "std") << ", " << distName << ") ---\n"
              << "ct level after boot=" << ctAfter->GetLevel()
              << " (towers=" << ctAfter->GetElements()[0].GetNumOfElements() << ")\n"
              << "bootstrap latency (end-to-end, excl setup/keygen): " << std::setprecision(2) << bootSec << " s\n"
              << "throughput: " << std::setprecision(2) << bootSec / slots * 1e6 << " us / real-slot\n"
              << "precision: " << std::setprecision(2) << bits << " bits  (maxerr " << std::scientific << maxerr
              << ")\n";
    return 0;
}
