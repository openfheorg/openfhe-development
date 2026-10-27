//==================================================================================
// CI (native conjugate-invariant, N real slots) vs standard CKKS (N/2 slots of real data)
// bootstrap: latency + precision at matched ring dimension and level budget.
// Args: scheme(ci|std) logN lbEnc lbDec scaleMod firstMod secure(0|1) reps scaling(fm|fa) corr secret(uniform|encap)
//       [stcfirst: 0 = CtS-first (default), 1 = EvalBootstrapSetup with BTSlotsEncoding = true,
//        2 = call EvalBootstrapStCFirst directly; 1 and 2 must throw for ci]
// Thread count: OMP_NUM_THREADS. First bootstrap (includes lazy diagonal precompute) is
// reported separately; the warm bootstraps are what count.
//==================================================================================
#include "openfhe.h"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <string>
#include <vector>

using namespace lbcrypto;
using Clock = std::chrono::steady_clock;
static double Sec(Clock::time_point t0) { return std::chrono::duration<double>(Clock::now() - t0).count(); }
static double RssGB() {
    std::ifstream f("/proc/self/status");
    std::string k;
    while (f >> k)
        if (k == "VmHWM:") {
            double kb;
            f >> kb;
            return kb / 1048576.0;
        }
    return 0;
}

int main(int argc, char** argv) {
    std::string scheme = (argc > 1) ? argv[1] : "ci";
    uint32_t logN      = (argc > 2) ? std::stoul(argv[2]) : 12;
    uint32_t lbEnc     = (argc > 3) ? std::stoul(argv[3]) : 3;
    uint32_t lbDec     = (argc > 4) ? std::stoul(argv[4]) : 3;
    uint32_t scaleMod  = (argc > 5) ? std::stoul(argv[5]) : 59;
    uint32_t firstMod  = (argc > 6) ? std::stoul(argv[6]) : 60;
    bool secure        = (argc > 7) ? std::stoul(argv[7]) != 0 : false;
    uint32_t reps      = (argc > 8) ? std::stoul(argv[8]) : 2;
    std::string sc     = (argc > 9) ? argv[9] : "fm";
    uint32_t corr      = (argc > 10) ? std::stoul(argv[10]) : 0;  // 0 = OpenFHE default
    std::string dist   = (argc > 11) ? argv[11] : "uniform";        // uniform | encap
    uint32_t stcFirst  = (argc > 12) ? std::stoul(argv[12]) : 0;
    bool isCI          = (scheme == "ci");
    uint32_t N         = 1u << logN;
    std::vector<uint32_t> levelBudget = {lbEnc, lbDec};
    SecretKeyDist skd                 = (dist == "encap") ? SPARSE_ENCAPSULATED : UNIFORM_TERNARY;
    uint32_t levelsAfter              = 2;

    CCParams<CryptoContextCKKSRNS> parameters;
    if (isCI)
        parameters.SetCKKSDataType(REAL_CI);
    parameters.SetRingDim(N);
    parameters.SetSecretKeyDist(skd);
    parameters.SetScalingTechnique(sc == "fa" ? FLEXIBLEAUTO : FIXEDMANUAL);
    parameters.SetScalingModSize(scaleMod);
    parameters.SetFirstModSize(firstMod);
    parameters.SetSecurityLevel(secure ? HEStd_128_classic : HEStd_NotSet);
    uint32_t bootDepth = FHECKKSRNS::GetBootstrapDepth(levelBudget, skd);
    uint32_t depth     = levelsAfter + bootDepth;
    parameters.SetMultiplicativeDepth(depth);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    uint32_t slots = isCI ? N : N / 2;
    double log2Q   = 0;
    for (auto& p : cc->GetCryptoParameters()->GetElementParams()->GetParams())
        log2Q += std::log2(p->GetModulus().ConvertToDouble());
    double log2P = 0;
    auto cpr     = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
    for (auto& p : cpr->GetParamsP()->GetParams())
        log2P += std::log2(p->GetModulus().ConvertToDouble());

    auto t0 = Clock::now();
    cc->EvalBootstrapSetup(levelBudget, {0, 0}, slots, corr, true, stcFirst == 1);
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalBootstrapKeyGen(keys.secretKey, slots);
    double setupSec = Sec(t0);
    size_t nKeys    = cc->GetEvalAutomorphismKeyMap(keys.secretKey->GetKeyTag()).size();

    std::vector<double> x(slots);
    std::mt19937_64 rng(2026);
    std::uniform_real_distribution<double> U(-1.0, 1.0);
    for (auto& v : x)
        v = U(rng);
    auto pt = cc->MakeCKKSPackedPlaintext(x, 1, depth - 1, nullptr, slots);
    auto ct = cc->Encrypt(keys.publicKey, pt);

    double lastRms = 0, lastP99 = 0;
    auto prec = [&](const Ciphertext<DCRTPoly>& c) {
        Plaintext r;
        cc->Decrypt(keys.secretKey, c, &r);
        r->SetLength(slots);
        double e = 0, ss = 0;
        std::vector<double> errs(slots);
        for (uint32_t i = 0; i < slots; ++i) {
            errs[i] = std::abs(r->GetCKKSPackedValue()[i].real() - x[i]);
            e       = std::max(e, errs[i]);
            ss += errs[i] * errs[i];
        }
        std::sort(errs.begin(), errs.end());
        lastRms = -std::log2(std::sqrt(ss / slots));
        lastP99 = -std::log2(errs[static_cast<size_t>(0.99 * (slots - 1))]);
        return (e > 0) ? -std::log2(e) : 60.0;
    };

    if (stcFirst == 2)
        cc->EvalBootstrapStCFirst(ct);
    auto tf      = Clock::now();
    auto first   = cc->EvalBootstrap(ct);
    double fSec  = Sec(tf);
    double fBits = prec(first);
    std::vector<double> times, bits;
    for (uint32_t r = 0; r < reps; ++r) {
        auto tb = Clock::now();
        auto o  = cc->EvalBootstrap(ct);
        times.push_back(Sec(tb));
        bits.push_back(prec(o));
        if (r == 0)
            std::cout << "out level=" << o->GetLevel() << " towers=" << o->GetElements()[0].GetNumOfElements() << "\n";
    }
    std::sort(times.begin(), times.end());
    double med  = times.empty() ? fSec : times[times.size() / 2];
    double minB = bits.empty() ? fBits : *std::min_element(bits.begin(), bits.end());
    std::cout << std::fixed << std::setprecision(3) << "RESULT scheme=" << scheme << " logN=" << logN << " budget={"
              << lbEnc << "," << lbDec << "} sc=" << sc << " scaleMod=" << scaleMod << " firstMod=" << firstMod
              << " secure=" << secure << " dist=" << dist << " corr=" << corr << " corrEff=" << cc->GetCKKSBootCorrectionFactor() << " slots=" << slots << " depth=" << depth << " log2Q=" << std::setprecision(0)
              << log2Q << " log2P=" << log2P << " galoisKeys=" << nKeys << std::setprecision(3)
              << " setup+keygen_s=" << setupSec << " first_s=" << fSec << " warm_median_s=" << med
              << " us_per_real_slot=" << med / slots * 1e6 << " prec_bits_min=" << std::setprecision(2) << minB
              << " first_prec=" << fBits << " rms_bits=" << lastRms << " p99_bits=" << lastP99 << " peakRSS_GB=" << RssGB() << " threads="
              << (getenv("OMP_NUM_THREADS") ? getenv("OMP_NUM_THREADS") : "?") << std::endl;
    return 0;
}
