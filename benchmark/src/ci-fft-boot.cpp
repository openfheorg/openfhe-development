//==================================================================================
// CI (native conjugate-invariant, N real slots) vs standard CKKS (N/2 slots of real data)
// bootstrap: latency + precision at matched ring dimension and level budget.
// Args: scheme(ci|std) logN lbEnc lbDec scaleMod firstMod secure(0|1) reps scaling(fm|fa) corr secret(uniform|encap)
//       [stcfirst: 0 = CtS-first (default), 1 = EvalBootstrapSetup with BTSlotsEncoding = true (StC-first; the
//        input is encrypted with lbDec + 2 towers, the StC input level; CI since item 2.5),
//        2 = call EvalBootstrapStCFirst directly on a CtS-first setup (must throw for ci)]
//       [dnum: number of large digits for HYBRID key switching (SetNumLargeDigits); 0 = OpenFHE default]
//       [after: levels left for the application after the bootstrap; default 2 (the paper uses 3)]
//       [iters: EvalBootstrap numIterations, 1 (default) or 2 (META-BTS; the chain gets iters - 1 more levels)]
//       [metaprec: the META-BTS precision argument in bits; 0 (default) = floor of the min precision of the
//        first bootstrap, which then runs with 1 iteration (as OpenFHE's iterative-ckks-bootstrapping example)]
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
    uint32_t dnum      = (argc > 13) ? std::stoul(argv[13]) : 0;  // 0 = OpenFHE default (3 for depth > 3)
    uint32_t after     = (argc > 14) ? std::stoul(argv[14]) : 2;
    uint32_t iters     = (argc > 15) ? std::stoul(argv[15]) : 1;
    uint32_t metaPrec  = (argc > 16) ? std::stoul(argv[16]) : 0;
    bool isCI          = (scheme == "ci");
    uint32_t N         = 1u << logN;
    std::vector<uint32_t> levelBudget = {lbEnc, lbDec};
    SecretKeyDist skd                 = (dist == "encap") ? SPARSE_ENCAPSULATED : UNIFORM_TERNARY;
    uint32_t levelsAfter              = after;

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
    uint32_t depth     = levelsAfter + bootDepth + (iters - 1);
    parameters.SetMultiplicativeDepth(depth);
    if (dnum > 0)
        parameters.SetNumLargeDigits(dnum);

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
    size_t towersQ = cc->GetCryptoParameters()->GetElementParams()->GetParams().size();
    double log2P = 0;
    auto cpr     = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
    for (auto& p : cpr->GetParamsP()->GetParams())
        log2P += std::log2(p->GetModulus().ConvertToDouble());

    std::cout << "chain Q bits (q0 first):";
    for (auto& p : cc->GetCryptoParameters()->GetElementParams()->GetParams())
        std::cout << " " << std::lround(std::log2(p->GetModulus().ConvertToDouble()));
    std::cout << " | P bits:";
    for (auto& p : cpr->GetParamsP()->GetParams())
        std::cout << " " << std::lround(std::log2(p->GetModulus().ConvertToDouble()));
    std::cout << std::endl;

    auto t0 = Clock::now();
    cc->EvalBootstrapSetup(levelBudget, {0, 0}, slots, corr, true, stcFirst == 1);
    double bootSetupSec = Sec(t0);  // EvalBootstrapSetup alone (CI: includes the diagonal encodes, item 2.4)
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalBootstrapKeyGen(keys.secretKey, slots);
    double setupSec = Sec(t0);
    auto& autoKeys  = cc->GetEvalAutomorphismKeyMap(keys.secretKey->GetKeyTag());
    size_t nKeys    = autoKeys.size();
    // Size of one switching key: dnum (a, b) pairs, each over the full Q*P basis.
    auto keyBytes = [&](const EvalKey<DCRTPoly>& k) {
        double b = 0;
        for (auto& v : k->GetAVector())
            b += double(v.GetNumOfElements()) * v.GetRingDimension() * 8;
        for (auto& v : k->GetBVector())
            b += double(v.GetNumOfElements()) * v.GetRingDimension() * 8;
        return b;
    };
    double keyMB = autoKeys.empty() ? 0 : keyBytes(autoKeys.begin()->second) / 1048576.0;
    double allKeysGB = 0;
    for (auto& kv : autoKeys)
        allKeysGB += keyBytes(kv.second);
    for (auto& k : cc->GetEvalMultKeyVector(keys.secretKey->GetKeyTag()))
        allKeysGB += keyBytes(k);
    allKeysGB /= 1073741824.0;

    std::vector<double> x(slots);
    std::mt19937_64 rng(2026);
    std::uniform_real_distribution<double> U(-1.0, 1.0);
    for (auto& v : x)
        v = U(rng);
    // CtS-first: 2 towers (one for the correction-factor adjust before the ModRaise). StC-first: lbDec + 2 towers
    // (StC runs on the input; EvalBootstrapStCFirst / the CI StC-first branch need exactly this level or above).
    const uint32_t encLevel = (stcFirst == 1) ? depth - lbDec - 1 : depth - 1;
    auto pt = cc->MakeCKKSPackedPlaintext(x, 1, encLevel, nullptr, slots);
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
    // META-BTS with metaprec 0: the first bootstrap runs with 1 iteration and sets the precision argument.
    const bool autoPrec = (iters > 1 && metaPrec == 0);
    auto tf      = Clock::now();
    auto first   = cc->EvalBootstrap(ct, autoPrec ? 1 : iters, metaPrec);
    double fSec  = Sec(tf);
    double fBits = prec(first);
    if (autoPrec)
        metaPrec = static_cast<uint32_t>(std::floor(fBits));
    // EvalBootstrap returns a clone of the input when its output would not have more towers than the input.
    bool passthrough = false;
    std::vector<double> times, bits;
    for (uint32_t r = 0; r < reps; ++r) {
        auto tb = Clock::now();
        auto o  = cc->EvalBootstrap(ct, iters, metaPrec);
        times.push_back(Sec(tb));
        bits.push_back(prec(o));
        if (o->GetElements()[0].GetNumOfElements() <= ct->GetElements()[0].GetNumOfElements())
            passthrough = true;
        if (r == 0)
            std::cout << "in level=" << ct->GetLevel() << " towers=" << ct->GetElements()[0].GetNumOfElements()
                      << " | out level=" << o->GetLevel() << " towers=" << o->GetElements()[0].GetNumOfElements()
                      << " noiseScaleDeg=" << o->GetNoiseScaleDeg() << "\n";
    }
    std::sort(times.begin(), times.end());
    double med  = times.empty() ? fSec : times[times.size() / 2];
    double minB = bits.empty() ? fBits : *std::min_element(bits.begin(), bits.end());
    std::cout << std::fixed << std::setprecision(3) << "RESULT scheme=" << scheme << " logN=" << logN << " budget={"
              << lbEnc << "," << lbDec << "} sc=" << sc << " scaleMod=" << scaleMod << " firstMod=" << firstMod
              << " secure=" << secure << " dist=" << dist << " corr=" << corr << " corrEff=" << cc->GetCKKSBootCorrectionFactor() << " stcfirst=" << stcFirst << " iters=" << iters << " metaprec=" << metaPrec << " passthrough=" << passthrough << " slots=" << slots << " depth=" << depth << " after=" << levelsAfter << " towersQ=" << towersQ << " log2Q=" << std::setprecision(0)
              << log2Q << " log2P=" << log2P << " dnum=" << cpr->GetNumPartQ() << " alpha=" << cpr->GetNumPerPartQ()
              << " towersP=" << cpr->GetParamsP()->GetParams().size() << " galoisKeys=" << nKeys
              << std::setprecision(1) << " keyMB=" << keyMB << std::setprecision(3) << " keysGB=" << allKeysGB
              << " setup+keygen_s=" << setupSec << " bootsetup_s=" << bootSetupSec << " first_s=" << fSec << " warm_median_s=" << med
              << " us_per_real_slot=" << med / slots * 1e6 << " prec_bits_min=" << std::setprecision(2) << minB
              << " first_prec=" << fBits << " rms_bits=" << lastRms << " p99_bits=" << lastP99 << " peakRSS_GB=" << RssGB() << " threads="
              << (getenv("OMP_NUM_THREADS") ? getenv("OMP_NUM_THREADS") : "?") << std::endl;
    return 0;
}
