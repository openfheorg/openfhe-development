//==================================================================================
// Per-operation cost, CI (REAL_CI, N real slots) vs standard CKKS, at the same ring dimension and tower count.
// Item 4.2 of ci-ckks-paper/PLAN_PHASE2.md.
// Args: scheme(ci|std) logN depth secure(0|1) reps iters [towers list, comma separated; default "full,half,4"]
//   The chain is FIXEDMANUAL 59/60 (same tower count as the FLEXIBLEAUTO bootstrap chain of the same depth), uniform
//   ternary secret, dnum = OpenFHE default. Only the relinearization key and one rotation key (Galois element 5) are
//   generated. Every op is timed `iters` times per rep; the rep loop is outermost, so speed changes of the laptop hit
//   all ops alike. Every op call is followed by a calibrator call (a std NTT round trip per tower on a fixed prime that
//   is in neither chain: identical work in both processes), and "norm" = op / calibrator per iteration cancels the
//   laptop's speed state. Output: one "OP" line per (rep, towers, op) with the medians of the iters (ms, norm), then
//   "OPMED" lines with the medians over reps. Run CI and std in separate processes: they must not share a process (a CI context
//   registers its primes as CI moduli, plan item 6.1).
// Ops (all at the given tower count; "ext" = extended basis Q_l P):
//   add      EvalAdd ct + ct
//   ptmult   EvalMult ct x pt (Hadamard products, no NTT: the same work in both schemes; the calibrator)
//   tensor   EvalMultNoRelin ct x ct
//   relin    Relinearize of the 3-element tensor (one key switch: ModUp + inner product + ModDown)
//   mult     EvalMult ct x ct (tensor + relin)
//   rescale  Rescale of the product (drops one tower: INTT of the last tower, NTT into the others)
//   rotate   EvalAutomorphism by Galois element 5 (one full key switch + automorphism)
//   modup    EvalFastRotationPrecompute (digit decomposition + basis extension, hoisted rotations)
//   rotext   EvalFastRotationExt (hoisted rotation in the extended basis: key inner product + automorphism)
//   ksdown   KeySwitchDown of a rotext result (ModDown of both elements)
//   ntt      one DCRTPoly element: INTT + NTT round trip over all towers
//   automorph one DCRTPoly element: AutomorphismTransform (permutation only)
//   automap  PrecomputeAutoMap / PrecomputeAutoMapCI for one Galois element (once per rotation call)
//==================================================================================
#include "openfhe.h"
#include "math/ci-transform.h"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <functional>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

using namespace lbcrypto;
using Clock = std::chrono::steady_clock;

static double MedianOf(std::vector<double> v) {
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

int main(int argc, char** argv) {
    std::string scheme = (argc > 1) ? argv[1] : "ci";
    uint32_t logN      = (argc > 2) ? std::stoul(argv[2]) : 12;
    uint32_t depth     = (argc > 3) ? std::stoul(argv[3]) : 10;
    bool secure        = (argc > 4) ? std::stoul(argv[4]) != 0 : false;
    uint32_t reps      = (argc > 5) ? std::stoul(argv[5]) : 3;
    uint32_t iters     = (argc > 6) ? std::stoul(argv[6]) : 5;
    std::string tlist  = (argc > 7) ? argv[7] : "full,half,4";
    const bool isCI    = (scheme == "ci");
    const uint32_t N   = 1u << logN;

    CCParams<CryptoContextCKKSRNS> pr;
    if (isCI)
        pr.SetCKKSDataType(REAL_CI);
    pr.SetRingDim(N);
    pr.SetSecurityLevel(secure ? HEStd_128_classic : HEStd_NotSet);
    pr.SetScalingTechnique(FIXEDMANUAL);
    pr.SetScalingModSize(59);
    pr.SetFirstModSize(60);
    pr.SetMultiplicativeDepth(depth);
    pr.SetSecretKeyDist(UNIFORM_TERNARY);
    auto cc = GenCryptoContext(pr);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    auto cpr          = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
    const uint32_t L1 = cc->GetCryptoParameters()->GetElementParams()->GetParams().size();
    std::cout << "CONFIG scheme=" << scheme << " logN=" << logN << " depth=" << depth << " towersQ=" << L1
              << " towersP=" << cpr->GetParamsP()->GetParams().size() << " dnum=" << cpr->GetNumPartQ()
              << " secure=" << secure << " reps=" << reps << " iters=" << iters << " threads="
              << (getenv("OMP_NUM_THREADS") ? getenv("OMP_NUM_THREADS") : "?") << std::endl;

    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    const uint32_t galois = 5;  // CI: 5^1 mod 4N; std: rotation by 1 slot = 5 mod 2N
    if (isCI)
        cc->EvalAutomorphismKeyGen(keys.secretKey, {galois});
    else
        cc->EvalRotateKeyGen(keys.secretKey, {1});
    const uint32_t rotIdxExt = isCI ? galois : 1;  // EvalFastRotationExt takes the CI Galois element directly
    auto& km                 = cc->GetEvalAutomorphismKeyMap(keys.secretKey->GetKeyTag());

    const uint32_t slots = isCI ? N : N / 2;
    std::vector<double> x(slots), y(slots);
    std::mt19937_64 rng(42);
    std::uniform_real_distribution<double> U(-1.0, 1.0);
    for (uint32_t i = 0; i < slots; ++i) {
        x[i] = U(rng);
        y[i] = U(rng);
    }

    // tower counts to measure
    std::vector<uint32_t> towers;
    {
        std::stringstream ss(tlist);
        std::string tok;
        while (std::getline(ss, tok, ',')) {
            uint32_t t = (tok == "full") ? L1 : (tok == "half") ? (L1 + 1) / 2 : std::stoul(tok);
            if (t >= 2 && t <= L1)
                towers.push_back(t);
        }
    }

    struct LevelData {
        uint32_t t;
        Ciphertext<DCRTPoly> a, b, prod3, prod, ext;
        Plaintext p;
        std::shared_ptr<std::vector<DCRTPoly>> digits;
    };
    std::vector<LevelData> lv;
    for (uint32_t t : towers) {
        LevelData d;
        d.t           = t;
        uint32_t lvl  = L1 - t;
        d.a           = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(x, 1, lvl, nullptr, slots));
        d.b           = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(y, 1, lvl, nullptr, slots));
        d.p           = cc->MakeCKKSPackedPlaintext(y, 1, lvl, nullptr, slots);
        d.prod3       = cc->EvalMultNoRelin(d.a, d.b);
        d.prod        = cc->EvalMult(d.a, d.b);
        d.digits      = cc->EvalFastRotationPrecompute(d.a);
        d.ext         = cc->EvalFastRotationExt(d.a, rotIdxExt, d.digits, true);
        // sanity: x * y after rescale
        Plaintext r;
        cc->Decrypt(keys.secretKey, cc->Rescale(d.prod), &r);
        r->SetLength(slots);
        double mx = 0;
        for (uint32_t i = 0; i < slots; ++i)
            mx = std::max(mx, std::abs(r->GetCKKSPackedValue()[i].real() - x[i] * y[i]));
        std::cout << "CHECK scheme=" << scheme << " towers=" << t << " mult_rescale_max_bits=" << std::fixed
                  << std::setprecision(2) << -std::log2(mx) << std::endl;
        lv.push_back(std::move(d));
    }

    using Op = std::pair<std::string, std::function<void(LevelData&)>>;
    std::vector<uint32_t> amap(N);
    std::vector<Op> ops = {
        {"add", [&](LevelData& d) { auto c = cc->EvalAdd(d.a, d.b); }},
        {"ptmult", [&](LevelData& d) { auto c = cc->EvalMult(d.a, d.p); }},
        {"tensor", [&](LevelData& d) { auto c = cc->EvalMultNoRelin(d.a, d.b); }},
        {"relin", [&](LevelData& d) { auto c = cc->Relinearize(d.prod3); }},
        {"mult", [&](LevelData& d) { auto c = cc->EvalMult(d.a, d.b); }},
        {"rescale", [&](LevelData& d) { auto c = cc->Rescale(d.prod); }},
        {"rotate", [&](LevelData& d) { auto c = cc->EvalAutomorphism(d.a, galois, km); }},
        {"modup", [&](LevelData& d) { auto g = cc->EvalFastRotationPrecompute(d.a); }},
        {"rotext", [&](LevelData& d) { auto c = cc->EvalFastRotationExt(d.a, rotIdxExt, d.digits, true); }},
        {"ksdown", [&](LevelData& d) { auto c = cc->KeySwitchDown(d.ext); }},
        {"ntt",
         [&](LevelData& d) {
             DCRTPoly e = d.a->GetElements()[0];
             e.SwitchFormat();
             e.SwitchFormat();
         }},
        {"automorph",
         [&](LevelData& d) {
             if (isCI)
                 PrecomputeAutoMapCI(N, galois, &amap);
             else
                 PrecomputeAutoMap(N, galois, &amap);
             auto e = d.a->GetElements()[0].AutomorphismTransform(galois, amap);
         }},
        {"automap",
         [&](LevelData& d) {
             if (isCI)
                 PrecomputeAutoMapCI(N, galois, &amap);
             else
                 PrecomputeAutoMap(N, galois, &amap);
         }},
    };

    // Calibrator: the plain (std) negacyclic NTT round trip, called directly through ChineseRemainderTransformFTT on
    // a fixed 58-bit prime that is in neither chain, once per tower. It is the same code and data in both
    // processes, so op / calib (timed back to back in every iteration) cancels the laptop's speed state.
    const NativeInteger cq    = FirstPrime<NativeInteger>(58, 2 * N);  // both chains use 59- and 60-bit primes
    const NativeInteger croot = RootOfUnity<NativeInteger>(2 * N, cq);
    NativeVector cvec(N, cq);
    for (uint32_t i = 0; i < N; ++i)
        cvec[i] = NativeInteger(rng()).Mod(cq);
    auto calib = [&](uint32_t t) {
        for (uint32_t k = 0; k < t; ++k) {
            ChineseRemainderTransformFTT<NativeVector>().ForwardTransformToBitReverseInPlace(croot, 2 * N, &cvec);
            ChineseRemainderTransformFTT<NativeVector>().InverseTransformFromBitReverseInPlace(croot, 2 * N, &cvec);
        }
    };
    std::cout << "CALIB prime=" << cq << " registeredCI=" << IsCIModulus(cq) << std::endl;

    // results[towersIdx][opIdx] = per-rep medians (ms, and op / calib)
    std::vector<std::vector<std::vector<double>>> res(lv.size(), std::vector<std::vector<double>>(ops.size()));
    auto resN = res;
    for (uint32_t r = 0; r < reps; ++r) {
        for (size_t li = 0; li < lv.size(); ++li) {
            for (size_t oi = 0; oi < ops.size(); ++oi) {
                ops[oi].second(lv[li]);  // warm-up
                std::vector<double> ts, tn;
                for (uint32_t it = 0; it < iters; ++it) {
                    auto t0 = Clock::now();
                    ops[oi].second(lv[li]);
                    auto t1 = Clock::now();
                    calib(lv[li].t);
                    auto t2   = Clock::now();
                    double to = std::chrono::duration<double, std::milli>(t1 - t0).count();
                    double tc = std::chrono::duration<double, std::milli>(t2 - t1).count();
                    ts.push_back(to);
                    tn.push_back(to / tc);
                }
                res[li][oi].push_back(MedianOf(ts));
                resN[li][oi].push_back(MedianOf(tn));
                std::cout << "OP scheme=" << scheme << " rep=" << r << " towers=" << lv[li].t << " op=" << ops[oi].first
                          << " ms=" << std::setprecision(3) << res[li][oi].back() << " norm=" << std::setprecision(5)
                          << resN[li][oi].back() << std::endl;
            }
        }
    }
    for (size_t li = 0; li < lv.size(); ++li)
        for (size_t oi = 0; oi < ops.size(); ++oi)
            std::cout << "OPMED scheme=" << scheme << " towers=" << lv[li].t << " op=" << ops[oi].first
                      << " ms=" << std::setprecision(3) << MedianOf(res[li][oi]) << " norm=" << std::setprecision(5)
                      << MedianOf(resN[li][oi]) << std::endl;
    return 0;
}
