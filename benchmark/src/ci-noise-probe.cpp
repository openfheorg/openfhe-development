// Noise probe: CI vs std CKKS basic-operation precision vs ring dimension.
// Args: scheme(ci|std) logN scaleMod. Prints -log2(max err) and -log2(rms err) for:
// fresh enc, mult+rescale, rotation (by 1 slot), 6 chained squarings (x -> 2x^2-1).
#include "openfhe.h"
#include <cmath>
#include <iomanip>
#include <iostream>
#include <random>
using namespace lbcrypto;

int main(int argc, char** argv) {
    std::string scheme = (argc > 1) ? argv[1] : "ci";
    uint32_t logN      = (argc > 2) ? std::stoul(argv[2]) : 12;
    uint32_t scaleMod  = (argc > 3) ? std::stoul(argv[3]) : 50;
    std::string sc     = (argc > 4) ? argv[4] : "fm";
    bool isCI          = scheme == "ci";
    uint32_t N         = 1u << logN, slots = isCI ? N : N / 2;
    CCParams<CryptoContextCKKSRNS> pr;
    if (isCI)
        pr.SetCKKSDataType(REAL_CI);
    pr.SetRingDim(N);
    pr.SetSecurityLevel(HEStd_NotSet);
    pr.SetScalingTechnique(sc == "fa" ? FLEXIBLEAUTO : FIXEDMANUAL);
    pr.SetScalingModSize(scaleMod);
    pr.SetFirstModSize(60);
    pr.SetMultiplicativeDepth(8);
    pr.SetSecretKeyDist(UNIFORM_TERNARY);
    auto cc = GenCryptoContext(pr);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    auto k = cc->KeyGen();
    cc->EvalMultKeyGen(k.secretKey);
    if (isCI) {
        // CI rotation by one g=5 step = Galois element 5
        cc->EvalAutomorphismKeyGen(k.secretKey, {5});
    }
    else {
        cc->EvalRotateKeyGen(k.secretKey, {1});
    }
    std::vector<double> x(slots);
    std::mt19937_64 g(7);
    std::uniform_real_distribution<double> U(-1, 1);
    for (auto& v : x)
        v = U(g);
    auto ct = cc->Encrypt(k.publicKey, cc->MakeCKKSPackedPlaintext(x, 1, 0, nullptr, slots));
    auto rep = [&](const char* name, const Ciphertext<DCRTPoly>& c, const std::vector<double>& ref) {
        Plaintext p;
        cc->Decrypt(k.secretKey, c, &p);
        p->SetLength(slots);
        double mx = 0, ss = 0;
        for (uint32_t i = 0; i < slots; ++i) {
            double e = std::abs(p->GetCKKSPackedValue()[i].real() - ref[i]);
            mx       = std::max(mx, e);
            ss += e * e;
        }
        std::cout << std::fixed << std::setprecision(2) << "PROBE " << scheme << " " << sc << " logN=" << logN << " " << name
                  << " max_bits=" << -std::log2(mx) << " rms_bits=" << -std::log2(std::sqrt(ss / slots)) << "\n";
    };
    rep("fresh", ct, x);
    auto sq = cc->EvalMult(ct, ct);
    if (sc != "fa")
        cc->ModReduceInPlace(sq);
    std::vector<double> x2(slots);
    for (uint32_t i = 0; i < slots; ++i)
        x2[i] = x[i] * x[i];
    rep("mult", sq, x2);
    // rotation: compare against decrypted-then-rotated reference
    Ciphertext<DCRTPoly> rot;
    std::vector<double> xr(slots);
    if (isCI) {
        auto km = cc->GetEvalAutomorphismKeyMap(k.secretKey->GetKeyTag());
        rot     = cc->EvalAutomorphism(ct, 5, km);
        Plaintext p0;
        cc->Decrypt(k.secretKey, rot, &p0);  // reference via exact permutation of x: use decrypt of fresh
        // build reference by permuting x with the CI map: find permutation from a noiseless check
        // (rotation is an exact slot permutation; compare sorted multiset instead)
        std::vector<double> a(slots), b(x);
        p0->SetLength(slots);
        for (uint32_t i = 0; i < slots; ++i)
            a[i] = p0->GetCKKSPackedValue()[i].real();
        // match each output slot to the nearest input value (values are distinct uniforms)
        std::vector<std::pair<double, uint32_t>> sb(slots);
        for (uint32_t i = 0; i < slots; ++i)
            sb[i] = {b[i], i};
        std::sort(sb.begin(), sb.end());
        for (uint32_t i = 0; i < slots; ++i) {
            auto it = std::lower_bound(sb.begin(), sb.end(), std::make_pair(a[i], 0u));
            double best = 1e9;
            for (auto jt = (it == sb.begin() ? it : it - 1); jt != sb.end() && jt <= it + 1; ++jt)
                if (std::abs(jt->first - a[i]) < std::abs(best - a[i]))
                    best = jt->first;
            xr[i] = best;
        }
    }
    else {
        rot = cc->EvalRotate(ct, 1);
        for (uint32_t i = 0; i < slots; ++i)
            xr[i] = x[(i + 1) % slots];
    }
    rep("rotate", rot, xr);
    auto c = ct;
    std::vector<double> ref(x);
    for (int t = 0; t < 6; ++t) {
        c = cc->EvalMult(c, c);
        if (sc != "fa")
            cc->ModReduceInPlace(c);
        c = cc->EvalAdd(c, c);
        c = cc->EvalSub(c, 1.0);
        for (auto& v : ref)
            v = 2 * v * v - 1;
    }
    rep("6xdoubleangle", c, ref);
    return 0;
}
