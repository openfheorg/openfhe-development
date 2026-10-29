//==================================================================================
// Item 6.1 check: CI and standard CKKS contexts in ONE process, sharing primes.
// Args: spec [boot]
//   spec: comma-separated list of contexts, created in this order, e.g. "ci12,std12,std13,ci13"
//         (scheme ci|std followed by logN; insecure, FIXEDMANUAL, scaleMod 59, firstMod 60, budget {3,3},
//          CtS-first; a trailing "s" (e.g. "ci12s") makes that context StC-first).
//   boot: 1 (default) also bootstraps once per context; 0 = only EvalMult + rescale.
// All contexts (and their keys) are created first; the operations then run on each context in turn, so every
// context works after all others have registered their moduli. For each context the driver prints the primes it
// shares with earlier contexts (Q and P) and the precision of EvalMult+rescale and of the bootstrap; a context
// fails (exit 1) when a step throws or its precision is below 15 bits (EvalMult) / 7 bits (bootstrap; CI 2^13 / 2^14 {3,3}
// CtS-first alone reach about 9.2 / 7.8-8.3 bits at this setting, before and after item 6.1).
//==================================================================================
#include <algorithm>
#include <cmath>
#include <iostream>
#include <random>
#include <set>
#include <string>
#include <vector>

#include "openfhe.h"

using namespace lbcrypto;

struct Ctx {
    std::string name;
    bool ci;
    bool stcFirst;
    uint32_t logN, slots, depth;
    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> keys;
    std::vector<uint64_t> moduli;  // Q and P
};

static double Bits(const std::vector<double>& want, Plaintext& r, uint32_t slots) {
    r->SetLength(slots);
    double e = 0;
    for (uint32_t i = 0; i < slots; ++i) {
        double d = std::abs(r->GetCKKSPackedValue()[i].real() - want[i]);
        if (!std::isfinite(d))  // a garbage decryption (std::max would skip a NaN)
            return -1;
        e = std::max(e, d);
    }
    return (e > 0) ? -std::log2(e) : 60.0;
}

int main(int argc, char** argv) {
    std::string spec = (argc > 1) ? argv[1] : "ci12,std12";
    bool boot = (argc > 2) ? std::stoul(argv[2]) != 0 : true;
    const std::vector<uint32_t> lb{3, 3};

    std::vector<Ctx> ctxs;
    for (std::string str = spec; !str.empty();) {
        auto pos = str.find(',');
        std::string tok = str.substr(0, pos);
        str = (pos == std::string::npos) ? "" : str.substr(pos + 1);
        Ctx c;
        c.name = tok;
        c.ci = tok.rfind("ci", 0) == 0;
        c.stcFirst = tok.back() == 's';
        c.logN = std::stoul(tok.substr(c.ci ? 2 : 3));
        uint32_t N = 1u << c.logN;
        c.slots = c.ci ? N : N / 2;

        CCParams<CryptoContextCKKSRNS> p;
        if (c.ci)
            p.SetCKKSDataType(REAL_CI);
        p.SetRingDim(N);
        p.SetSecretKeyDist(UNIFORM_TERNARY);
        p.SetScalingTechnique(FIXEDMANUAL);
        p.SetScalingModSize(59);
        p.SetFirstModSize(60);
        p.SetSecurityLevel(HEStd_NotSet);
        // StC-first contexts get one extra level: GenCryptoContext returns the cached context for equal
        // parameters, so "ci12" and "ci12s" would otherwise share one context (and one bootstrap setup).
        c.depth = 2 + FHECKKSRNS::GetBootstrapDepth(lb, UNIFORM_TERNARY) + (c.stcFirst ? 1 : 0);
        p.SetMultiplicativeDepth(c.depth);
        c.cc = GenCryptoContext(p);
        c.cc->Enable(PKE);
        c.cc->Enable(KEYSWITCH);
        c.cc->Enable(LEVELEDSHE);
        c.cc->Enable(ADVANCEDSHE);
        c.cc->Enable(FHE);
        for (auto& m : c.cc->GetCryptoParameters()->GetElementParams()->GetParams())
            c.moduli.push_back(m->GetModulus().ConvertToInt());
        auto cpr = std::dynamic_pointer_cast<CryptoParametersRNS>(c.cc->GetCryptoParameters());
        for (auto& m : cpr->GetParamsP()->GetParams())
            c.moduli.push_back(m->GetModulus().ConvertToInt());

        size_t shared = 0;
        std::set<std::string> with;
        for (auto& o : ctxs)
            for (auto q : c.moduli)
                if (std::find(o.moduli.begin(), o.moduli.end(), q) != o.moduli.end()) {
                    ++shared;
                    with.insert(o.name);
                }
        std::cout << "CTX " << c.name << " towers(Q+P)=" << c.moduli.size() << " shared_with_earlier=" << shared;
        for (auto& w : with)
            std::cout << " " << w;
        std::cout << std::endl;

        if (boot)
            c.cc->EvalBootstrapSetup(lb, {0, 0}, c.slots, 0, true, c.stcFirst);
        c.keys = c.cc->KeyGen();
        c.cc->EvalMultKeyGen(c.keys.secretKey);
        if (boot)
            c.cc->EvalBootstrapKeyGen(c.keys.secretKey, c.slots);
        ctxs.push_back(std::move(c));
    }

    int fails = 0;
    std::mt19937_64 rng(61);
    std::uniform_real_distribution<double> U(-1.0, 1.0);
    for (auto& c : ctxs) {
        std::vector<double> x(c.slots), y(c.slots), xy(c.slots);
        for (uint32_t i = 0; i < c.slots; ++i) {
            x[i] = U(rng);
            y[i] = U(rng);
            xy[i] = x[i] * y[i];
        }
        double mulBits = -1, bootBits = -1;
        std::string err;
        try {
            auto cx = c.cc->Encrypt(c.keys.publicKey, c.cc->MakeCKKSPackedPlaintext(x, 1, 0, nullptr, c.slots));
            auto cy = c.cc->Encrypt(c.keys.publicKey, c.cc->MakeCKKSPackedPlaintext(y, 1, 0, nullptr, c.slots));
            auto m = c.cc->Rescale(c.cc->EvalMult(cx, cy));
            Plaintext r;
            c.cc->Decrypt(c.keys.secretKey, m, &r);
            mulBits = Bits(xy, r, c.slots);
            if (boot) {
                const uint32_t lvl = c.stcFirst ? c.depth - lb[1] - 1 : c.depth - 1;
                auto ct = c.cc->Encrypt(c.keys.publicKey, c.cc->MakeCKKSPackedPlaintext(x, 1, lvl, nullptr, c.slots));
                auto o = c.cc->EvalBootstrap(ct);
                Plaintext rb;
                c.cc->Decrypt(c.keys.secretKey, o, &rb);
                bootBits = Bits(x, rb, c.slots);
            }
        } catch (const std::exception& e) {
            err = e.what();
        }
        bool ok = err.empty() && mulBits >= 15 && (!boot || bootBits >= 7);
        fails += !ok;
        std::cout << "RESULT ctx=" << c.name << " mult_bits=" << mulBits << " boot_bits=" << bootBits << " ok=" << ok;
        if (!err.empty())
            std::cout << " error=\"" << err.substr(0, 160) << "\"";
        std::cout << std::endl;
    }
    std::cout << "SUMMARY spec=" << spec << " boot=" << boot << " fails=" << fails << std::endl;
    return fails ? 1 : 0;
}
