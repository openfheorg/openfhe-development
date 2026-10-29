//==================================================================================
// CI (and std) context + bootstrap-key serialization round trip (item 6.3).
// Args: mode(save|load) dir scheme(ci|std) logN lbEnc lbDec secret(uniform|encap) stcfirst(0|1) iters(1|2)
//   save: builds the context, sets up bootstrapping, generates keys, checks that EvalBootstrapKeyMapIndices equals
//         the generated automorphism key set, bootstraps one ciphertext, and writes the context, the key pair, the
//         input ciphertext, the EvalMult keys, the bootstrap keys (SerializeEvalBootstrapKey) and the bootstrapped
//         ciphertext to dir.
//   load: (run in a fresh process) reads them back, redoes EvalBootstrapSetup on the deserialized context (as
//         ckks-bootstrap-keys-serial.cpp), loads the bootstrap keys with DeserializeEvalBootstrapKey (by context
//         and by the index list), checks the loaded key set, bootstraps the input ciphertext and requires the
//         output to equal the saved one bit for bit and to decrypt to the input.
// Prints "SERIAL-OK ..." and exits 0 on success; any failed check prints "SERIAL-FAIL <reason>" and exits 1.
// Insecure small rings (HEStd_NotSet), FIXEDMANUAL 59/60 bits, 2 levels after the bootstrap.
//==================================================================================
#include "openfhe.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <set>
#include <string>
#include <vector>

using namespace lbcrypto;

static int Fail(const std::string& why) {
    std::cout << "SERIAL-FAIL " << why << std::endl;
    return 1;
}

static std::set<uint32_t> KeySet(const std::map<uint32_t, EvalKey<DCRTPoly>>& m) {
    std::set<uint32_t> s;
    for (auto& kv : m)
        s.insert(kv.first);
    return s;
}

int main(int argc, char** argv) {
    if (argc < 10) {
        std::cerr << "usage: " << argv[0]
                  << " save|load dir ci|std logN lbEnc lbDec uniform|encap stcfirst(0|1) iters(1|2)\n";
        return 2;
    }
    const std::string mode = argv[1], dir = argv[2], scheme = argv[3];
    const uint32_t logN = std::stoul(argv[4]), lbEnc = std::stoul(argv[5]), lbDec = std::stoul(argv[6]);
    const std::string dist = argv[7];
    const bool stcFirst    = std::stoul(argv[8]) != 0;
    const uint32_t iters   = std::stoul(argv[9]);
    const bool isCI        = (scheme == "ci");
    const uint32_t N       = 1u << logN;
    const uint32_t slots   = isCI ? N : N / 2;
    const std::vector<uint32_t> levelBudget = {lbEnc, lbDec};
    const SecretKeyDist skd = (dist == "encap") ? SPARSE_ENCAPSULATED : UNIFORM_TERNARY;
    const uint32_t depth    = 2 + FHECKKSRNS::GetBootstrapDepth(levelBudget, skd) + (iters - 1);
    const uint32_t encLevel = stcFirst ? depth - lbDec - 1 : depth - 1;
    const std::string tag   = "case " + scheme + " logN=" + std::to_string(logN) + " budget={" +
                            std::to_string(lbEnc) + "," + std::to_string(lbDec) + "} " + dist +
                            " stcfirst=" + std::to_string(stcFirst) + " iters=" + std::to_string(iters);
    const auto ST = SerType::BINARY;

    std::vector<double> x(slots);
    std::mt19937_64 rng(2026);
    std::uniform_real_distribution<double> U(-1.0, 1.0);
    for (auto& v : x)
        v = U(rng);
    auto rmsBits = [&](const CryptoContext<DCRTPoly>& cc, const PrivateKey<DCRTPoly>& sk,
                       const Ciphertext<DCRTPoly>& c) {
        Plaintext r;
        cc->Decrypt(sk, c, &r);
        r->SetLength(slots);
        double ss = 0;
        for (uint32_t i = 0; i < slots; ++i) {
            const double e = r->GetCKKSPackedValue()[i].real() - x[i];
            ss += e * e;
        }
        return -std::log2(std::sqrt(ss / slots));
    };
    // META-BTS precision argument: fixed so that save and load run the same computation.
    const uint32_t metaPrec = (iters > 1) ? 12 : 0;

    if (mode == "save") {
        CCParams<CryptoContextCKKSRNS> parameters;
        if (isCI)
            parameters.SetCKKSDataType(REAL_CI);
        parameters.SetRingDim(N);
        parameters.SetSecretKeyDist(skd);
        parameters.SetScalingTechnique(FIXEDMANUAL);
        parameters.SetScalingModSize(59);
        parameters.SetFirstModSize(60);
        parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetMultiplicativeDepth(depth);
        auto cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
        cc->Enable(FHE);
        cc->EvalBootstrapSetup(levelBudget, {0, 0}, slots, 0, true, stcFirst);
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        cc->EvalBootstrapKeyGen(keys.secretKey, slots);

        const auto gen = KeySet(cc->GetEvalAutomorphismKeyMap(keys.secretKey->GetKeyTag()));
        const auto idx = cc->GetScheme()->EvalBootstrapKeyMapIndices(cc, slots);
        const std::set<uint32_t> idxSet(idx.begin(), idx.end());
        size_t onlyIdx = 0, onlyGen = 0;
        for (auto i : idxSet)
            onlyIdx += gen.count(i) ? 0 : 1;
        for (auto g : gen)
            onlyGen += idxSet.count(g) ? 0 : 1;
        std::cout << tag << " | keygen keys=" << gen.size() << " KeyMapIndices=" << idxSet.size()
                  << " (only in indices " << onlyIdx << ", only in keygen " << onlyGen << ")" << std::endl;
        if (idxSet != gen)
            return Fail(tag + ": EvalBootstrapKeyMapIndices differs from the generated key set");

        auto pt = cc->MakeCKKSPackedPlaintext(x, 1, encLevel, nullptr, slots);
        auto ct = cc->Encrypt(keys.publicKey, pt);
        auto out = cc->EvalBootstrap(ct, iters, metaPrec);
        const double bits = rmsBits(cc, keys.secretKey, out);
        std::cout << tag << " | save-side bootstrap rms_bits=" << std::fixed << std::setprecision(2) << bits
                  << std::endl;

        bool ok = Serial::SerializeToFile(dir + "/cc.bin", cc, ST) &&
                  Serial::SerializeToFile(dir + "/sk.bin", keys.secretKey, ST) &&
                  Serial::SerializeToFile(dir + "/ct.bin", ct, ST) && Serial::SerializeToFile(dir + "/out.bin", out, ST);
        if (!ok)
            return Fail(tag + ": serializing context/key/ciphertexts");
        std::ofstream mk(dir + "/mult.bin", std::ios::binary);
        if (!cc->SerializeEvalMultKey(mk, ST))
            return Fail(tag + ": SerializeEvalMultKey");
        mk.close();
        std::ofstream bk(dir + "/boot.bin", std::ios::binary);
        try {
            if (!cc->SerializeEvalBootstrapKey(bk, ST, cc, keys.secretKey->GetKeyTag(), slots))
                return Fail(tag + ": SerializeEvalBootstrapKey returned false");
        }
        catch (const std::exception& e) {
            return Fail(tag + ": SerializeEvalBootstrapKey threw: " + e.what());
        }
        bk.close();
        std::ifstream sz(dir + "/boot.bin", std::ios::binary | std::ios::ate);
        std::cout << "SERIAL-OK save " << tag << " bootKeysMB=" << std::setprecision(1) << sz.tellg() / 1048576.0
                  << " rms_bits=" << std::setprecision(2) << bits << std::endl;
        cc->ClearStaticMapsAndVectors();
        return 0;
    }

    if (mode != "load")
        return Fail("unknown mode " + mode);

    CryptoContext<DCRTPoly> cc;
    PrivateKey<DCRTPoly> sk;
    Ciphertext<DCRTPoly> ct, ref;
    if (!Serial::DeserializeFromFile(dir + "/cc.bin", cc, ST) || !Serial::DeserializeFromFile(dir + "/sk.bin", sk, ST) ||
        !Serial::DeserializeFromFile(dir + "/ct.bin", ct, ST) || !Serial::DeserializeFromFile(dir + "/out.bin", ref, ST))
        return Fail(tag + ": deserializing context/key/ciphertexts");
    if ((cc->GetCKKSDataType() == REAL_CI) != isCI)
        return Fail(tag + ": deserialized context has the wrong CKKS data type");
    for (auto& p : cc->GetCryptoParameters()->GetElementParams()->GetParams())
        if (p->IsConjugateInvariant() != isCI)
            return Fail(tag + ": deserialized element parameters have the wrong ring type");
    cc->EvalBootstrapSetup(levelBudget, {0, 0}, slots, 0, true, stcFirst);
    std::ifstream mk(dir + "/mult.bin", std::ios::binary);
    if (!cc->DeserializeEvalMultKey(mk, ST))
        return Fail(tag + ": DeserializeEvalMultKey");
    const auto idx = cc->GetScheme()->EvalBootstrapKeyMapIndices(cc, slots);
    try {
        std::ifstream bk(dir + "/boot.bin", std::ios::binary);
        if (!cc->DeserializeEvalBootstrapKey(bk, ST, cc, sk->GetKeyTag(), slots))
            return Fail(tag + ": DeserializeEvalBootstrapKey (by context) returned false");
        std::ifstream bk2(dir + "/boot.bin", std::ios::binary);
        if (!cc->DeserializeEvalBootstrapKey(bk2, ST, sk->GetKeyTag(), idx))
            return Fail(tag + ": DeserializeEvalBootstrapKey (by index list) returned false");
    }
    catch (const std::exception& e) {
        return Fail(tag + ": DeserializeEvalBootstrapKey threw: " + e.what());
    }
    const auto loaded = KeySet(cc->GetEvalAutomorphismKeyMap(sk->GetKeyTag()));
    if (loaded != std::set<uint32_t>(idx.begin(), idx.end()))
        return Fail(tag + ": loaded key set differs from EvalBootstrapKeyMapIndices");

    Ciphertext<DCRTPoly> out;
    try {
        out = cc->EvalBootstrap(ct, iters, metaPrec);
    }
    catch (const std::exception& e) {
        return Fail(tag + ": EvalBootstrap with deserialized keys threw: " + e.what());
    }
    const bool same = out->GetElements() == ref->GetElements() && out->GetLevel() == ref->GetLevel() &&
                      out->GetNoiseScaleDeg() == ref->GetNoiseScaleDeg();
    const double bits = rmsBits(cc, sk, out);
    std::cout << tag << " | load-side keys=" << loaded.size() << " bit-exact vs save-side output: " << (same ? 1 : 0)
              << " rms_bits=" << std::fixed << std::setprecision(2) << bits << std::endl;
    if (!same)
        return Fail(tag + ": bootstrap output with deserialized keys differs from the save-side output");
    if (bits < 10)
        return Fail(tag + ": bootstrap output does not decrypt to the input");
    std::cout << "SERIAL-OK load " << tag << " keys=" << loaded.size() << " rms_bits=" << bits << std::endl;
    cc->ClearStaticMapsAndVectors();
    return 0;
}
