//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

#include "lwe-pke.h"
#include "math/binaryuniformgenerator.h"
#include "math/discreteuniformgenerator.h"
#include "math/ternaryuniformgenerator.h"
#include "utils/parallel.h"

namespace lbcrypto {

// the main rounding operation used in ModSwitch (as described in Section 3 of
// https://eprint.iacr.org/2014/816) The idea is that Round(x) = 0.5 + Floor(x)
static inline NativeInteger RoundqQ(NativeInteger v, NativeInteger q, NativeInteger Q) {
    return NativeInteger(static_cast<BasicInteger>(
                             std::floor(0.5 + v.ConvertToDouble() * q.ConvertToDouble() / Q.ConvertToDouble())))
        .Mod(q);
}

LWEPrivateKey LWEEncryptionScheme::KeyGen(uint32_t size, NativeInteger modulus) const {
    TernaryUniformGeneratorImpl<NativeVector> tug;
    return std::make_shared<LWEPrivateKeyImpl>(tug.GenerateVector(size, modulus));
}

LWEPrivateKey LWEEncryptionScheme::KeyGenGaussian(uint32_t size, NativeInteger modulus) const {
    DiscreteGaussianGeneratorImpl<NativeVector> dgg(3.19);
    return std::make_shared<LWEPrivateKeyImpl>(dgg.GenerateVector(size, modulus));
}

// size is the ring dimension N, modulus is the large Q used in RGSW encryption of bootstrapping.
LWEKeyPair LWEEncryptionScheme::KeyGenPair(const std::shared_ptr<LWECryptoParams>& params) const {
    uint32_t dim = params->GetN();
    auto modulus = params->GetQ();

    // generate secret vector skN of ring dimension N
    auto skN = (params->GetKeyDist() == GAUSSIAN) ? KeyGenGaussian(dim, modulus) : KeyGen(dim, modulus);

    // generate public key pkN corresponding to secret key skN
    auto pkN = PubKeyGen(params, skN);

    // return the public key (A, v), private key sk pair
    return std::make_shared<LWEKeyPairImpl>(std::move(pkN), std::move(skN));
}

// size is the ring dimension N, modulus is the large Q used in RGSW encryption of bootstrapping.
LWEPublicKey LWEEncryptionScheme::PubKeyGen(const std::shared_ptr<LWECryptoParams>& params,
                                            ConstLWEPrivateKey& skN) const {
    const uint32_t dim = params->GetN();
    const auto modulus = params->GetQ();
    const auto mu      = modulus.ComputeMu();
    const auto& ske    = skN->GetElement();

    std::vector<NativeVector> A(dim);
    auto v = params->GetDgg().GenerateVector(dim, modulus);
    DiscreteUniformGeneratorImpl<NativeVector> dug(modulus);

    // compute v = As + e
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(dim)) firstprivate(dug)
    for (uint32_t j = 0; j < dim; ++j) {
        A[j] = dug.GenerateVector(dim);
        for (uint32_t i = 0; i < dim; ++i)
            v[j].ModAddFastEq(A[j][i].ModMulFast(ske[i], modulus, mu), modulus);
    }
    return std::make_shared<LWEPublicKeyImpl>(std::move(A), std::move(v));
}

// classical LWE encryption
// a is a randomly uniform vector of dimension n; with integers mod q
// b = a*s + e + m floor(q/4) is an integer mod q
LWECiphertext LWEEncryptionScheme::Encrypt(const std::shared_ptr<LWECryptoParams>& params, ConstLWEPrivateKey& sk,
                                           LWEPlaintext m, LWEPlaintextModulus p, NativeInteger q) const {
    if (q % p != 0 && q.ConvertToInt() & (1 == 0))
        OPENFHE_THROW("plaintext modulus p must divide ciphertext modulus q");

    NativeVector s = sk->GetElement();
    s.SwitchModulus(q);

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    const uint32_t n = s.GetLength();
    NativeVector a   = dug.GenerateVector(n, q);
    NativeInteger b  = (m % p) * (q / p) + params->GetDgg().GenerateInteger(q);
    NativeInteger mu = q.ComputeMu();
    for (uint32_t i = 0; i < n; ++i)
        b += a[i].ModMulFast(s[i], q, mu);

    return std::make_shared<LWECiphertextImpl>(std::move(a), b.Mod(q), p);
}

// classical public key LWE encryption
// a = As' + e' of dimension n; with integers mod q
// b = vs' + e" + m floor(q/4) is an integer mod q
LWECiphertext LWEEncryptionScheme::EncryptN(const std::shared_ptr<LWECryptoParams>& params, ConstLWEPublicKey& pk,
                                            LWEPlaintext m, LWEPlaintextModulus p, NativeInteger q) const {
    if (q % p != 0 && q.ConvertToInt() & (1 == 0))
        OPENFHE_THROW("plaintext modulus p must divide ciphertext modulus q");

    auto bp    = pk->Getv();
    bp.SwitchModulus(q);  // todo : this is probably not required
    uint32_t N = bp.GetLength();

    TernaryUniformGeneratorImpl<NativeVector> tug;
    NativeVector sp = tug.GenerateVector(N, q);

    // compute a in the ciphertext (a, b)
    const auto& dgg = params->GetDgg();
    auto a          = dgg.GenerateVector(N, q);
    auto& A         = pk->GetA();
    for (uint32_t j = 0; j < N; ++j) {
        // columnwise a = A_1s1 + ... + A_NsN
        a.ModAddEq(A[j].ModMul(sp[j]));
    }

    // compute b in ciphertext (a,b)
    NativeInteger mu = q.ComputeMu();
    NativeInteger b  = (m % p) * (q / p) + dgg.GenerateInteger(q);
    if (b >= q)
        b.ModEq(q);
    for (uint32_t i = 0; i < N; ++i)
        b.ModAddFastEq(bp[i].ModMulFast(sp[i], q, mu), q);

    return std::make_shared<LWECiphertextImpl>(std::move(a), b, p);
}

// convert ciphertext with modulus Q and dimension N to ciphertext with modulus q and dimension n
LWECiphertext LWEEncryptionScheme::SwitchCTtoqn(const std::shared_ptr<LWECryptoParams>& params,
                                                ConstLWESwitchingKey& ksk, ConstLWECiphertext& ct) const {
    // Modulus switching to a middle step Q'
    auto ctMS = ModSwitch(params->GetqKS(), ct);
    // Key switching
    auto ctKS = KeySwitch(params, ksk, ctMS);
    // Modulus switching
    return ModSwitch(params->Getq(), ctKS);
}

// classical LWE decryption
// m_result = Round(4/q * (b - a*s))
void LWEEncryptionScheme::Decrypt(const std::shared_ptr<LWECryptoParams>& params, ConstLWEPrivateKey& sk,
                                  ConstLWECiphertext& ct, LWEPlaintext* result, LWEPlaintextModulus p) const {
    if (sk == nullptr)
        OPENFHE_THROW("PrivateKey is empty");
    else if (ct == nullptr)
        OPENFHE_THROW("Ciphertext is empty");
    else if (result == nullptr)
        OPENFHE_THROW("result is nullptr");

    // TODO in the future we should add a check to make sure sk parameters match
    // the ct parameters

    // Create local variables to speed up the computations
    auto q = ct->GetModulus();
    if (q % (p * 2) != 0 && q.ConvertToInt() & (1 == 0))
        OPENFHE_THROW("plaintext modulus p*2 must divide ciphertext modulus q");

    const auto& a = ct->GetA();
    auto s        = sk->GetElement();
    uint32_t n    = s.GetLength();
    auto mu       = q.ComputeMu();
    s.SwitchModulus(q);
    NativeInteger inner(0);
    for (uint32_t i = 0; i < n; ++i) {
        inner += a[i].ModMulFast(s[i], q, mu);
    }
    inner.ModEq(q);

    NativeInteger r = ct->GetB();

    r.ModSubFastEq(inner, q);

    // Alternatively, rounding can be done as
    // *result = (r.MultiplyAndRound(NativeInteger(4),q)).ConvertToInt();
    // But the method below is a more efficient way of doing the rounding
    // the idea is that Round(4/q x) = q/8 + Floor(4/q x)
    r.ModAddFastEq((q / (p * 2)), q);

    *result = ((NativeInteger(p) * r) / q).ConvertToInt();

#if defined(WITH_NOISE_DEBUG)
    double error =
        (static_cast<double>(p) * (r.ConvertToDouble() - q.ConvertToDouble() / (p * 2))) / q.ConvertToDouble() -
        static_cast<double>(*result);
    std::cerr << error * q.ConvertToDouble() / static_cast<double>(p) << std::endl;
#endif
}

void LWEEncryptionScheme::EvalAddEq(LWECiphertext& ct1, ConstLWECiphertext& ct2) const {
    ct1->GetA().ModAddEq(ct2->GetA());
    ct1->SetB(ct1->GetB().ModAddFast(ct2->GetB(), ct1->GetModulus()));
}

void LWEEncryptionScheme::EvalAddConstEq(LWECiphertext& ct, NativeInteger cnst) const {
    ct->SetB(ct->GetB().ModAddFast(cnst, ct->GetModulus()));
}

void LWEEncryptionScheme::EvalSubEq(LWECiphertext& ct1, ConstLWECiphertext& ct2) const {
    ct1->GetA().ModSubEq(ct2->GetA());
    ct1->SetB(ct1->GetB().ModSubFast(ct2->GetB(), ct1->GetModulus()));
}

void LWEEncryptionScheme::EvalSubEq2(ConstLWECiphertext& ct1, LWECiphertext& ct2) const {
    ct2->GetA() = ct1->GetA().ModSub(ct2->GetA());
    ct2->SetB(ct1->GetB().ModSubFast(ct2->GetB(), ct1->GetModulus()));
}

void LWEEncryptionScheme::EvalSubConstEq(LWECiphertext& ct, NativeInteger cnst) const {
    ct->SetB(ct->GetB().ModSubFast(cnst, ct->GetModulus()));
}

void LWEEncryptionScheme::EvalMultConstEq(LWECiphertext& ct1, NativeInteger cnst) const {
    ct1->GetA().ModMulEq(cnst);
    ct1->SetB(ct1->GetB().ModMulFast(cnst, ct1->GetModulus()));
}

// Modulus switching - directly applies the scale-and-round operation RoundQ
LWECiphertext LWEEncryptionScheme::ModSwitch(NativeInteger q, ConstLWECiphertext& ctQ) const {
    uint32_t n = ctQ->GetLength();
    auto Q     = ctQ->GetModulus();
    NativeVector a(n, q);
    for (uint32_t i = 0; i < n; ++i)
        a[i] = RoundqQ(ctQ->GetA()[i], q, Q);
    return std::make_shared<LWECiphertextImpl>(std::move(a), RoundqQ(ctQ->GetB(), q, Q));
}

// Switching key as described in Section 3 of https://eprint.iacr.org/2014/816
LWESwitchingKey LWEEncryptionScheme::KeySwitchGen(const std::shared_ptr<LWECryptoParams>& params,
                                                  ConstLWEPrivateKey& sk, ConstLWEPrivateKey& skN) const {
    NativeInteger qKS(params->GetqKS());
    NativeInteger baseKS(params->GetBaseKS());
    NativeInteger value{1};
    const uint32_t digitCount = std::ceil(std::log(qKS.ConvertToDouble()) / std::log(baseKS.ConvertToDouble()));
    std::vector<NativeInteger> digitsKS(digitCount);
    for (uint32_t i = 0; i < digitCount; ++i) {
        digitsKS[i] = value;
        value *= baseKS;
    }

    // newSK stores negative values using modulus q
    // we need to switch to modulus Q
    NativeVector sv(sk->GetElement());
    sv.SwitchModulus(qKS);

    NativeVector svN(skN->GetElement());
    svN.SwitchModulus(qKS);

    DiscreteUniformGeneratorImpl<NativeVector> dug(qKS);

    NativeInteger mu(qKS.ComputeMu());

    const uint32_t N(params->GetN());
    const uint32_t m(baseKS.ConvertToInt<uint32_t>());
    const uint32_t n(params->Getn());

    std::vector<std::vector<std::vector<NativeVector>>> resultVecA(N);
    std::vector<std::vector<std::vector<NativeInteger>>> resultVecB(N);

#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(N)) firstprivate(dug)
#endif
    for (uint32_t i = 0; i < N; ++i) {
        std::vector<std::vector<NativeVector>> vector1A;
        vector1A.reserve(m);
        std::vector<std::vector<NativeInteger>> vector1B;
        vector1B.reserve(m);

        for (uint32_t j = 0; j < m; ++j) {
            std::vector<NativeVector> vector2A;
            vector2A.reserve(digitCount);
            std::vector<NativeInteger> vector2B;
            vector2B.reserve(digitCount);
            for (uint32_t k = 0; k < digitCount; ++k) {
                vector2A.emplace_back(dug.GenerateVector(n));
                NativeVector& a = vector2A.back();
                NativeInteger b =
                    (params->GetDggKS().GenerateInteger(qKS)).ModAdd(svN[i].ModMul(j * digitsKS[k], qKS), qKS);
#if NATIVEINT == 32
                for (uint32_t i = 0; i < n; ++i)
                    b.ModAddFastEq(a[i].ModMulFast(sv[i], qKS, mu), qKS);
#else
                for (uint32_t i = 0; i < n; ++i)
                    b += a[i].ModMulFast(sv[i], qKS, mu);
                b.ModEq(qKS);
#endif
                vector2B.emplace_back(b);
            }
            vector1A.push_back(std::move(vector2A));
            vector1B.push_back(std::move(vector2B));
        }
        resultVecA[i] = std::move(vector1A);
        resultVecB[i] = std::move(vector1B);
    }
    return std::make_shared<LWESwitchingKeyImpl>(std::move(resultVecA), std::move(resultVecB));
}

// the key switching operation as described in Section 3 of
// https://eprint.iacr.org/2014/816
LWECiphertext LWEEncryptionScheme::KeySwitch(const std::shared_ptr<LWECryptoParams>& params, ConstLWESwitchingKey& K,
                                             ConstLWECiphertext& ctQN) const {
    const uint32_t n(params->Getn());
    const uint32_t N(params->GetN());
    NativeInteger Q(params->GetqKS());
    NativeInteger::Integer baseKS(params->GetBaseKS());
    const uint32_t digitCount = std::ceil(std::log(Q.ConvertToDouble()) / std::log(static_cast<double>(baseKS)));

    NativeVector a(n, Q);
    NativeInteger b(ctQN->GetB());
    for (uint32_t i = 0; i < N; ++i) {
        auto& refA = K->GetElementsA()[i];
        auto& refB = K->GetElementsB()[i];
        NativeInteger::Integer atmp(ctQN->GetA()[i].ConvertToInt());
        for (uint32_t j = 0; j < digitCount; ++j) {
            const auto a0 = (atmp % baseKS);
            atmp /= baseKS;
            b.ModSubFastEq(refB[a0][j], Q);
            auto& refAj = refA[a0][j];
            for (uint32_t k = 0; k < n; ++k)
                a[k].ModSubFastEq(refAj[k], Q);
        }
    }
    return std::make_shared<LWECiphertextImpl>(std::move(a), b);
}

// noiseless LWE embedding
// a is a zero vector of dimension n; with integers mod q
// b = m floor(q/4) is an integer mod q
LWECiphertext LWEEncryptionScheme::NoiselessEmbedding(const std::shared_ptr<LWECryptoParams>& params,
                                                      LWEPlaintext m) const {
    NativeInteger q(params->Getq());
    return std::make_shared<LWECiphertextImpl>(NativeVector(params->Getn(), q), (q >> 2) * m);
}

};  // namespace lbcrypto
