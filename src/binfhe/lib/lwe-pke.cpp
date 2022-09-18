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

#include "math/binaryuniformgenerator.h"
#include "math/discreteuniformgenerator.h"
#include "math/ternaryuniformgenerator.h"

#include "lwe-pke.h"

namespace lbcrypto {

LWEPrivateKey LWEEncryptionScheme::KeyGen(usint size, const NativeInteger& modulus) const {
    TernaryUniformGeneratorImpl<NativeVector> tug;
    return std::make_shared<LWEPrivateKeyImpl>(LWEPrivateKeyImpl(tug.GenerateVector(size, modulus)));
}

// classical LWE encryption
// a is a randomly uniform vector of dimension n; with integers mod q
// b = a*s + e + m floor(q/4) is an integer mod q
LWECiphertext LWEEncryptionScheme::Encrypt(const std::shared_ptr<LWECryptoParams> params, ConstLWEPrivateKey sk,
                                           const LWEPlaintext& m, const LWEPlaintextModulus& p,
                                           const NativeInteger& mod) const {
    if (mod % p != 0 && mod.ConvertToInt() & (1 == 0)) {
        std::string errMsg = "ERROR: ciphertext modulus q needs to be divisible by plaintext modulus p.";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    NativeVector s = sk->GetElement();
    uint32_t n     = s.GetLength();
    s.SwitchModulus(mod);

    NativeInteger b = (m % p) * (mod / p) + params->GetDgg().GenerateInteger(mod);

#if defined(BINFHE_DEBUG)
    std::cout << b % mod << std::endl;
    std::cout << (m % p) * (mod / p) << std::endl;
#endif

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    dug.SetModulus(mod);
    NativeVector a = dug.GenerateVector(n);

    NativeInteger mu = mod.ComputeMu();

    for (uint32_t i = 0; i < n; ++i) {
        b += a[i].ModMulFast(s[i], mod, mu);
    }
    b.ModEq(mod);

    return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a, b));
}

// classical LWE decryption
// m_result = Round(4/q * (b - a*s))
void LWEEncryptionScheme::Decrypt(const std::shared_ptr<LWECryptoParams> params, ConstLWEPrivateKey sk,
                                  ConstLWECiphertext ct, LWEPlaintext* result, const LWEPlaintextModulus& p) const {
    // TODO in the future we should add a check to make sure sk parameters match
    // the ct parameters

    // Create local variables to speed up the computations
    const NativeInteger& mod = ct->GetModulus();
    if (mod % (p * 2) != 0 && mod.ConvertToInt() & (1 == 0)) {
        std::string errMsg = "ERROR: ciphertext modulus q needs to be divisible by plaintext modulus p*2.";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    NativeVector a   = ct->GetA();
    NativeVector s   = sk->GetElement();
    uint32_t n       = s.GetLength();
    NativeInteger mu = mod.ComputeMu();
    s.SwitchModulus(mod);
    NativeInteger inner(0);
    for (uint32_t i = 0; i < n; ++i) {
        inner += a[i].ModMulFast(s[i], mod, mu);
    }
    inner.ModEq(mod);

    NativeInteger r = ct->GetB();

    r.ModSubFastEq(inner, mod);

    // Alternatively, rounding can be done as
    // *result = (r.MultiplyAndRound(NativeInteger(4),q)).ConvertToInt();
    // But the method below is a more efficient way of doing the rounding
    // the idea is that Round(4/q x) = q/8 + Floor(4/q x)
    r.ModAddFastEq((mod / (p * 2)), mod);
    *result = ((NativeInteger(p) * r) / mod).ConvertToInt();

#if defined(BINFHE_DEBUG)
    double error =
        (static_cast<double>(p) * (r.ConvertToDouble() - mod.ConvertToInt() / (p * 2))) / mod.ConvertToDouble() -
        static_cast<double>(*result);
    std::cerr << mod << " " << p << " " << r << " error:\t" << error << std::endl;
    std::cerr << error * mod.ConvertToDouble() / static_cast<double>(p) << std::endl;
#endif

    return;
}

void LWEEncryptionScheme::EvalAddEq(LWECiphertext& ct1, ConstLWECiphertext ct2) const {
    ct1->GetA().ModAddEq(ct2->GetA());
    ct1->GetB().ModAddFastEq(ct2->GetB(), ct1->GetModulus());
}

void LWEEncryptionScheme::EvalAddConstEq(LWECiphertext& ct, NativeInteger cnst) const {
    ct->GetB().ModAddFastEq(cnst, ct->GetModulus());
}

void LWEEncryptionScheme::EvalSubEq(LWECiphertext& ct1, ConstLWECiphertext ct2) const {
    ct1->GetA().ModSubEq(ct2->GetA());
    ct1->GetB().ModSubFastEq(ct2->GetB(), ct1->GetModulus());
}

void LWEEncryptionScheme::EvalSubEq2(ConstLWECiphertext ct1, LWECiphertext& ct2) const {
    ct2->GetA() = ct1->GetA().ModSub(ct2->GetA());
    ct2->GetB() = ct1->GetB().ModSubFast(ct2->GetB(), ct1->GetModulus());
}

void LWEEncryptionScheme::EvalSubConstEq(LWECiphertext& ct, NativeInteger cnst) const {
    ct->GetB().ModSubFastEq(cnst, ct->GetModulus());
}

void LWEEncryptionScheme::EvalMultConstEq(LWECiphertext& ct1, NativeInteger cnst) const {
    ct1->GetA().ModMulEq(cnst);
    ct1->GetB().ModMulFastEq(cnst, ct1->GetModulus());
}

// Modulus switching - directly applies the scale-and-round operation RoundQ
LWECiphertext LWEEncryptionScheme::ModSwitch(NativeInteger q, ConstLWECiphertext ctQ) const {
    auto n = ctQ->GetLength();
    auto Q = ctQ->GetModulus();
    NativeVector a(n, q);

    for (uint32_t i = 0; i < n; ++i)
        a[i] = RoundqQ(ctQ->GetA()[i], q, Q);

    NativeInteger b = RoundqQ(ctQ->GetB(), q, Q);

    return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a, b));
}

// Switching key as described in Section 3 of https://eprint.iacr.org/2014/816
LWESwitchingKey LWEEncryptionScheme::KeySwitchGen(const std::shared_ptr<LWECryptoParams> params, ConstLWEPrivateKey sk,
                                                  ConstLWEPrivateKey skN) const {
    // Create local copies of main variables
    uint32_t n        = params->Getn();
    uint32_t N        = params->GetN();
    NativeInteger qKS = params->GetqKS();
    uint32_t baseKS   = params->GetBaseKS();
    // Number of digits in representing numbers mod qKS
    uint32_t digitCount = (uint32_t)std::ceil(log(qKS.ConvertToDouble()) / log(static_cast<double>(baseKS)));
    std::vector<NativeInteger> digitsKS;
    // Populate digits
    NativeInteger value = 1;
    for (uint32_t i = 0; i < digitCount; i++) {
        digitsKS.push_back(value);
        value *= baseKS;
    }

    // newSK stores negative values using modulus q
    // we need to switch to modulus Q
    NativeVector sv = sk->GetElement();
    sv.SwitchModulus(qKS);

    NativeVector svN = skN->GetElement();
    svN.SwitchModulus(qKS);
    //    NativeVector oldSK(oldSKlargeQ.GetLength(), qKS);
    //    for (size_t i = 0; i < oldSK.GetLength(); i++) {
    //        if ((oldSKlargeQ[i] == 0) || (oldSKlargeQ[i] == 1)) {
    //            oldSK[i] = oldSKlargeQ[i];
    //        }
    //        else {
    //            oldSK[i] = qKS - 1;
    //        }
    //    }

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    dug.SetModulus(qKS);

    NativeInteger mu = qKS.ComputeMu();

    std::vector<std::vector<std::vector<NativeVector>>> resultVecA(N);
    std::vector<std::vector<std::vector<NativeInteger>>> resultVecB(N);

#pragma omp parallel for
    for (uint32_t i = 0; i < N; ++i) {
        std::vector<std::vector<NativeVector>> vector1A(baseKS);
        std::vector<std::vector<NativeInteger>> vector1B(baseKS);
        for (uint32_t j = 0; j < baseKS; ++j) {
            std::vector<NativeVector> vector2A(digitCount);
            std::vector<NativeInteger> vector2B(digitCount);
            for (uint32_t k = 0; k < digitCount; ++k) {
                NativeInteger b =
                    (params->GetDggKS().GenerateInteger(qKS)).ModAdd(svN[i].ModMul(j * digitsKS[k], qKS), qKS);

                NativeVector a = dug.GenerateVector(n);

#if NATIVEINT == 32
                for (uint32_t i = 0; i < n; ++i) {
                    b.ModAddFastEq(a[i].ModMulFast(sv[i], qKS, mu), qKS);
                }
#else
                for (uint32_t i = 0; i < n; ++i) {
                    b += a[i].ModMulFast(sv[i], qKS, mu);
                }
                b.ModEq(qKS);
#endif

                vector2A[k] = std::move(a);
                vector2B[k] = std::move(b);
            }
            vector1A[j] = std::move(vector2A);
            vector1B[j] = std::move(vector2B);
        }
        resultVecA[i] = std::move(vector1A);
        resultVecB[i] = std::move(vector1B);
    }

    return std::make_shared<LWESwitchingKeyImpl>(LWESwitchingKeyImpl(resultVecA, resultVecB));
}

// the key switching operation as described in Section 3 of
// https://eprint.iacr.org/2014/816
LWECiphertext LWEEncryptionScheme::KeySwitch(const std::shared_ptr<LWECryptoParams> params, ConstLWESwitchingKey K,
                                             ConstLWECiphertext ctQN) const {
    uint32_t n          = params->Getn();
    uint32_t N          = params->GetN();
    NativeInteger Q     = params->GetqKS();
    uint32_t baseKS     = params->GetBaseKS();
    uint32_t digitCount = (uint32_t)std::ceil(log(Q.ConvertToDouble()) / log(static_cast<double>(baseKS)));

    // creates an empty vector
    NativeVector a(n, Q);
    NativeInteger b = ctQN->GetB();
    for (uint32_t i = 0; i < N; ++i) {
        NativeInteger atmp = ctQN->GetA(i);
        for (uint32_t j = 0; j < digitCount; ++j, atmp /= baseKS) {
            uint64_t a0 = (atmp % baseKS).ConvertToInt();
            for (uint32_t k = 0; k < n; ++k)
                a[k].ModSubFastEq(K->GetElementsA()[i][a0][j][k], Q);
            b.ModSubFastEq(K->GetElementsB()[i][a0][j], Q);
        }
    }

    return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(std::move(a), b));
}

// noiseless LWE embedding
// a is a zero vector of dimension n; with integers mod q
// b = m floor(q/4) is an integer mod q
LWECiphertext LWEEncryptionScheme::NoiselessEmbedding(const std::shared_ptr<LWECryptoParams> params,
                                                      const LWEPlaintext& m) const {
    NativeInteger q = params->Getq();
    uint32_t n      = params->Getn();

    NativeVector a(n, q);
    for (uint32_t i = 0; i < n; ++i)
        a[i] = 0;

    NativeInteger b = m * (q >> 2);

    return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a, b));
}

// the main rounding operation used in ModSwitch (as described in Section 3 of
// https://eprint.iacr.org/2014/816) The idea is that Round(x) = 0.5 + Floor(x)
NativeInteger RoundqQ(const NativeInteger& v, const NativeInteger& q, const NativeInteger& Q) {
    return NativeInteger((uint64_t)std::floor(0.5 + v.ConvertToDouble() * q.ConvertToDouble() / Q.ConvertToDouble()))
        .Mod(q);
}

};  // namespace lbcrypto
