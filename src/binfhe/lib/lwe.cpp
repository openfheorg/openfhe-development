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

/*
  LWE Encryption Scheme as described in
  https://eprint.iacr.org/2014/816 Full reference:
  @misc{cryptoeprint:2014:816,
    author = {Leo Ducas and Daniele Micciancio},
    title = {FHEW: Bootstrapping Homomorphic Encryption in less than a second},
    howpublished = {Cryptology ePrint Archive, Report 2014/816},
    year = {2014},
    note = {\url{https://eprint.iacr.org/2014/816}},
 */

#include "lwe.h"
#include "math/binaryuniformgenerator.h"
#include "math/discreteuniformgenerator.h"
#include "math/ternaryuniformgenerator.h"

namespace lbcrypto {

std::shared_ptr<LWEPrivateKeyImpl> LWEEncryptionScheme::KeyGen(const std::shared_ptr<LWECryptoParams> params) const {
    TernaryUniformGeneratorImpl<NativeVector> tug;
    return std::make_shared<LWEPrivateKeyImpl>(LWEPrivateKeyImpl(tug.GenerateVector(params->Getn(), params->Getq())));
}

std::shared_ptr<LWEPrivateKeyImpl> LWEEncryptionScheme::KeyGenN(const std::shared_ptr<LWECryptoParams> params) const {
    TernaryUniformGeneratorImpl<NativeVector> tug;
    return std::make_shared<LWEPrivateKeyImpl>(LWEPrivateKeyImpl(tug.GenerateVector(params->GetN(), params->GetQ())));
}

// classical LWE encryption
// a is a randomly uniform vector of dimension n; with integers mod q
// b = a*s + e + m floor(q/4) is an integer mod q
std::shared_ptr<LWECiphertextImpl> LWEEncryptionScheme::Encrypt(const std::shared_ptr<LWECryptoParams> params,
                                                                const std::shared_ptr<const LWEPrivateKeyImpl> sk,
                                                                const LWEPlaintext& m,
                                                                const LWEPlaintextModulus& p) const {
    NativeInteger q = sk->GetElement().GetModulus();
    uint32_t n      = sk->GetElement().GetLength();

    if (q % p != 0 && q.ConvertToInt() & (1 == 0)) {
        std::string errMsg = "ERROR: ciphertext modulus q needs to be divisible by plaintext modulus p.";
        PALISADE_THROW(not_implemented_error, errMsg);
    }

    NativeInteger b = (m % p) * (q / p) + params->GetDgg().GenerateInteger(q);

#if defined(BINFHE_DEBUG)
    std::cout << b % q << std::endl;
    std::cout << (m % p) * (q / p) << std::endl;
#endif

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    dug.SetModulus(q);
    NativeVector a = dug.GenerateVector(n);

    NativeInteger mu = q.ComputeMu();

    const NativeVector& s = sk->GetElement();
    for (uint32_t i = 0; i < n; ++i) {
        b += a[i].ModMulFast(s[i], q, mu);
    }
    b.ModEq(q);

    return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a, b));
}

// classical LWE decryption
// m_result = Round(4/q * (b - a*s))
void LWEEncryptionScheme::Decrypt(const std::shared_ptr<LWECryptoParams> params,
                                  const std::shared_ptr<const LWEPrivateKeyImpl> sk,
                                  const std::shared_ptr<const LWECiphertextImpl> ct, LWEPlaintext* result,
                                  const LWEPlaintextModulus& p) const {
    // TODO in the future we should add a check to make sure sk parameters match
    // the ct parameters

    // Create local variables to speed up the computations
    NativeVector a  = ct->GetA();
    uint32_t n      = sk->GetElement().GetLength();
    NativeVector s  = sk->GetElement();
    NativeInteger q = sk->GetElement().GetModulus();

    if (q % (p * 2) != 0 && q.ConvertToInt() & (1 == 0)) {
        std::string errMsg = "ERROR: ciphertext modulus q needs to be divisible by plaintext modulus p*2.";
        PALISADE_THROW(not_implemented_error, errMsg);
    }

    NativeInteger mu = q.ComputeMu();

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

#if defined(BINFHE_DEBUG)
    double error = (static_cast<double>(p) * (r.ConvertToDouble() - q.ConvertToInt() / (p * 2))) / q.ConvertToDouble() -
                   static_cast<double>(*result);
    std::cerr << q << " " << p << " " << r << " error:\t" << error << std::endl;
    std::cerr << error * q.ConvertToDouble() / static_cast<double>(p) << std::endl;
#endif

    return;
}

// the main rounding operation used in ModSwitch (as described in Section 3 of
// https://eprint.iacr.org/2014/816) The idea is that Round(x) = 0.5 + Floor(x)
NativeInteger RoundqQ(const NativeInteger& v, const NativeInteger& q, const NativeInteger& Q) {
    return NativeInteger((uint64_t)std::floor(0.5 + v.ConvertToDouble() * q.ConvertToDouble() / Q.ConvertToDouble()))
        .Mod(q);
}

// Modulus switching - directly applies the scale-and-round operation RoundQ
std::shared_ptr<LWECiphertextImpl> LWEEncryptionScheme::ModSwitch(
    NativeInteger q, const std::shared_ptr<const LWECiphertextImpl> ctQ) const {
    auto n = ctQ->GetA().GetLength();
    auto Q = ctQ->GetA().GetModulus();
    NativeVector a(n, q);

    for (uint32_t i = 0; i < n; ++i)
        a[i] = RoundqQ(ctQ->GetA()[i], q, Q);

    NativeInteger b = RoundqQ(ctQ->GetB(), q, Q);

    return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a, b));
}

// Switching key as described in Section 3 of https://eprint.iacr.org/2014/816
std::shared_ptr<LWESwitchingKey> LWEEncryptionScheme::KeySwitchGen(
    const std::shared_ptr<LWECryptoParams> params, const std::shared_ptr<const LWEPrivateKeyImpl> sk,
    const std::shared_ptr<const LWEPrivateKeyImpl> skN) const {
    // Create local copies of main variables
    uint32_t n                          = params->Getn();
    uint32_t N                          = params->GetN();
    NativeInteger Q                     = params->GetqKS();
    uint32_t baseKS                     = params->GetBaseKS();
    std::vector<NativeInteger> digitsKS = params->GetDigitsKS();
    uint32_t expKS                      = digitsKS.size();

    // newSK stores negative values using modulus q
    // we need to switch to modulus Q
    NativeVector newSK = sk->GetElement();
    newSK.SwitchModulus(Q);

    NativeVector oldSKlargeQ = skN->GetElement();
    NativeVector oldSK(oldSKlargeQ.GetLength(), Q);
    for (size_t i = 0; i < oldSK.GetLength(); i++) {
        if ((oldSKlargeQ[i] == 0) || (oldSKlargeQ[i] == 1)) {
            oldSK[i] = oldSKlargeQ[i];
        }
        else {
            oldSK[i] = Q - 1;
        }
    }

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    dug.SetModulus(Q);

    NativeInteger mu = Q.ComputeMu();

    std::vector<std::vector<std::vector<LWECiphertextImpl>>> resultVec(N);

#pragma omp parallel for
    for (uint32_t i = 0; i < N; ++i) {
        std::vector<std::vector<LWECiphertextImpl>> vector1(baseKS);
        for (uint32_t j = 0; j < baseKS; ++j) {
            std::vector<LWECiphertextImpl> vector2(expKS);
            for (uint32_t k = 0; k < expKS; ++k) {
                NativeInteger b =
                    (params->GetDggKS().GenerateInteger(Q)).ModAdd(oldSK[i].ModMul(j * digitsKS[k], Q), Q);

                NativeVector a = dug.GenerateVector(n);

#if NATIVEINT == 32
                for (uint32_t i = 0; i < n; ++i) {
                    b.ModAddFastEq(a[i].ModMulFast(newSK[i], Q, mu), Q);
                }
#else
                for (uint32_t i = 0; i < n; ++i) {
                    b += a[i].ModMulFast(newSK[i], Q, mu);
                }
                b.ModEq(Q);
#endif

                vector2[k] = LWECiphertextImpl(a, b);
            }
            vector1[j] = std::move(vector2);
        }
        resultVec[i] = std::move(vector1);
    }

    return std::make_shared<LWESwitchingKey>(LWESwitchingKey(resultVec));
}

// the key switching operation as described in Section 3 of
// https://eprint.iacr.org/2014/816
std::shared_ptr<LWECiphertextImpl> LWEEncryptionScheme::KeySwitch(
    const std::shared_ptr<LWECryptoParams> params, const std::shared_ptr<LWESwitchingKey> K,
    const std::shared_ptr<const LWECiphertextImpl> ctQN) const {
    uint32_t n                          = params->Getn();
    uint32_t N                          = params->GetN();
    NativeInteger Q                     = params->GetqKS();
    uint32_t baseKS                     = params->GetBaseKS();
    std::vector<NativeInteger> digitsKS = params->GetDigitsKS();
    uint32_t expKS                      = digitsKS.size();

    // creates an empty vector
    NativeVector a(n, Q);
    NativeInteger b   = ctQN->GetB();
    NativeVector aOld = ctQN->GetA();

    for (uint32_t i = 0; i < N; ++i) {
        NativeInteger atmp = aOld[i];
        for (uint32_t j = 0; j < expKS; ++j, atmp /= baseKS) {
            uint64_t a0 = (atmp % baseKS).ConvertToInt();
            for (uint32_t k = 0; k < n; ++k)
                a[k].ModSubFastEq((K->GetElements()[i][a0][j]).GetA()[k], Q);
            b.ModSubFastEq((K->GetElements()[i][a0][j]).GetB(), Q);
        }
    }

    return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a, b));
}

// noiseless LWE embedding
// a is a zero vector of dimension n; with integers mod q
// b = m floor(q/4) is an integer mod q
std::shared_ptr<LWECiphertextImpl> LWEEncryptionScheme::NoiselessEmbedding(
    const std::shared_ptr<LWECryptoParams> params, const LWEPlaintext& m) const {
    NativeInteger q = params->Getq();
    uint32_t n      = params->Getn();

    NativeVector a(n, q);
    for (uint32_t i = 0; i < n; ++i)
        a[i] = 0;

    NativeInteger b = m * (q >> 2);

    return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a, b));
}

};  // namespace lbcrypto
