//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
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

#include <algorithm>
#include <limits>

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
    NativeVector s(sk->GetElement(), q);

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    const uint32_t n = s.GetLength();
    NativeVector a   = dug.GenerateVector(n, q);
    // TODO: the slot pitch is truncated, so message m sits m*frac(q/p) below its cell centre and
    // the matching offset in Decrypt truncates too. Free where p divides q, which is every shipped
    // p except the 6 used by 3-input gates; those lose ~1.4% of the decryption threshold at STD128,
    // about 3.5 bits of log2(P_fail). Rounded placement halves it, at the integer-placement optimum:
    // m*(q/p) + (m*(q%p) + p/2)/p, split that way so m*(q%p) < p^2 cannot overflow a 32-bit word.
    NativeInteger b = (m % p) * (q / p) + params->GetDgg().GenerateInteger(q);
    if (b >= q)
        b.ModEq(q);
    NativeInteger mu = q.ComputeMu();
    for (uint32_t i = 0; i < n; ++i)
        b.ModAddFastEq(a[i].ModMulFast(s[i], q, mu), q);

    return std::make_shared<LWECiphertextImpl>(std::move(a), b, p);
}

// classical public key LWE encryption
// a = As' + e' of dimension n; with integers mod q
// b = vs' + e" + m floor(q/4) is an integer mod q
LWECiphertext LWEEncryptionScheme::EncryptN(const std::shared_ptr<LWECryptoParams>& params, ConstLWEPublicKey& pk,
                                            LWEPlaintext m, LWEPlaintextModulus p, NativeInteger q) const {
    auto bp = pk->Getv();
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
        a.MultAccEqNoCheck(A[j], sp[j]);
    }

    // compute b in ciphertext (a,b)
    NativeInteger mu = q.ComputeMu();
    // TODO: same truncated slot pitch as Encrypt above
    NativeInteger b = (m % p) * (q / p) + dgg.GenerateInteger(q);
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
    auto q        = ct->GetModulus();
    const auto& a = ct->GetA();
    auto s        = sk->GetElement();
    uint32_t n    = s.GetLength();
    auto mu       = q.ComputeMu();
    s.SwitchModulus(q);
    NativeInteger inner(0);
    for (uint32_t i = 0; i < n; ++i)
        inner.ModAddFastEq(a[i].ModMulFast(s[i], q, mu), q);

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
    const uint32_t digitCount = params->GetDigitCountKS();
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

    // the unreduced accumulator below reaches (n+1)*qKS
    const bool unreducedAccumFits{qKS.ConvertToInt() <= std::numeric_limits<BasicInteger>::max() / (n + 1)};

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
                if (unreducedAccumFits) {
                    for (uint32_t idx = 0; idx < n; ++idx)
                        b += a[idx].ModMulFast(sv[idx], qKS, mu);
                    b.ModEq(qKS);
                }
                else {
                    for (uint32_t idx = 0; idx < n; ++idx)
                        b.ModAddFastEq(a[idx].ModMulFast(sv[idx], qKS, mu), qKS);
                }
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
    if (K == nullptr)
        OPENFHE_THROW("SwitchingKey is empty");
    if (ctQN == nullptr)
        OPENFHE_THROW("Ciphertext is empty");

    const uint32_t n(params->Getn());
    const uint32_t N(params->GetN());
    if (ctQN->GetLength() != N)
        OPENFHE_THROW("Ciphertext dimension must be equal to N for key switching");
    if (K->GetElementsA().size() != N || K->GetElementsB().size() != N)
        OPENFHE_THROW("Switching key dimension must be equal to N");

    NativeInteger Q(params->GetqKS());
    NativeInteger::Integer baseKS(params->GetBaseKS());
    const uint32_t digitCount = params->GetDigitCountKS();

    const auto& elemA = K->GetElementsA();
    const auto& elemB = K->GetElementsB();
    const auto& ctA   = ctQN->GetA();

    auto accumulateRow = [&](uint32_t i, NativeVector& av, NativeInteger& bv) {
        const auto& refA = elemA[i];
        const auto& refB = elemB[i];
        NativeInteger::Integer atmp(ctA[i].ConvertToInt());
        for (uint32_t j = 0; j < digitCount; ++j) {
            const auto a0 = (atmp % baseKS);
            atmp /= baseKS;
            bv.ModAddFastEq(refB[a0][j], Q);
            av.ModAddNoCheckEq(refA[a0][j]);
        }
    };

    NativeVector a(n, Q);
    NativeInteger bAcc(0);

    int nthreads = OpenFHEParallelControls.GetThreadLimit(std::min<uint32_t>((N * digitCount) / 128, 32));
    if (nthreads < 2) {
        for (uint32_t i = 0; i < N; ++i)
            accumulateRow(i, a, bAcc);
    }
    else {
#pragma omp parallel num_threads(nthreads)
        {
            NativeVector aLocal(n, Q);
            NativeInteger bLocal(0);
#pragma omp for schedule(static) nowait
            for (uint32_t i = 0; i < N; ++i)
                accumulateRow(i, aLocal, bLocal);
#pragma omp critical(lwe_keyswitch_reduce)
            {
                a.ModAddNoCheckEq(aLocal);
                bAcc.ModAddFastEq(bLocal, Q);
            }
        }
    }

    const NativeInteger zero{0};
    for (uint32_t k = 0; k < n; ++k)
        a[k] = zero.ModSubFast(a[k], Q);

    return std::make_shared<LWECiphertextImpl>(std::move(a), ctQN->GetB().ModSubFast(bAcc, Q));
}

#if NATIVEINT != 32
LWESwitchingKey32Impl::LWESwitchingKey32Impl(const LWECryptoParams& params, const LWESwitchingKeyImpl& K)
    : LWESwitchingKey32Impl(params.GetN(), params.GetBaseKS(), params.GetDigitCountKS(), params.Getn()) {
    const auto& elemA = K.GetElementsA();
    const auto& elemB = K.GetElementsB();
    for (uint32_t i = 0; i < m_N; ++i) {
        for (uint32_t j = 0; j < m_m; ++j) {
            for (uint32_t k = 0; k < m_d; ++k) {
                const auto& src = elemA[i][j][k];
                uint32_t* dst   = RowA(i, j, k);
                for (uint32_t idx = 0; idx < m_n; ++idx)
                    dst[idx] = static_cast<uint32_t>(src[idx].ConvertToInt());
                B(i, j, k) = static_cast<uint32_t>(elemB[i][j][k].ConvertToInt());
            }
        }
    }
}

LWESwitchingKey LWESwitchingKey32Impl::Widen(const LWECryptoParams& params) const {
    NativeInteger qKS(params.GetqKS());
    std::vector<std::vector<std::vector<NativeVector>>> keyA(m_N);
    std::vector<std::vector<std::vector<NativeInteger>>> keyB(m_N);
    for (uint32_t i = 0; i < m_N; ++i) {
        keyA[i].resize(m_m);
        keyB[i].resize(m_m);
        for (uint32_t j = 0; j < m_m; ++j) {
            keyA[i][j].reserve(m_d);
            keyB[i][j].reserve(m_d);
            for (uint32_t k = 0; k < m_d; ++k) {
                NativeVector v(m_n, qKS);
                const uint32_t* row = RowA(i, j, k);
                for (uint32_t idx = 0; idx < m_n; ++idx)
                    v[idx] = NativeInteger(row[idx]);
                keyA[i][j].push_back(std::move(v));
                keyB[i][j].emplace_back(B(i, j, k));
            }
        }
    }
    return std::make_shared<LWESwitchingKeyImpl>(std::move(keyA), std::move(keyB));
}

// native 32-bit sampling: the whole key is generated on 32-bit words (the outputs follow the
// same distributions as KeySwitchGen but the sampling sequence differs, so keys are not
// bit-comparable across widths -- verify by truth tables)
LWESwitchingKey32 LWEEncryptionScheme::KeySwitchGen32(const std::shared_ptr<LWECryptoParams>& params,
                                                      ConstLWEPrivateKey& sk, ConstLWEPrivateKey& skN) const {
    NativeInteger qKS(params->GetqKS());
    const uint64_t qKS64{qKS.ConvertToInt()};
    const uint32_t qKS32{static_cast<uint32_t>(qKS64)};
    const uint64_t baseKS{params->GetBaseKS()};
    const uint32_t digitCount = params->GetDigitCountKS();
    std::vector<uint64_t> digitsKS(digitCount);
    digitsKS[0] = 1;
    for (uint32_t i = 1; i < digitCount; ++i)
        digitsKS[i] = digitsKS[i - 1] * baseKS;

    // newSK stores negative values using modulus q
    // we need to switch to modulus Q
    NativeVector sv(sk->GetElement());
    sv.SwitchModulus(qKS);

    NativeVector svN(skN->GetElement());
    svN.SwitchModulus(qKS);

    const uint32_t N(params->GetN());
    const uint32_t m(static_cast<uint32_t>(baseKS));
    const uint32_t n(params->Getn());

    // the secret key is fixed across the whole generation: precompute its Shoup constants so
    // the inner products run at one high-word estimate per lane, with a lazy 64-bit accumulator
    // (bound (n + 1) * qKS < 2^64 -- qKS is a 32-bit word and n <= 2^16)
    std::vector<uint32_t> s32(n), sp32(n);
    for (uint32_t idx = 0; idx < n; ++idx) {
        s32[idx]  = static_cast<uint32_t>(sv[idx].ConvertToInt());
        sp32[idx] = static_cast<uint32_t>((static_cast<uint64_t>(s32[idx]) << 32) / qKS64);
    }

    DiscreteUniformGeneratorImpl<NativeVector32> dug{NativeInteger32(qKS32)};
    DiscreteGaussianGeneratorImpl<NativeVector32> dggKS32(params->GetDggKS().GetStd());
    const NativeInteger32 qKS32i{qKS32};

    auto result = std::make_shared<LWESwitchingKey32Impl>(N, m, digitCount, n);

    #if !defined(__MINGW32__) && !defined(__MINGW64__)
        #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(N)) firstprivate(dug)
    #endif
    for (uint32_t i = 0; i < N; ++i) {
        const uint64_t svNi{svN[i].ConvertToInt()};
        for (uint32_t j = 0; j < m; ++j) {
            for (uint32_t k = 0; k < digitCount; ++k) {
                NativeVector32 a(dug.GenerateVector(n));
                uint64_t noise{dggKS32.GenerateInteger(qKS32i).ConvertToInt()};
                uint64_t acc{(noise + svNi * ((j * digitsKS[k]) % qKS64)) % qKS64};
                uint32_t* row = result->RowA(i, j, k);
                for (uint32_t idx = 0; idx < n; ++idx) {
                    uint32_t av{static_cast<uint32_t>(a[idx].ConvertToInt())};
                    row[idx] = av;
                    uint32_t hi{static_cast<uint32_t>((static_cast<uint64_t>(av) * sp32[idx]) >> 32)};
                    uint32_t r{av * s32[idx] - hi * qKS32};
                    acc += r - (qKS32 & (uint32_t(0) - static_cast<uint32_t>(r >= qKS32)));
                }
                result->B(i, j, k) = static_cast<uint32_t>(acc % qKS64);
            }
        }
    }
    return result;
}

LWECiphertext LWEEncryptionScheme::KeySwitch(const std::shared_ptr<LWECryptoParams>& params, ConstLWESwitchingKey32& K,
                                             ConstLWECiphertext& ctQN) const {
    if (K == nullptr)
        OPENFHE_THROW("SwitchingKey is empty");
    if (ctQN == nullptr)
        OPENFHE_THROW("Ciphertext is empty");

    const uint32_t n(params->Getn());
    const uint32_t N(params->GetN());
    if (ctQN->GetLength() != N)
        OPENFHE_THROW("Ciphertext dimension must be equal to N for key switching");
    if (K->GetN() != N || K->Getn() != n)
        OPENFHE_THROW("Switching key dimension must be equal to N");

    NativeInteger Q(params->GetqKS());
    const uint64_t q64{Q.ConvertToInt<uint64_t>()};
    const uint64_t baseKS{params->GetBaseKS()};
    const uint32_t digitCount = params->GetDigitCountKS();

    const auto& ctA = ctQN->GetA();

    // rows accumulate unreduced: all N*digitCount values below qKS fit a uint64
    // (LWESwitchingKey32Impl::Fits), so one reduction per output coefficient replaces one per
    // row and the residues match the 64-bit path bit for bit
    auto accumulateRow = [&](uint32_t i, std::vector<uint64_t>& av, uint64_t& bv) {
        uint64_t atmp{ctA[i].ConvertToInt<uint64_t>()};
        for (uint32_t j = 0; j < digitCount; ++j) {
            const auto a0 = static_cast<uint32_t>(atmp % baseKS);
            atmp /= baseKS;
            bv += K->B(i, a0, j);
            const uint32_t* row = K->RowA(i, a0, j);
            for (uint32_t k = 0; k < n; ++k)
                av[k] += row[k];
        }
    };

    std::vector<uint64_t> acc(n, 0);
    uint64_t bAcc{0};

    int nthreads = OpenFHEParallelControls.GetThreadLimit(std::min<uint32_t>((N * digitCount) / 128, 32));
    if (nthreads < 2) {
        for (uint32_t i = 0; i < N; ++i)
            accumulateRow(i, acc, bAcc);
    }
    else {
    #pragma omp parallel num_threads(nthreads)
        {
            std::vector<uint64_t> accLocal(n, 0);
            uint64_t bLocal{0};
    #pragma omp for schedule(static) nowait
            for (uint32_t i = 0; i < N; ++i)
                accumulateRow(i, accLocal, bLocal);
    #pragma omp critical(lwe_keyswitch32_reduce)
            {
                for (uint32_t k = 0; k < n; ++k)
                    acc[k] += accLocal[k];
                bAcc += bLocal;
            }
        }
    }

    NativeVector a(n, Q);
    for (uint32_t k = 0; k < n; ++k) {
        uint64_t r{acc[k] % q64};
        a[k] = NativeInteger(r != 0 ? q64 - r : 0);
    }
    return std::make_shared<LWECiphertextImpl>(std::move(a), ctQN->GetB().ModSubFast(NativeInteger(bAcc % q64), Q));
}

LWECiphertext LWEEncryptionScheme::SwitchCTtoqn(const std::shared_ptr<LWECryptoParams>& params,
                                                ConstLWESwitchingKey32& ksk, ConstLWECiphertext& ct) const {
    auto ctMS = ModSwitch(params->GetqKS(), ct);
    auto ctKS = KeySwitch(params, ksk, ctMS);
    return ModSwitch(params->Getq(), ctKS);
}
#endif  // NATIVEINT != 32

// noiseless LWE embedding
// a is a zero vector of dimension n; with integers mod q
// b = m floor(q/4) is an integer mod q
LWECiphertext LWEEncryptionScheme::NoiselessEmbedding(const std::shared_ptr<LWECryptoParams>& params,
                                                      LWEPlaintext m) const {
    NativeInteger q(params->Getq());
    return std::make_shared<LWECiphertextImpl>(NativeVector(params->Getn(), q), (q >> 2) * m);
}

};  // namespace lbcrypto
