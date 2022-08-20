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
  FHEW scheme (RingGSW accumulator) implementation
  The scheme is described in https://eprint.iacr.org/2014/816 and in Daniele Micciancio and Yuriy Polyakov
  "Bootstrapping in FHEW-like Cryptosystems", Cryptology ePrint Archive, Report 2020/086,
  https://eprint.iacr.org/2020/086.

  Full reference to https://eprint.iacr.org/2014/816:
  @misc{cryptoeprint:2014:816,
    author = {Leo Ducas and Daniele Micciancio},
    title = {FHEW: Bootstrapping Homomorphic Encryption in less than a second},
    howpublished = {Cryptology ePrint Archive, Report 2014/816},
    year = {2014},
    note = {\url{https://eprint.iacr.org/2014/816}},
 */

#include <string>

#include "binfhe-base-scheme.h"

namespace lbcrypto {

// Encryption as described in Section 5 of https://eprint.iacr.org/2014/816
// skNTT corresponds to the secret key z
RingGSWCiphertext RingGSWAccumulatorSchemeBase::EncryptAP(const std::shared_ptr<RingGSWCryptoParams> params,
                                                          const NativePoly& skNTT, const LWEPlaintext& m) const {
    NativeInteger Q                                  = params->GetLWEParams()->GetQ();
    int64_t q                                        = params->GetLWEParams()->Getq().ConvertToInt();
    uint32_t N                                       = params->GetLWEParams()->GetN();
    uint32_t digitsG                                 = params->GetDigitsG();
    uint32_t digitsG2                                = params->GetDigitsG2();
    const std::shared_ptr<ILNativeParams> polyParams = params->GetPolyParams();

    auto result = std::make_shared<RingGSWCiphertextImpl>(digitsG2, 2);

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    dug.SetModulus(Q);

    // Reduce mod q (dealing with negative number as well)
    int64_t mm   = (((m % q) + q) % q) * (2 * N / q);
    int64_t sign = 1;
    if (mm >= N) {
        mm -= N;
        sign = -1;
    }

    // tempA is introduced to minimize the number of NTTs
    std::vector<NativePoly> tempA(digitsG2);

    for (uint32_t i = 0; i < digitsG2; ++i) {
        // populate result[i][0] with uniform random a
        (*result)[i][0] = NativePoly(dug, polyParams, Format::COEFFICIENT);
        tempA[i]        = (*result)[i][0];
        // populate result[i][1] with error e
        (*result)[i][1] = NativePoly(params->GetLWEParams()->GetDgg(), polyParams, Format::COEFFICIENT);
    }

    for (uint32_t i = 0; i < digitsG; ++i) {
        if (sign > 0) {
            // Add G Multiple
            (*result)[2 * i][0][mm].ModAddEq(params->GetGPower()[i], Q);
            // [a,as+e] + X^m*G
            (*result)[2 * i + 1][1][mm].ModAddEq(params->GetGPower()[i], Q);
        }
        else {
            // Subtract G Multiple
            (*result)[2 * i][0][mm].ModSubEq(params->GetGPower()[i], Q);
            // [a,as+e] - X^m*G
            (*result)[2 * i + 1][1][mm].ModSubEq(params->GetGPower()[i], Q);
        }
    }

    // 3*digitsG2 NTTs are called
    result->SetFormat(Format::EVALUATION);
    for (uint32_t i = 0; i < digitsG2; ++i) {
        tempA[i].SetFormat(Format::EVALUATION);
        (*result)[i][1] += tempA[i] * skNTT;
    }

    return result;
}

// Encryption for the GINX variant, as described in https://eprint.iacr.org/2020/08
RingGSWCiphertext RingGSWAccumulatorSchemeBase::EncryptGINX(const std::shared_ptr<RingGSWCryptoParams> params,
                                                            const NativePoly& skNTT, const LWEPlaintext& m) const {
    NativeInteger Q                                  = params->GetLWEParams()->GetQ();
    uint32_t digitsG                                 = params->GetDigitsG();
    uint32_t digitsG2                                = params->GetDigitsG2();
    const std::shared_ptr<ILNativeParams> polyParams = params->GetPolyParams();

    auto result = std::make_shared<RingGSWCiphertextImpl>(digitsG2, 2);

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    dug.SetModulus(Q);

    // tempA is introduced to minimize the number of NTTs
    std::vector<NativePoly> tempA(digitsG2);

    for (uint32_t i = 0; i < digitsG2; ++i) {
        (*result)[i][0] = NativePoly(dug, polyParams, Format::COEFFICIENT);
        tempA[i]        = (*result)[i][0];
        (*result)[i][1] = NativePoly(params->GetLWEParams()->GetDgg(), polyParams, Format::COEFFICIENT);
    }

    for (uint32_t i = 0; i < digitsG; ++i) {
        if (m > 0) {
            // Add G Multiple
            (*result)[2 * i][0][0].ModAddEq(params->GetGPower()[i], Q);
            // [a,as+e] + G
            (*result)[2 * i + 1][1][0].ModAddEq(params->GetGPower()[i], Q);
        }
    }

    // 3*digitsG2 NTTs are called
    result->SetFormat(Format::EVALUATION);
    for (uint32_t i = 0; i < digitsG2; ++i) {
        tempA[i].SetFormat(Format::EVALUATION);
        (*result)[i][1] += tempA[i] * skNTT;
    }

    return result;
}

// wrapper for KeyGen methods
RingGSWEvalKey RingGSWAccumulatorSchemeBase::KeyGen(const std::shared_ptr<RingGSWCryptoParams> params,
                                                    const std::shared_ptr<LWEEncryptionScheme> lwescheme,
                                                    ConstLWEPrivateKey LWEsk) const {
    if (params->GetMethod() == AP)
        return KeyGenAP(params, lwescheme, LWEsk);
    else  // GINX
        return KeyGenGINX(params, lwescheme, LWEsk);
}

// Key generation as described in Section 4 of https://eprint.iacr.org/2014/816
RingGSWEvalKey RingGSWAccumulatorSchemeBase::KeyGenAP(const std::shared_ptr<RingGSWCryptoParams> params,
                                                      const std::shared_ptr<LWEEncryptionScheme> lwescheme,
                                                      ConstLWEPrivateKey LWEsk) const {
    const auto& LWEParams = params->GetLWEParams();

    ConstLWEPrivateKey skN = lwescheme->KeyGenN(LWEParams);

    RingGSWEvalKey ek;
    ek.KSkey = lwescheme->KeySwitchGen(LWEParams, LWEsk, skN);

    NativePoly skNPoly = NativePoly(params->GetPolyParams());
    skNPoly.SetValues(skN->GetElement(), Format::COEFFICIENT);
    skNPoly.SetFormat(Format::EVALUATION);

    NativeInteger q                    = LWEParams->Getq();
    NativeInteger qHalf                = q >> 1;
    int32_t qInt                       = q.ConvertToInt();
    uint32_t n                         = LWEParams->Getn();
    uint32_t baseR                     = params->GetBaseR();
    std::vector<NativeInteger> digitsR = params->GetDigitsR();

    ek.BSkey = std::make_shared<RingGSWBTKeyImpl>(n, baseR, digitsR.size());

#pragma omp parallel for
    for (uint32_t i = 0; i < n; ++i)
        for (uint32_t j = 1; j < baseR; ++j)
            for (uint32_t k = 0; k < digitsR.size(); ++k) {
                int32_t signedSK;
                if (LWEsk->GetElement()[i] < qHalf)
                    signedSK = LWEsk->GetElement()[i].ConvertToInt();
                else
                    signedSK = (int32_t)LWEsk->GetElement()[i].ConvertToInt() - qInt;
                if (LWEsk->GetElement()[i] >= qHalf)
                    signedSK -= qInt;
                (*ek.BSkey)[i][j][k] =
                    *(EncryptAP(params, skNPoly, signedSK * (int32_t)j * (int32_t)digitsR[k].ConvertToInt()));
            }

    return ek;
}

// Bootstrapping keys generation for the GINX variant, as described in
// https://eprint.iacr.org/2020/08
RingGSWEvalKey RingGSWAccumulatorSchemeBase::KeyGenGINX(const std::shared_ptr<RingGSWCryptoParams> params,
                                                        const std::shared_ptr<LWEEncryptionScheme> lwescheme,
                                                        ConstLWEPrivateKey LWEsk) const {
    RingGSWEvalKey ek;
    ConstLWEPrivateKey skN = lwescheme->KeyGenN(params->GetLWEParams());

    ek.KSkey = lwescheme->KeySwitchGen(params->GetLWEParams(), LWEsk, skN);

    NativePoly skNPoly = NativePoly(params->GetPolyParams());
    skNPoly.SetValues(skN->GetElement(), Format::COEFFICIENT);
    skNPoly.SetFormat(Format::EVALUATION);

    uint64_t q = params->GetLWEParams()->Getq().ConvertToInt();
    uint32_t n = params->GetLWEParams()->Getn();

    ek.BSkey = std::make_shared<RingGSWBTKeyImpl>(1, 2, n);

    int64_t qHalf = (q >> 1);

    // handles ternary secrets using signed mod 3 arithmetic; 0 -> {0,0}, 1 ->
    // {1,0}, -1 -> {0,1}
#pragma omp parallel for
    for (uint32_t i = 0; i < n; ++i) {
        int64_t s = LWEsk->GetElement()[i].ConvertToInt();
        if (s > qHalf)
            s -= q;
        switch (s) {
            case 0:
                (*ek.BSkey)[0][0][i] = *(EncryptGINX(params, skNPoly, 0));
                (*ek.BSkey)[0][1][i] = *(EncryptGINX(params, skNPoly, 0));
                break;
            case 1:
                (*ek.BSkey)[0][0][i] = *(EncryptGINX(params, skNPoly, 1));
                (*ek.BSkey)[0][1][i] = *(EncryptGINX(params, skNPoly, 0));
                break;
            case -1:
                (*ek.BSkey)[0][0][i] = *(EncryptGINX(params, skNPoly, 0));
                (*ek.BSkey)[0][1][i] = *(EncryptGINX(params, skNPoly, 1));
                break;
            default:
                std::string errMsg = "ERROR: only ternary secret key distributions are supported.";
                OPENFHE_THROW(not_implemented_error, errMsg);
        }
    }

    return ek;
}

// SignedDigitDecompose is a bottleneck operation
// There are two approaches to do it.
// The current approach appears to give the best performance
// results. The two variants are labeled A and B.
void RingGSWAccumulatorSchemeBase::SignedDigitDecompose(const std::shared_ptr<RingGSWCryptoParams> params,
                                                        const std::vector<NativePoly>& input,
                                                        std::vector<NativePoly>* output) const {
    uint32_t N                           = params->GetLWEParams()->GetN();
    uint32_t digitsG                     = params->GetDigitsG();
    NativeInteger Q                      = params->GetLWEParams()->GetQ();
    NativeInteger QHalf                  = Q >> 1;
    NativeInteger::SignedNativeInt Q_int = Q.ConvertToInt();

    NativeInteger::SignedNativeInt baseG = NativeInteger(params->GetBaseG()).ConvertToInt();

    NativeInteger::SignedNativeInt d = 0;

    NativeInteger::SignedNativeInt gBits = (NativeInteger::SignedNativeInt)std::log2(baseG);

    // VARIANT A
    NativeInteger::SignedNativeInt gBitsMaxBits = NativeInteger::MaxBits() - gBits;

    // VARIANT B
    // NativeInteger::SignedNativeInt gminus1 = (1 << gBits) - 1;
    // NativeInteger::SignedNativeInt baseGdiv2 =
    // (baseG >> 1)-1;

    // Signed digit decomposition
    for (uint32_t j = 0; j < 2; j++) {
        for (uint32_t k = 0; k < N; k++) {
            NativeInteger t = input[j][k];
            if (t < QHalf)
                d += t.ConvertToInt();
            else
                d += (NativeInteger::SignedNativeInt)t.ConvertToInt() - Q_int;

            for (uint32_t l = 0; l < digitsG; l++) {
                // remainder is signed

                // This approach gives a slightly better performance
                // VARIANT A
                NativeInteger::SignedNativeInt r = d << gBitsMaxBits;
                r >>= gBitsMaxBits;

                // VARIANT B
                // NativeInteger::SignedNativeInt r = d & gminus1;
                // if (r > baseGdiv2) r -= baseG;

                d -= r;
                d >>= gBits;

                if (r >= 0)
                    (*output)[j + 2 * l][k] += NativeInteger(r);
                else
                    (*output)[j + 2 * l][k] += NativeInteger(r + Q_int);
            }
            d = 0;
        }
    }
}

// AP Accumulation as described in https://eprint.iacr.org/2020/08
void RingGSWAccumulatorSchemeBase::AddToACCAP(const std::shared_ptr<RingGSWCryptoParams> params,
                                              const RingGSWCiphertextImpl& input, RingGSWCiphertext& acc) const {
    uint32_t digitsG2                                = params->GetDigitsG2();
    const std::shared_ptr<ILNativeParams> polyParams = params->GetPolyParams();

    std::vector<NativePoly> ct = acc->GetElements()[0];
    std::vector<NativePoly> dct(digitsG2);

    // initialize dct to zeros
    for (uint32_t i = 0; i < digitsG2; i++)
        dct[i] = NativePoly(polyParams, Format::COEFFICIENT, true);

    // calls 2 NTTs
    for (uint32_t i = 0; i < 2; i++)
        ct[i].SetFormat(Format::COEFFICIENT);

    SignedDigitDecompose(params, ct, &dct);

    // calls digitsG2 NTTs
    for (uint32_t j = 0; j < digitsG2; j++)
        dct[j].SetFormat(Format::EVALUATION);

    // acc = dct * input (matrix product);
    // uses in-place * operators for the last call to dct[i] to gain performance
    // improvement
    for (uint32_t j = 0; j < 2; j++) {
        (*acc)[0][j].SetValuesToZero();
        for (uint32_t l = 0; l < digitsG2; l++) {
            if (j == 0)
                (*acc)[0][j] += dct[l] * input[l][j];
            else
                (*acc)[0][j] += (dct[l] *= input[l][j]);
        }
    }
}

// GINX Accumulation as described in https://eprint.iacr.org/2020/08
// Added ternary MUX introduced in paper https://eprint.iacr.org/2022/074.pdf section 5
// We optimize the algorithm by multiplying the monomial after the external product
// This reduces the number of polynomial multiplications which further reduces the runtime
void RingGSWAccumulatorSchemeBase::AddToACCGINX(const std::shared_ptr<RingGSWCryptoParams> params,
                                                const RingGSWCiphertextImpl& input1,
                                                const RingGSWCiphertextImpl& input2, const NativeInteger& a,
                                                RingGSWCiphertext& acc) const {
    // cycltomic order
    uint32_t m                                       = 2 * params->GetLWEParams()->GetN();
    uint32_t digitsG2                                = params->GetDigitsG2();
    int64_t q                                        = params->GetLWEParams()->Getq().ConvertToInt();
    const std::shared_ptr<ILNativeParams> polyParams = params->GetPolyParams();

    std::vector<NativePoly> ct = acc->GetElements()[0];
    std::vector<NativePoly> dct(digitsG2);

    // initialize dct to zeros
    for (uint32_t i = 0; i < digitsG2; i++)
        dct[i] = NativePoly(polyParams, Format::COEFFICIENT, true);

    // calls 2 NTTs
    for (uint32_t i = 0; i < 2; i++)
        ct[i].SetFormat(Format::COEFFICIENT);

    SignedDigitDecompose(params, ct, &dct);

    for (uint32_t j = 0; j < digitsG2; j++)
        dct[j].SetFormat(Format::EVALUATION);

    // First obtain both monomial(index) for sk = 1 and monomial(-index) for sk = -1
    auto aNeg         = params->GetLWEParams()->Getq().ModSub(a, q);
    uint64_t index    = a.ConvertToInt() * (m / q);
    uint64_t indexNeg = aNeg.ConvertToInt() * (m / q);
    // index is in range [0,m] - so we need to adjust the edge case when
    // index = m to index = 0
    if (index == m)
        index = 0;
    if (indexNeg == m)
        indexNeg = 0;
    const NativePoly& monomial    = params->GetMonomial(index);
    const NativePoly& monomialNeg = params->GetMonomial(indexNeg);

    // acc = acc + dct * input1 * monomial + dct * input2 * negative_monomial;
    // uses in-place * operators for the last call to dct[i] to gain performance
    // improvement. Needs to be done using two loops for ternary secrets.
    for (uint32_t j = 0; j < 2; j++) {
        NativePoly temp1 = (j < 1) ? dct[0] * input1[0][j] : (dct[0] * input1[0][j]);
        for (uint32_t l = 1; l < digitsG2; l++) {
            if (j == 0)
                temp1 += dct[l] * input1[l][j];
            else
                temp1 += (dct[l] * input1[l][j]);
        }
        (*acc)[0][j] += (temp1 * monomial);
    }
    for (uint32_t j = 0; j < 2; j++) {
        NativePoly temp1 = (j < 1) ? dct[0] * input2[0][j] : (dct[0] * input2[0][j]);
        for (uint32_t l = 1; l < digitsG2; l++) {
            if (j == 0)
                temp1 += dct[l] * input2[l][j];
            else
                temp1 += (dct[l] * input2[l][j]);
        }
        (*acc)[0][j] += (temp1 * monomialNeg);
    }
}

RingGSWCiphertext RingGSWAccumulatorSchemeBase::BootstrapCore(
    const std::shared_ptr<RingGSWCryptoParams> params, const BINGATE gate, const RingGSWEvalKey& EK,
    const NativeVector& a, const NativeInteger& b, const std::shared_ptr<LWEEncryptionScheme> LWEscheme) const {
    if ((EK.BSkey == nullptr) || (EK.KSkey == nullptr)) {
        std::string errMsg =
            "Bootstrapping keys have not been generated. Please call BTKeyGen "
            "before calling bootstrapping.";
        OPENFHE_THROW(config_error, errMsg);
    }

    const std::shared_ptr<ILNativeParams> polyParams = params->GetPolyParams();
    NativeInteger q                                  = params->GetLWEParams()->Getq();
    NativeInteger Q                                  = params->GetLWEParams()->GetQ();
    uint32_t N                                       = params->GetLWEParams()->GetN();
    uint32_t baseR                                   = params->GetBaseR();
    uint32_t n                                       = params->GetLWEParams()->Getn();
    std::vector<NativeInteger> digitsR               = params->GetDigitsR();

    // Specifies the range [q1,q2) that will be used for mapping
    uint32_t qHalf   = q.ConvertToInt() >> 1;
    NativeInteger q1 = params->GetGateConst()[static_cast<int>(gate)];
    NativeInteger q2 = q1.ModAddFast(NativeInteger(qHalf), q);

    // depending on whether the value is the range, it will be set
    // to either Q/8 or -Q/8 to match binary arithmetic
    NativeInteger Q8    = Q / NativeInteger(8) + 1;
    NativeInteger Q8Neg = Q - Q8;

    NativeVector m(params->GetLWEParams()->GetN(), params->GetLWEParams()->GetQ());
    // Since q | (2*N), we deal with a sparse embedding of Z_Q[x]/(X^{q/2}+1) to
    // Z_Q[x]/(X^N+1)
    uint32_t factor = (2 * N / q.ConvertToInt());

    for (uint32_t j = 0; j < qHalf; j++) {
        NativeInteger temp = b.ModSub(j, q);
        if (q1 < q2)
            m[j * factor] = ((temp >= q1) && (temp < q2)) ? Q8Neg : Q8;
        else
            m[j * factor] = ((temp >= q2) && (temp < q1)) ? Q8 : Q8Neg;
    }
    std::vector<NativePoly> res(2);
    // no need to do NTT as all coefficients of this poly are zero
    res[0] = NativePoly(polyParams, Format::EVALUATION, true);
    res[1] = NativePoly(polyParams, Format::COEFFICIENT, false);
    res[1].SetValues(std::move(m), Format::COEFFICIENT);
    res[1].SetFormat(Format::EVALUATION);

    // main accumulation computation
    // the following loop is the bottleneck of bootstrapping/binary gate
    // evaluation
    auto acc  = std::make_shared<RingGSWCiphertextImpl>(1, 2);
    (*acc)[0] = std::move(res);

    if (params->GetMethod() == AP) {
        for (uint32_t i = 0; i < n; i++) {
            NativeInteger aI = q.ModSub(a[i], q);
            for (uint32_t k = 0; k < digitsR.size(); k++, aI /= NativeInteger(baseR)) {
                uint32_t a0 = (aI.Mod(baseR)).ConvertToInt();
                if (a0)
                    this->AddToACCAP(params, (*EK.BSkey)[i][a0][k], acc);
            }
        }
    }
    else {  // if GINX
        for (uint32_t i = 0; i < n; i++) {
            // handles -a*E(1) and handles -a*E(-1) = a*E(1)
            this->AddToACCGINX(params, (*EK.BSkey)[0][0][i], (*EK.BSkey)[0][1][i], q.ModSub(a[i], q), acc);
        }
    }

    return acc;
}

// Full evaluation as described in https://eprint.iacr.org/2020/08
LWECiphertext RingGSWAccumulatorSchemeBase::EvalBinGate(const std::shared_ptr<RingGSWCryptoParams> params,
                                                        const BINGATE gate, const RingGSWEvalKey& EK,
                                                        ConstLWECiphertext ct1, ConstLWECiphertext ct2,
                                                        const std::shared_ptr<LWEEncryptionScheme> LWEscheme) const {
    NativeInteger q  = params->GetLWEParams()->Getq();
    NativeInteger Q  = params->GetLWEParams()->GetQ();
    uint32_t n       = params->GetLWEParams()->Getn();
    uint32_t N       = params->GetLWEParams()->GetN();
    NativeInteger Q8 = Q / NativeInteger(8) + 1;

    if (ct1 == ct2) {
        std::string errMsg = "ERROR: Please only use independent ciphertexts as inputs.";
        OPENFHE_THROW(config_error, errMsg);
    }

    // By default, we compute XOR/XNOR using a combination of AND, OR, and NOT
    // gates
    if ((gate == XOR) || (gate == XNOR)) {
        auto ct1NOT = EvalNOT(params, ct1);
        auto ct2NOT = EvalNOT(params, ct2);
        auto ctAND1 = EvalBinGate(params, AND, EK, ct1, ct2NOT, LWEscheme);
        auto ctAND2 = EvalBinGate(params, AND, EK, ct1NOT, ct2, LWEscheme);
        auto ctOR   = EvalBinGate(params, OR, EK, ctAND1, ctAND2, LWEscheme);
        // NOT is free so there is not cost to do it an extra time for XNOR
        if (gate == XOR)
            return ctOR;
        else  // XNOR
            return EvalNOT(params, ctOR);
    }
    else {
        NativeVector a(n, q);
        NativeInteger b;

        // the additive homomorphic operation for XOR/NXOR is different from the
        // other gates we compute 2*(ct1 - ct2) mod 4 for XOR, me map 1,2 -> 1 and
        // 3,0 -> 0
        if ((gate == XOR_FAST) || (gate == XNOR_FAST)) {
            a = ct1->GetA() - ct2->GetA();
            a += a;
            b = ct1->GetB().ModSubFast(ct2->GetB(), q);
            b.ModAddFastEq(b, q);
        }
        else {
            // for all other gates, we simply compute (ct1 + ct2) mod 4
            // for AND: 0,1 -> 0 and 2,3 -> 1
            // for OR: 1,2 -> 1 and 3,0 -> 0
            a = ct1->GetA() + ct2->GetA();
            b = ct1->GetB().ModAddFast(ct2->GetB(), q);
        }

        auto acc = BootstrapCore(params, gate, EK, a, b, LWEscheme);

        NativeInteger bNew;
        NativeVector aNew(N, Q);

        // the accumulator result is encrypted w.r.t. the transposed secret key
        // we can transpose "a" to get an encryption under the original secret key
        NativePoly temp = (*acc)[0][0];
        temp            = temp.Transpose();
        temp.SetFormat(Format::COEFFICIENT);
        aNew = temp.GetValues();

        temp = (*acc)[0][1];
        temp.SetFormat(Format::COEFFICIENT);
        // we add Q/8 to "b" to to map back to Q/4 (i.e., mod 2) arithmetic.
        bNew = Q8.ModAddFast(temp[0], Q);

        // Modulus switching to a middle step Q'
        auto eQN =
            LWEscheme->ModSwitch(params->GetLWEParams()->GetqKS(), std::make_shared<LWECiphertextImpl>(aNew, bNew));

        // Key switching
        ConstLWECiphertext eQ = LWEscheme->KeySwitch(params->GetLWEParams(), EK.KSkey, eQN);

        // Modulus switching
        return LWEscheme->ModSwitch(q, eQ);
    }
}

// Full evaluation as described in https://eprint.iacr.org/2020/08
LWECiphertext RingGSWAccumulatorSchemeBase::Bootstrap(const std::shared_ptr<RingGSWCryptoParams> params,
                                                      const RingGSWEvalKey& EK, ConstLWECiphertext ct1,
                                                      const std::shared_ptr<LWEEncryptionScheme> LWEscheme) const {
    NativeInteger q  = params->GetLWEParams()->Getq();
    NativeInteger Q  = params->GetLWEParams()->GetQ();
    uint32_t n       = params->GetLWEParams()->Getn();
    uint32_t N       = params->GetLWEParams()->GetN();
    NativeInteger Q8 = Q / NativeInteger(8) + 1;

    NativeVector a(n, q);
    NativeInteger b;

    a = ct1->GetA();
    b = ct1->GetB().ModAddFast(q >> 2, q);

    auto acc = BootstrapCore(params, AND, EK, a, b, LWEscheme);

    NativeInteger bNew;
    NativeVector aNew(N, Q);

    // the accumulator result is encrypted w.r.t. the transposed secret key
    // we can transpose "a" to get an encryption under the original secret key
    NativePoly temp = (*acc)[0][0];
    temp            = temp.Transpose();
    temp.SetFormat(Format::COEFFICIENT);
    aNew = temp.GetValues();

    temp = (*acc)[0][1];
    temp.SetFormat(Format::COEFFICIENT);
    // we add Q/8 to "b" to to map back to Q/4 (i.e., mod 2) arithmetic.
    bNew = Q8.ModAddFast(temp[0], Q);

    // Modulus switching to a middle step Q'
    auto eQN = LWEscheme->ModSwitch(params->GetLWEParams()->GetqKS(), std::make_shared<LWECiphertextImpl>(aNew, bNew));

    // Key switching
    ConstLWECiphertext eQ = LWEscheme->KeySwitch(params->GetLWEParams(), EK.KSkey, eQN);

    // Modulus switching
    return LWEscheme->ModSwitch(q, eQ);
}

// Evaluation of the NOT operation; no key material is needed
LWECiphertext RingGSWAccumulatorSchemeBase::EvalNOT(const std::shared_ptr<RingGSWCryptoParams> params,
                                                    ConstLWECiphertext ct) const {
    NativeInteger q = params->GetLWEParams()->Getq();
    uint32_t n      = params->GetLWEParams()->Getn();

    NativeVector a(n, q);

    for (uint32_t i = 0; i < n; i++)
        a[i] = q - ct->GetA(i);

    NativeInteger b = (q >> 2).ModSubFast(ct->GetB(), q);

    return std::make_shared<LWECiphertextImpl>(std::move(a), b);
}

// Functions below are for large-precision sign evaluation,
// flooring, homomorphic digit decomposition, and arbitrary
// funciton evaluation, from https://eprint.iacr.org/2021/1337

template <typename Func>
RingGSWCiphertext RingGSWAccumulatorSchemeBase::BootstrapCore(const std::shared_ptr<RingGSWCryptoParams> params,
                                                              const BINGATE gate, const RingGSWEvalKey& EK,
                                                              const NativeVector& a, const NativeInteger& b,
                                                              const std::shared_ptr<LWEEncryptionScheme> LWEscheme,
                                                              const Func f, const NativeInteger bigger_q) const {
    if ((EK.BSkey == nullptr) || (EK.KSkey == nullptr)) {
        std::string errMsg =
            "Bootstrapping keys have not been generated. Please call BTKeyGen "
            "before calling bootstrapping.";
        OPENFHE_THROW(config_error, errMsg);
    }

    const std::shared_ptr<ILNativeParams> polyParams = params->GetPolyParams();
    NativeInteger q                                  = params->GetLWEParams()->Getq();
    NativeInteger Q                                  = params->GetLWEParams()->GetQ();
    uint32_t N                                       = params->GetLWEParams()->GetN();
    uint32_t baseR                                   = params->GetBaseR();
    uint32_t n                                       = params->GetLWEParams()->Getn();
    std::vector<NativeInteger> digitsR               = params->GetDigitsR();

    NativeVector m(params->GetLWEParams()->GetN(), params->GetLWEParams()->GetQ());
    // For specific function evaluation instead of general bootstrapping
    uint32_t factor = (2 * N / q.ConvertToInt());
    for (uint32_t j = 0; j < q / 2; j++) {
        NativeInteger temp = b.ModSub(j, q);
        m[j * factor]      = Q.ConvertToInt() / bigger_q.ConvertToInt() * f(temp, q, bigger_q);
    }

    std::vector<NativePoly> res(2);
    // no need to do NTT as all coefficients of this poly are zero
    res[0] = NativePoly(polyParams, Format::EVALUATION, true);
    res[1] = NativePoly(polyParams, Format::COEFFICIENT, false);
    res[1].SetValues(std::move(m), Format::COEFFICIENT);
    res[1].SetFormat(Format::EVALUATION);

    // main accumulation computation
    // the following loop is the bottleneck of bootstrapping/binary gate
    // evaluation
    auto acc  = std::make_shared<RingGSWCiphertextImpl>(1, 2);
    (*acc)[0] = std::move(res);

    if (params->GetMethod() == AP) {
        for (uint32_t i = 0; i < n; i++) {
            NativeInteger aI = q.ModSub(a[i], q);
            for (uint32_t k = 0; k < digitsR.size(); k++, aI /= NativeInteger(baseR)) {
                uint32_t a0 = (aI.Mod(baseR)).ConvertToInt();
                if (a0)
                    this->AddToACCAP(params, (*EK.BSkey)[i][a0][k], acc);
            }
        }
    }
    else {  // if GINX
        for (uint32_t i = 0; i < n; i++) {
            // handles -a*E(1) and handles -a*E(-1) = a*E(1)
            this->AddToACCGINX(params, (*EK.BSkey)[0][0][i], (*EK.BSkey)[0][1][i], q.ModSub(a[i], q), acc);
        }
    }

    return acc;
}

// Full evaluation as described in https://eprint.iacr.org/2020/08
template <typename Func>
LWECiphertext RingGSWAccumulatorSchemeBase::Bootstrap(const std::shared_ptr<RingGSWCryptoParams> params,
                                                      const RingGSWEvalKey& EK, ConstLWECiphertext ct1,
                                                      const std::shared_ptr<LWEEncryptionScheme> LWEscheme,
                                                      const Func f, const NativeInteger bigger_q) const {
    NativeInteger q     = params->GetLWEParams()->Getq();
    NativeInteger Q     = params->GetLWEParams()->GetQ();
    uint32_t n          = params->GetLWEParams()->Getn();
    uint32_t N          = params->GetLWEParams()->GetN();
    NativeInteger toAdd = 0;  // we add beta outside as it's now dependent on plaintext space

    NativeVector a(n, q);
    NativeInteger b;

    a = ct1->GetA();
    b = ct1->GetB();

    auto acc = BootstrapCore(params, AND, EK, a, b, LWEscheme, f, bigger_q);

    NativeInteger bNew;
    NativeVector aNew(N, Q);

    // the accumulator result is encrypted w.r.t. the transposed secret key
    // we can transpose "a" to get an encryption under the original secret key
    NativePoly temp = (*acc)[0][0];
    temp            = temp.Transpose();
    temp.SetFormat(Format::COEFFICIENT);
    aNew = temp.GetValues();

    temp = (*acc)[0][1];
    temp.SetFormat(Format::COEFFICIENT);
    bNew = toAdd.ModAddFast(temp[0], Q);

    // Modulus switching to a middle step Q'
    auto eQN = LWEscheme->ModSwitch(params->GetLWEParams()->GetqKS(), std::make_shared<LWECiphertextImpl>(aNew, bNew));

    // Key switching
    ConstLWECiphertext eQ = LWEscheme->KeySwitch(params->GetLWEParams(), EK.KSkey, eQN);

    // Modulus switching
    return LWEscheme->ModSwitch(bigger_q, eQ);
}

// Check what type of function the input function is.
int checkInputFunction(std::vector<NativeInteger> lut, NativeInteger bigger_q) {
    int ret = 0;  // 0 for negacyclic, 1 for periodic, 2 for arbitrary
    if (lut[0] == (bigger_q - lut[lut.size() / 2])) {
        for (size_t i = 1; i < lut.size() / 2; i++) {
            if (lut[i] != (bigger_q - lut[lut.size() / 2 + i])) {
                ret = 2;
                break;
            }
        }
    }
    else if (lut[0] == lut[lut.size() / 2]) {
        ret = 1;
        for (size_t i = 1; i < lut.size() / 2; i++) {
            if (lut[i] != lut[lut.size() / 2 + i]) {
                ret = 2;
                break;
            }
        }
    }
    else {
        ret = 2;
    }

    return ret;
}

// Evaluate Arbitrary Function homomorphically
LWECiphertext RingGSWAccumulatorSchemeBase::EvalFunc(const std::shared_ptr<RingGSWCryptoParams> params,
                                                     const RingGSWEvalKey& EK, ConstLWECiphertext ct1,
                                                     const std::shared_ptr<LWEEncryptionScheme> LWEscheme,
                                                     const std::vector<NativeInteger>& LUT, const NativeInteger beta,
                                                     const NativeInteger bigger_q) const {
    NativeInteger q              = params->GetLWEParams()->Getq();
    NativeInteger bigger_q_local = bigger_q;
    if (bigger_q == 0)
        bigger_q_local = q;

    // Get what time of function it is
    int functionProperty = checkInputFunction(LUT, bigger_q_local);

    auto a1  = ct1->GetA();
    auto b1  = ct1->GetB();
    b1       = b1.ModAddFast(beta, q);
    auto ct0 = std::make_shared<LWECiphertextImpl>(std::move(a1), std::move(b1));

    if (functionProperty == 0) {  // negacyclic function only needs one bootstrap
        auto f_neg = [LUT](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            return LUT[x.ConvertToInt()];
        };

        return Bootstrap(params, EK, ct0, LWEscheme, f_neg, q);
    }
    else if (functionProperty == 2) {  // arbitary funciton
        uint32_t N = params->GetLWEParams()->GetN();
        if (q > N) {  // need q to be at most = N for arbitary function
            std::string errMsg =
                "ERROR: ciphertext modulus q needs to be <= ring dimension for arbitrary function evaluation";
            OPENFHE_THROW(not_implemented_error, errMsg);
        }

        a1 = ct1->GetA();
        // mod up to 2q, so the encryption of m is then encryption of m or encryption of m+q (both with prob roughly 1/2)
        a1.SetModulus(q * 2);
        b1  = ct1->GetB();
        ct0 = std::make_shared<LWECiphertextImpl>(std::move(a1), std::move(b1));
        params->SetQ(q * 2);

        std::vector<NativeInteger> LUT_local = LUT;
        LUT_local.insert(LUT_local.end(), LUT.begin(), LUT.end());  // repeat the LUT to make it periodic
        // re-evaluate since it's now periodic
        auto ct2 = EvalFunc(params, EK, ct0, LWEscheme, LUT_local, beta, bigger_q_local * 2);

        auto a2 = ct2->GetA().Mod(bigger_q_local);
        auto b2 = ct2->GetB().Mod(bigger_q_local);
        params->SetQ(bigger_q_local);

        return std::make_shared<LWECiphertextImpl>(std::move(a2), std::move(b2));
    }
    else {
        // It's periodic function so we evaluate directly
    }

    auto f1 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < q / 2)
            return Q - q / 4;
        else
            return q / 4;
    };

    auto ct2 = Bootstrap(params, EK, ct0, LWEscheme, f1, q);  // this is 1/4q_small or -1/4q_small mod q
    auto a2  = ct1->GetA() - ct2->GetA();
    auto b2  = ct1->GetB().ModAddFast(beta, q).ModSubFast(ct2->GetB(), q);
    b2       = b2.ModSubFast(q / 4, q);

    auto ct2_adj = std::make_shared<LWECiphertextImpl>(std::move(a2), std::move(b2));

    auto f_neg = [LUT](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < q / 2)
            return LUT[x.ConvertToInt()];
        else
            return Q - LUT[x.ConvertToInt() - q.ConvertToInt() / 2];
    };

    // Now the input is within the range [0, q/2).
    // Note that for non-periodic function, the input q is boosted up to 2q
    return Bootstrap(params, EK, ct2_adj, LWEscheme, f_neg, bigger_q_local);
}

// Evaluate Homomorphic Flooring
LWECiphertext RingGSWAccumulatorSchemeBase::EvalFloor(const std::shared_ptr<RingGSWCryptoParams> params,
                                                      const RingGSWEvalKey& EK, ConstLWECiphertext ct1,
                                                      const std::shared_ptr<LWEEncryptionScheme> LWEscheme,
                                                      const NativeInteger beta, const NativeInteger bigger_q) const {
    auto f1 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < q / 2)
            return Q - q / 4;
        else
            return q / 4;
    };

    auto f2 = [](NativeInteger m, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (m < q / 4)
            return Q - q / 2 - m;
        else if ((q / 4 <= m) && (m < 3 * q / 4))
            return m;
        else
            return Q + q / 2 - m;
    };

    NativeInteger q           = params->GetLWEParams()->Getq();
    const auto bigger_q_local = (bigger_q == 0) ? q : bigger_q;
    uint32_t n                = params->GetLWEParams()->Getn();

    NativeVector a(n, bigger_q_local);
    NativeInteger b;

    auto a1 = ct1->GetA();
    auto b1 = ct1->GetB();
    b1      = b1.ModAddFast(beta, bigger_q_local);

    auto a1_mod_q  = a1.Mod(q);
    auto b1_mod_q  = b1.Mod(q);
    auto ct0_mod_q = std::make_shared<LWECiphertextImpl>(std::move(a1_mod_q), std::move(b1_mod_q));

    // this is 1/4q_small or -1/4q_small mod q
    auto ct2 = Bootstrap(params, EK, ct0_mod_q, LWEscheme, f1, bigger_q_local);
    auto a2  = a1 - ct2->GetA();
    auto b2  = b1.ModSubFast(ct2->GetB(), bigger_q_local);

    auto a2_mod_q  = a2.Mod(q);
    auto b2_mod_q  = b2.Mod(q);
    auto ct2_mod_q = std::make_shared<LWECiphertextImpl>(std::move(a2_mod_q), std::move(b2_mod_q));

    // now the input is only within the range [0, q/2)
    auto ct3 = Bootstrap(params, EK, ct2_mod_q, LWEscheme, f2, bigger_q_local);

    auto a3 = a2 - ct3->GetA();
    auto b3 = b2.ModSubFast(ct3->GetB(), bigger_q_local);

    return std::make_shared<LWECiphertextImpl>(std::move(a3), std::move(b3));
}

// Evaluate large-precision sign
LWECiphertext RingGSWAccumulatorSchemeBase::EvalSign(const std::shared_ptr<RingGSWCryptoParams> params,
                                                     const std::map<uint32_t, RingGSWEvalKey>& EKs,
                                                     ConstLWECiphertext ct1,
                                                     const std::shared_ptr<LWEEncryptionScheme> LWEscheme,
                                                     const NativeInteger beta, const NativeInteger bigger_q) const {
    auto theBigger_q = bigger_q;
    NativeInteger q  = params->GetLWEParams()->Getq();
    if (theBigger_q <= q) {
        std::string errMsg =
            "ERROR: EvalSign is only for large precision. For small precision, please use bootstrapping directly";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    const auto curBase = params->GetBaseG();
    auto search        = EKs.find(curBase);
    if (search == EKs.end()) {
        std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
        OPENFHE_THROW(openfhe_error, errMsg);
    }
    RingGSWEvalKey curEK(search->second);

    auto ct    = std::make_shared<LWECiphertextImpl>(ct1->GetA(), ct1->GetB());
    uint32_t n = params->GetLWEParams()->Getn();
    while (theBigger_q > q) {
        ct          = EvalFloor(params, curEK, ct, LWEscheme, beta, theBigger_q);
        auto temp   = theBigger_q;
        theBigger_q = theBigger_q / q * 2 * beta;

        if (EKs.size() == 3) {  // if dynamic
            uint32_t base = 0;
            if (ceil(log2(theBigger_q.ConvertToInt())) <= 17)
                base = 1 << 27;
            else if (ceil(log2(theBigger_q.ConvertToInt())) <= 26)
                base = 1 << 18;

            if (0 != base) {  // if base is to change ...
                params->Change_BaseG(base);

                auto search = EKs.find(base);
                if (search == EKs.end()) {
                    std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
                    OPENFHE_THROW(openfhe_error, errMsg);
                }
                curEK = search->second;
            }
        }

        // round Q to 2betaQ/q
        NativeVector a_round(n, theBigger_q);
        for (uint32_t i = 0; i < n; ++i)
            a_round[i] = RoundqQ(ct->GetA()[i], theBigger_q, temp);
        NativeInteger b_round = RoundqQ(ct->GetB(), theBigger_q, temp);
        ct                    = std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a_round, b_round));
    }

    auto a1  = ct->GetA();
    auto b1  = ct->GetB();
    b1       = b1.ModAddFast(beta, theBigger_q);
    auto ct2 = std::make_shared<LWECiphertextImpl>(std::move(a1), std::move(b1));

    auto f3 = [](NativeInteger m, NativeInteger q, NativeInteger Q) -> NativeInteger {
        return (m < q / 2) ? (Q / 4) : (Q - Q / 4);
    };

    params->SetQ(
        theBigger_q);  // if the ended q is smaller than q, we need to change the param for the final boostrapping
    auto tmp = Bootstrap(params, curEK, ct2, LWEscheme, f3, q);  // this is 1/4q_small or -1/4q_small mod q
    params->SetQ(q);  // if the ended q is smaller than q, we need to change the param for the final boostrapping

    NativeVector a_round  = tmp->GetA();
    NativeInteger b_round = tmp->GetB();
    b_round               = b_round.ModSubFast(q / 4, q);
    auto res              = std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a_round, b_round));

    params->Change_BaseG(curBase);
    return res;
}

// Evaluate Ciphertext Decomposition
std::vector<LWECiphertext> RingGSWAccumulatorSchemeBase::EvalDecomp(
    const std::shared_ptr<RingGSWCryptoParams> params, const std::map<uint32_t, RingGSWEvalKey>& EKs,
    ConstLWECiphertext ct1, const std::shared_ptr<LWEEncryptionScheme> LWEscheme, const NativeInteger beta,
    const NativeInteger bigger_q) const {
    auto theBigger_q = bigger_q;
    NativeInteger q  = params->GetLWEParams()->Getq();
    if (theBigger_q <= q) {
        std::string errMsg =
            "ERROR: EvalSign is only for large precision. For small precision, please use bootstrapping directly";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    const auto curBase = params->GetBaseG();
    auto search        = EKs.find(curBase);
    if (search == EKs.end()) {
        std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
        OPENFHE_THROW(openfhe_error, errMsg);
    }
    RingGSWEvalKey curEK(search->second);

    auto ct    = std::make_shared<LWECiphertextImpl>(ct1->GetA(), ct1->GetB());
    uint32_t n = params->GetLWEParams()->Getn();
    std::vector<LWECiphertext> ret;
    while (theBigger_q > q) {
        NativeVector a = ct->GetA().Mod(q);
        a.SetModulus(q);
        NativeInteger b = ct->GetB().Mod(q);
        ret.push_back(std::make_shared<LWECiphertextImpl>(std::move(a), std::move(b)));

        // Floor the input sequentially to obtain the most significant bit
        ct          = EvalFloor(params, curEK, ct, LWEscheme, beta, theBigger_q);
        auto temp   = theBigger_q;
        theBigger_q = theBigger_q / q * 2 * beta;

        if (EKs.size() == 3) {  // if dynamic
            uint32_t base = 0;
            if (ceil(log2(theBigger_q.ConvertToInt())) <= 17)
                base = 1 << 27;
            else if (ceil(log2(theBigger_q.ConvertToInt())) <= 26)
                base = 1 << 18;

            if (0 != base) {  // if base is to change ...
                params->Change_BaseG(base);

                auto search = EKs.find(base);
                if (search == EKs.end()) {
                    std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
                    OPENFHE_THROW(openfhe_error, errMsg);
                }
                curEK = search->second;
            }
        }

        // round Q to 2betaQ/q
        NativeVector a_round(n, theBigger_q);
        for (uint32_t i = 0; i < n; ++i)
            a_round[i] = RoundqQ(ct->GetA()[i], theBigger_q, temp);
        NativeInteger b_round = RoundqQ(ct->GetB(), theBigger_q, temp);
        ct                    = std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a_round, b_round));
    }

    auto a1  = ct->GetA();
    auto b1  = ct->GetB();
    b1       = b1.ModAddFast(beta, theBigger_q);
    auto ct2 = std::make_shared<LWECiphertextImpl>(std::move(a1), std::move(b1));

    auto f3 = [](NativeInteger m, NativeInteger q, NativeInteger Q) -> NativeInteger {
        return (m < q / 2) ? (Q / 4) : (Q - Q / 4);
    };

    // if the ended q is smaller than q, we need to change the param for the final boostrapping
    params->SetQ(theBigger_q);
    auto tmp = Bootstrap(params, curEK, ct2, LWEscheme, f3, q);  // this is 1/4q_small or -1/4q_small mod q
    params->SetQ(q);  // if the ended q is smaller than q, we need to change the param for the final boostrapping

    NativeVector a_round  = tmp->GetA();
    NativeInteger b_round = tmp->GetB();
    b_round               = b_round.ModSubFast(q / 4, q);
    ret.push_back(std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a_round, b_round)));

    params->Change_BaseG(curBase);
    return ret;
}

};  // namespace lbcrypto
