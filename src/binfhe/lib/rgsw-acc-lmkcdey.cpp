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

#include "rgsw-acc-lmkcdey.h"

#include <string>

namespace lbcrypto {

// Key generation as described in https://eprint.iacr.org/2022/198
RingGSWACCKey RingGSWAccumulatorLMKCDEY::KeyGenAcc(const std::shared_ptr<RingGSWCryptoParams> params,
                                              const NativePoly& skNTT, ConstLWEPrivateKey LWEsk) const {
    auto sv     = LWEsk->GetElement();
    int32_t mod = sv.GetModulus().ConvertToInt();
    int32_t modHalf = mod >> 1;
    uint32_t N = params->GetN();
    uint32_t n = sv.GetLength();

    // dim2, 0: for RGSW(X^si), 1: for automorphism keys
    // only w automorphism keys required
    // allocates (n - w) more memory for pointer (not critical for performance)
    RingGSWACCKey ek = std::make_shared<RingGSWACCKeyImpl>(1, 2, n);  

#pragma omp parallel for
    for (size_t i = 0; i < n; ++i) {
        int32_t s = (int32_t)sv[i].ConvertToInt();
        if (s > modHalf) {
            s -= mod;
        }

        (*ek)[0][0][i] = KeyGenLMKCDEY(params, skNTT, s);
    }
    
    NativeInteger gen = NativeInteger(5);
    
    (*ek)[0][1][0] = KeyGenAuto(params, skNTT, 2*N - gen.ConvertToInt());

    // m_window: window size, consider parameterization in the future
#pragma omp parallel for
    for (size_t i = 1; i < m_window+1; i++)
    {
        (*ek)[0][1][i] = KeyGenAuto(params, skNTT, 
            gen.ModExp(i, 2*N).ConvertToInt());
    }
    
    return ek;
}

void RingGSWAccumulatorLMKCDEY::EvalAcc(const std::shared_ptr<RingGSWCryptoParams> params, const RingGSWACCKey ek,
                                   RLWECiphertext& acc, const NativeVector& a) const {
    // assume a is all-odd ciphertext (using round-to-odd technique)
    uint32_t n      = a.GetLength();
    uint32_t Nh     = params->GetN() / 2;
    uint32_t M      = 2 * params->GetN();

    NativeInteger MNative(M);

    auto logGen = params->GetLogGen();
    std::unordered_map<int32_t, std::vector<int32_t>> permuteMap;

    for (size_t i = 0; i < n; i++) { // put ail a_i in the permuteMap
        // make it odd; round-to-odd(https://eprint.iacr.org/2022/198) will improve error.
        NativeInteger aI = MNative.ModSub(a[i], MNative);
        int32_t aIOdd = (aI.ConvertToInt()/2)*2+1; 
        int32_t index = logGen[aIOdd];

        if(permuteMap.find(index) == permuteMap.end()){
            std::vector<int32_t> indexVec;
            permuteMap[index] = indexVec;
        }

        auto &indexVec = permuteMap[index];
        indexVec.push_back(i);
    }
    
    NativeInteger gen(5);
    uint32_t genInt = 5;
    
    uint32_t nSkips = 0;

    acc->GetElements()[1] = (acc->GetElements()[1]).AutomorphismTransform(M - genInt);

    // for a_j = -5^i
    for (uint32_t i = Nh - 1; i > 0; i--) {
        if (permuteMap.find(-i) != permuteMap.end()){
            if (nSkips != 0){ // Rotation by 5^nSkips
                Automorphism(params, gen.ModExp(nSkips, M), (*ek)[0][1][nSkips], acc); 
                nSkips = 0;
            }
            
            auto &indexVec = permuteMap[-i];
            for (size_t j = 0; j < indexVec.size(); j ++) {
                AddToAccLMKCDEY(params, (*ek)[0][0][indexVec[j]], acc);
            }
        }
        nSkips++;

        if(nSkips == m_window || i == 1){
            Automorphism(params, gen.ModExp(nSkips, M), (*ek)[0][1][nSkips], acc);
            nSkips = 0;
        }
    }

    // for -1
    if(permuteMap.find(M) != permuteMap.end()){
        auto &indexVec = permuteMap[M];
        for (size_t j = 0; j < indexVec.size(); j ++) {
            AddToAccLMKCDEY(params, (*ek)[0][0][indexVec[j]], acc);
        }
    }

    Automorphism(params, NativeInteger(M - genInt), (*ek)[0][1][0], acc);
    
    // for a_j = 5^i
    for (size_t i = Nh - 1; i > 0; i--) {
        if(permuteMap.find(i) != permuteMap.end()) {
            if (nSkips != 0){ // Rotation by 5^nSkips
                Automorphism(params, gen.ModExp(nSkips, M), (*ek)[0][1][nSkips], acc);
                nSkips = 0;
            }

            auto &indexVec = permuteMap[i];
            for (size_t j = 0; j < indexVec.size(); j++) {
                AddToAccLMKCDEY(params, (*ek)[0][0][indexVec[j]], acc);
            }
        }
        nSkips++;

        if(nSkips == m_window || i == 1){
            Automorphism(params, gen.ModExp(nSkips, M), (*ek)[0][1][nSkips], acc);
            nSkips = 0;
        }
    }

    // for 0
    if(permuteMap.find(0) != permuteMap.end()) {
        auto &indexVec = permuteMap[0];
        for (size_t j = 0; j < indexVec.size(); j++) {
            AddToAccLMKCDEY(params, (*ek)[0][0][indexVec[j]], acc);
        }
    }
    
    return;
}

// Encryption as described in Section 5 of https://eprint.iacr.org/2022/198
// Same as KeyGenAP, but only for X^{s_i}
// skNTT corresponds to the secret key z
RingGSWEvalKey RingGSWAccumulatorLMKCDEY::KeyGenLMKCDEY(const std::shared_ptr<RingGSWCryptoParams> params,
                                              const NativePoly& skNTT, const LWEPlaintext& m) const {
    NativeInteger Q   = params->GetQ();
    uint64_t q        = params->Getq().ConvertToInt();
    uint32_t N        = params->GetN();
    uint32_t digitsG  = params->GetDigitsG();
    uint32_t digitsG2 = digitsG << 1;
    auto polyParams   = params->GetPolyParams();
    auto Gpow         = params->GetGPower();
    auto result       = std::make_shared<RingGSWEvalKeyImpl>(digitsG2, 2);

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    dug.SetModulus(Q);

    // Reduce mod q (dealing with negative number as well)
    int64_t mm       = (((m % q) + q) % q) * (2 * N / q);
    bool isReducedMM = false;
    if (mm >= N) {
        mm -= N;
        isReducedMM = true;
    }

    // tempA is introduced to minimize the number of NTTs
    std::vector<NativePoly> tempA(digitsG2);

    for (size_t i = 0; i < digitsG2; ++i) {
        // populate result[i][0] with uniform random a
        (*result)[i][0] = NativePoly(dug, polyParams, Format::COEFFICIENT);
        tempA[i]        = (*result)[i][0];
        // populate result[i][1] with error e
        (*result)[i][1] = NativePoly(params->GetDgg(), polyParams, Format::COEFFICIENT);
    }

    for (size_t i = 0; i < digitsG; ++i) {
        if (!isReducedMM) {
            // Add G Multiple
            (*result)[2 * i][0][mm].ModAddEq(Gpow[i], Q);
            // [a,as+e] + X^m*G
            (*result)[2 * i + 1][1][mm].ModAddEq(Gpow[i], Q);
        }
        else {
            // Subtract G Multiple
            (*result)[2 * i][0][mm].ModSubEq(Gpow[i], Q);
            // [a,as+e] - X^m*G
            (*result)[2 * i + 1][1][mm].ModSubEq(Gpow[i], Q);
        }
    }

    // 3*digitsG2 NTTs are called
    result->SetFormat(Format::EVALUATION);
    for (size_t i = 0; i < digitsG2; ++i) {
        tempA[i].SetFormat(Format::EVALUATION);
        (*result)[i][1] += tempA[i] * skNTT;
    }

    return result;
}

// Generation of an autormorphism key
RingGSWEvalKey RingGSWAccumulatorLMKCDEY::KeyGenAuto(const std::shared_ptr<RingGSWCryptoParams> params,
                                              const NativePoly& skNTT, const LWEPlaintext& k) const {
    NativeInteger Q   = params->GetQ();
    uint32_t digitsG  = params->GetDigitsG();
    auto polyParams   = params->GetPolyParams();
    auto Gpow         = params->GetGPower();
    auto result       = std::make_shared<RingGSWEvalKeyImpl>(digitsG, 2);
    
    DiscreteUniformGeneratorImpl<NativeVector> dug;
    dug.SetModulus(Q);

    auto skAuto = skNTT.AutomorphismTransform(k);

    for (uint32_t i = 0; i < digitsG; ++i) {
        (*result)[i][0] = NativePoly(dug, polyParams, EVALUATION);
        (*result)[i][1] = NativePoly(params->GetDgg(),
            polyParams, EVALUATION);
        (*result)[i][1] -= skAuto * Gpow[i];
        (*result)[i][1] += (*result)[i][0] * skNTT; 
    }

    return result;
}

// LMKCDEY Accumulation as described in https://eprint.iacr.org/2022/198
// Same as AP, but multiplied once
void RingGSWAccumulatorLMKCDEY::AddToAccLMKCDEY(const std::shared_ptr<RingGSWCryptoParams> params, const RingGSWEvalKey ek,
                                      RLWECiphertext& acc) const {
    uint32_t digitsG2 = params->GetDigitsG() << 1;
    auto polyParams   = params->GetPolyParams();

    std::vector<NativePoly> ct = acc->GetElements();
    std::vector<NativePoly> dct(digitsG2);

    // initialize dct to zeros
    for (size_t i = 0; i < digitsG2; i++)
        dct[i] = NativePoly(polyParams, Format::COEFFICIENT, true);

    // calls 2 NTTs
    for (size_t i = 0; i < 2; ++i)
        ct[i].SetFormat(Format::COEFFICIENT);

    SignedDigitDecompose(params, ct, dct);

    // calls digitsG2 NTTs
    for (size_t j = 0; j < digitsG2; ++j)
        dct[j].SetFormat(Format::EVALUATION);

    // acc = dct * ek (matrix product);
    // uses in-place * operators for the last call to dct[i] to gain performance
    // improvement
    const std::vector<std::vector<NativePoly>>& ev = ek->GetElements();
    // for elements[0]:
    acc->GetElements()[0].SetValuesToZero();
    for (size_t l = 1; l < digitsG2; ++l)
        acc->GetElements()[0] += (dct[l] * ev[l][0]);
    // for elements[1]:
    acc->GetElements()[1].SetValuesToZero();
    for (size_t l = 1; l < digitsG2; ++l)
        acc->GetElements()[1] += (dct[l] *= ev[l][1]);
}

// Automorphism 
void RingGSWAccumulatorLMKCDEY::Automorphism(const std::shared_ptr<RingGSWCryptoParams> params, 
                        const NativeInteger &a,
                        const RingGSWEvalKey ak, RLWECiphertext& acc) const {
    uint32_t digitsG = params->GetDigitsG();
    auto polyParams   = params->GetPolyParams();

    NativePoly cta = acc->GetElements()[0];
    NativePoly ctb = acc->GetElements()[1];

    cta.SetFormat(COEFFICIENT);
    ctb.SetFormat(COEFFICIENT);

    cta = cta.AutomorphismTransform(a.ConvertToInt());
    ctb = ctb.AutomorphismTransform(a.ConvertToInt());

    std::vector<NativePoly> dcta(digitsG);
    for (uint32_t i = 0; i < digitsG; i++)
        dcta[i] = NativePoly(polyParams, COEFFICIENT, true);

    SignedDigitDecompose(params, cta, dcta);

    // d NTTs
    for (uint32_t i = 0; i < digitsG; i++) {
        dcta[i].SetFormat(EVALUATION);
    }

    // acc = dct * input (matrix product);
    // uses in-place * operators for the last call to dct[i] to gain performance
    // improvement
    const std::vector<std::vector<NativePoly>>& ev = ak->GetElements();
    // for elements[0]:
    acc->GetElements()[0].SetValuesToZero();
    for (size_t l = 1; l < digitsG; ++l)
        acc->GetElements()[0] += (dcta[l] * ev[l][0]);
    // for elements[1]:
    acc->GetElements()[1].SetValuesToZero();
    for (size_t l = 1; l < digitsG; ++l)
        acc->GetElements()[1] += (dcta[l] *= ev[l][1]);

    ctb.SetFormat(EVALUATION);
    acc->GetElements()[1] += ctb;
}

};  // namespace lbcrypto
