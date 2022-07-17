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
  Scheme parameter default class
 */

#ifndef _CRYPTOCONTEXTPARAMS_BASE_H_
#define _CRYPTOCONTEXTPARAMS_BASE_H_

// Had to include cryptocontext.h as the includes below give a compiler error.
// Those headers probably depend on some order/sequence.
// TODO (dsuponit): fix the problem with header described above
#include "cryptocontext.h"
#include "scheme/scheme-id.h"  // SCHEME
#include "utils/inttypes.h"
#include "constants.h"

#include <iosfwd>

namespace lbcrypto {

//====================================================================================================================
class Params {
    // NOTE: if any data member (below) is added/removed then update
    // cryptocontextparams-case.cpp and cryptocontextparams-defaults.h
    SCHEME scheme;
    // Used in BGV/BFV type schemes
    // Has impact on noise growth, thus has impact on parameter generation
    PlaintextModulus ptModulus;

    // Used in BV Key Switching only (KeySwitchTechnique = BV)
    // Has impact on noise growth, thus has impact on parameter generation
    usint digitSize;

    // Used for Gaussian error generation
    // Has impact on parameter generation
    float standardDeviation;

    // GAUSSIAN means Gaussian secret key distribution
    // UNIFORM_TERNARY means Ternary secret key distribution
    // SPARSE_TERNARY means sparse secret key distribution
    SecretKeyDist secretKeyDist;

    // Max relinearization degree of secret key polynomial (used for lazy relinearization)
    int maxRelinSkDeg;

    // key switching technique: BV or HYBRID currently
    // For BV we do not have extra modulus, so the security depends on ciphertext modulus Q.
    // For HYBRID we do have extra modulus P, so the security depends on modulus P*Q
    // For BV we need digitSize - digit size in digit decomposition
    // For HYBRID we need numLargeDigits - number of digits in digit decomposition
    // it is good to have alternative to numLargeDigits - numPrimesInDigit
    KeySwitchTechnique ksTech;

    // rescaling/modulus switching technique used in CKKS/BGV
    // The options are FIXEDMANUL, FIXEDAUTO, FLEXIBLEAUTO, and FLEXIBLEAUTOEXT (default)
    // see https://eprint.iacr.org/2022/915 for details
    ScalingTechnique scalTech;

    // max batch size of messages to be packed in encoding (number of slots)
    usint batchSize;

    // The ciphertext modulus should be seen as:
    // Q = q_0 * q_1 * ... * q_n * q'
    // where q_0 is first prime, and it's number of bits is firstModSize
    // other q_i have same number of bits and is equal to scalingModSize
    // the prime q' is not explicitly given,
    // but it is used internally in CKKS and BGV schemes (in *EXT scaling methods)

    usint firstModSize;

    usint scalingModSize;

    // see KeySwitchTechnique - number of digits in HYBRID key switching
    usint numLargeDigits;

    // multiplicative depth for these parameters
    usint multiplicativeDepth;

    // security level:
    // We use the values from the security standard  at
    // http://homomorphicencryption.org/wp-content/uploads/2018/11/HomomorphicEncryptionStandardv1.1.pdf
    // For given ring dimension and security level we have
    // upper bound of possible highest modulus (Q for BV or P*Q for HYBRID)
    SecurityLevel securityLevel;

    // ring dimension N of the scheme : the ring is Z_Q[x] / (X^N+1)
    usint ringDim;

    // number of additions (used for setting noise in BGV and BFV)
    usint evalAddCount;

    // number of key switching operations (used for setting noise in BGV and BFV)
    usint keySwitchCount;

    // size of moduli used for PRE in the provable HRA setting
    usint multiHopModSize;

    // STANDARD or EXTENDED mode for BFV encryption
    // EXTENDED slightly reduces the size of Q (by few bits) but makes encryption
    // somewhat slower
    // see https://eprint.iacr.org/2022/915 for details
    EncryptionTechnique encryptionTechnique;

    // multiplication method in BFV:
    // BEHZ, HPS, HPSPOVEQ, or HPSPOVERQLEVELED (default)
    // see https://eprint.iacr.org/2022/915 for details
    MultiplicationTechnique multiplicationTechnique;

    void SetToDefaults(SCHEME scheme);

public:
    explicit Params(SCHEME scheme0 = INVALID_SCHEME) {
        SetToDefaults(scheme0);
    }

    Params(const Params& obj) = default;
    Params(Params&& obj)      = default;

    Params& operator=(const Params& obj) = default;
    Params& operator=(Params&& obj) = default;

    ~Params() = default;

    // getters
    SCHEME GetScheme() const {
        return scheme;
    }
    PlaintextModulus GetPlaintextModulus() const {
        return ptModulus;
    }
    usint GetDigitSize() const {
        return digitSize;
    }
    float GetStandardDeviation() const {
        return standardDeviation;
    }
    SecretKeyDist GetSecretKeyDist() const {
        return secretKeyDist;
    }
    int GetMaxRelinSkDeg() const {
        return maxRelinSkDeg;
    }
    KeySwitchTechnique GetKeySwitchTechnique() const {
        return ksTech;
    }
    ScalingTechnique GetScalingTechnique() const {
        return scalTech;
    }
    usint GetBatchSize() const {
        return batchSize;
    }
    usint GetFirstModSize() const {
        return firstModSize;
    }
    uint32_t GetNumLargeDigits() const {
        return numLargeDigits;
    }
    usint GetMultiplicativeDepth() const {
        return multiplicativeDepth;
    }
    usint GetScalingModSize() const {
        return scalingModSize;
    }
    SecurityLevel GetSecurityLevel() const {
        return securityLevel;
    }
    usint GetRingDim() const {
        return ringDim;
    }
    usint GetEvalAddCount() const {
        return evalAddCount;
    }
    usint GetKeySwitchCount() const {
        return keySwitchCount;
    }
    EncryptionTechnique GetEncryptionTechnique() const {
        return encryptionTechnique;
    }
    MultiplicationTechnique GetMultiplicationTechnique() const {
        return multiplicationTechnique;
    }
    usint GetMultiHopModSize() const {
        return multiHopModSize;
    }

    // setters
    void SetPlaintextModulus(PlaintextModulus ptModulus0) {
        ptModulus = ptModulus0;
    }
    void SetDigitSize(usint digitSize0) {
        digitSize = digitSize0;
    }
    void SetStandardDeviation(float standardDeviation0) {
        standardDeviation = standardDeviation0;
    }
    void SetSecretKeyDist(SecretKeyDist secretKeyDist0) {
        secretKeyDist = secretKeyDist0;
    }
    void SetMaxRelinSkDeg(int maxRelinSkDeg0) {
        maxRelinSkDeg = maxRelinSkDeg0;
    }
    void SetKeySwitchTechnique(KeySwitchTechnique ksTech0) {
        ksTech = ksTech0;
    }
    void SetScalingTechnique(ScalingTechnique scalTech0) {
        scalTech = scalTech0;
    }
    void SetBatchSize(usint batchSize0) {
        batchSize = batchSize0;
    }
    void SetFirstModSize(usint firstModSize0) {
        firstModSize = firstModSize0;
    }
    void SetNumLargeDigits(uint32_t numLargeDigits0) {
        numLargeDigits = numLargeDigits0;
    }
    void SetMultiplicativeDepth(usint multiplicativeDepth0) {
        multiplicativeDepth = multiplicativeDepth0;
    }
    void SetScalingModSize(usint scalingModSize0) {
        scalingModSize = scalingModSize0;
    }
    void SetSecurityLevel(SecurityLevel securityLevel0) {
        securityLevel = securityLevel0;
    }
    void SetRingDim(usint ringDim0) {
        ringDim = ringDim0;
    }
    void SetEvalAddCount(usint evalAddCount0) {
        evalAddCount = evalAddCount0;
    }
    void SetKeySwitchCount(usint keySwitchCount0) {
        keySwitchCount = keySwitchCount0;
    }
    void SetEncryptionTechnique(EncryptionTechnique encryptionTechnique0) {
        encryptionTechnique = encryptionTechnique0;
    }
    void SetMultiplicationTechnique(MultiplicationTechnique multiplicationTechnique0) {
        multiplicationTechnique = multiplicationTechnique0;
    }
    void SetMultiHopModSize(usint multiHopModSize0) {
        multiHopModSize = multiHopModSize0;
    }

    friend std::ostream& operator<<(std::ostream& os, const Params& obj);
};
//====================================================================================================================

}  // namespace lbcrypto

#endif  // _CRYPTOCONTEXTPARAMS_BASE_H_
