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

#ifndef __GEN_CRYPTOCONTEXT_PARAMS_H__
#define __GEN_CRYPTOCONTEXT_PARAMS_H__

#include "scheme/scheme-id.h"
#include "utils/inttypes.h"
#include "constants.h"
#include "lattice/constants-lattice.h"
#include "lattice/stdlatticeparms.h"

#include <iosfwd>
#include <string>
#include <vector>

namespace lbcrypto {

//====================================================================================================================
class Params {
    // NOTE: if any data member (below) is added/removed then update
    // cryptocontextparams-case.cpp and cryptocontextparams-defaults.h

    // Scheme ID
    SCHEME scheme;

    // PlaintextModulus ptModulus is used in BGV/BFV type schemes and impacts noise growth
    PlaintextModulus ptModulus;

    // digitSize is used in BV Key Switching only (KeySwitchTechnique = BV) and impacts noise growth
    uint32_t digitSize;

    // standardDeviation is used for Gaussian error generation
    float standardDeviation;

    // Secret key distribution: GAUSSIAN, UNIFORM_TERNARY, etc.
    SecretKeyDist secretKeyDist;

    // Max relinearization degree of secret key polynomial (used for lazy relinearization)
    uint32_t maxRelinSkDeg;

    // key switching technique: BV or HYBRID currently
    // For BV we do not have extra modulus, so the security depends on ciphertext modulus Q.
    // For HYBRID we do have extra modulus P, so the security depends on modulus P*Q
    // For BV we need digitSize - digit size in digit decomposition
    // For HYBRID we need numLargeDigits - number of digits in digit decomposition
    // it is good to have alternative to numLargeDigits (possibly numPrimesInDigit?)
    KeySwitchTechnique ksTech;

    // rescaling/modulus switching technique used in CKKS/BGV: FLEXIBLEAUTOEXT, FIXEDMANUL, FLEXIBLEAUTO, etc.
    // see https://eprint.iacr.org/2022/915 for details
    ScalingTechnique scalTech;

    // max batch size of messages to be packed in encoding (number of slots)
    uint32_t batchSize;

    // PRE security mode
    ProxyReEncryptionMode PREMode;

    // Multiparty security mode in BFV/BGV
    // NOISE_FLOODING_MULTIPARTY is more secure than FIXED_NOISE_MULTIPARTY.
    MultipartyMode multipartyMode;

    // Execution mode in CKKS
    // In EXEC_NOISE_ESTIMATION mode, we estimate the noise we need to add to the actual computation to guarantee good security.
    // In EXEC_EVALUATION mode, we input our noise estimate and perform the desired secure encrypted computation.
    ExecutionMode executionMode;

    // Decryption noise mode in CKKS
    // NOISE_FLOODING_DECRYPT is more secure than FIXED_NOISE_DECRYPT, but it requires executing all computations twice.
    DecryptionNoiseMode decryptionNoiseMode;

    // Noise estimate in CKKS for NOISE_FLOODING_DECRYPT mode.
    // This estimate is obtained from running the computation in EXEC_NOISE_ESTIMATION mode.
    double noiseEstimate;

    // Desired precision for 128-bit CKKS. We use this value in NOISE_FLOODING_DECRYPT mode to determine the scaling factor.
    double desiredPrecision;

    // Statistical security of CKKS in NOISE_FLOODING_DECRYPT mode. This is the bound on the probability of success
    // that any adversary can have. Specifically, they a probability of success of at most 2^(-statisticalSecurity).
    uint32_t statisticalSecurity;

    // This is the number of adversarial queries a user is expecting for their application, which we use to ensure
    // security of CKKS in NOISE_FLOODING_DECRYPT mode.
    uint32_t numAdversarialQueries;

    // This is the number of parties in a threshold application, which is used for bound on the joint secret key
    uint32_t thresholdNumOfParties;
    // firstModSize and scalingModSize are used to calculate ciphertext modulus. The ciphertext modulus should be seen as:
    // Q = q_0 * q_1 * ... * q_n * q'
    // where q_0 is first prime, and it's number of bits is firstModSize
    // other q_i have same number of bits and is equal to scalingModSize
    // the prime q' is not explicitly given,
    // but it is used internally in CKKS and BGV schemes (in *EXT scaling methods)
    uint32_t firstModSize;
    uint32_t scalingModSize;

    // see KeySwitchTechnique - number of digits in HYBRID key switching
    uint32_t numLargeDigits;

    // multiplicative depth
    uint32_t multiplicativeDepth;

    // security level:
    // We use the values from the security standard  at
    // http://homomorphicencryption.org/wp-content/uploads/2018/11/HomomorphicEncryptionStandardv1.1.pdf
    // For given ring dimension and security level we have
    // upper bound of possible highest modulus (Q for BV or P*Q for HYBRID)
    SecurityLevel securityLevel;

    // ring dimension N of the scheme : the ring is Z_Q[x] / (X^N+1)
    uint32_t ringDim;

    // number of additions (used for setting noise in BGV and BFV)
    uint32_t evalAddCount;

    // number of key switching operations (used for setting noise in BGV and BFV)
    uint32_t keySwitchCount;

    // size of moduli used for PRE in the provable HRA setting
    uint32_t PRENumHops;

    // STANDARD or EXTENDED mode for BFV encryption
    // EXTENDED slightly reduces the size of Q (by few bits) but makes encryption somewhat slower
    // see https://eprint.iacr.org/2022/915 for details
    EncryptionTechnique encryptionTechnique;

    // multiplication method in BFV: BEHZ, HPS, etc.
    // see https://eprint.iacr.org/2022/915 for details
    MultiplicationTechnique multiplicationTechnique;

    // Interactive multi-party bootstrapping parameter
    // Set the compression level in ciphertext (SLACK or COMPACT)
    // SLACK has weaker security assumption, thus less efficient
    // COMPACT has stronger security assumption, thus more efficient
    COMPRESSION_LEVEL interactiveBootCompressionLevel;

    // CKKS composite scaling parameters to support high-precision CKKS RNS with small word sizes
    // Please refer to https://eprint.iacr.org/2023/1462.pdf for details
    uint32_t compositeDegree;
    uint32_t registerWordSize;

    // CKKS data type: real or complex. Noise flooding is only enabled for real values.
    CKKSDataType ckksDataType;

    void SetToDefaults(SCHEME scheme);

protected:
    // How to disable a particular setter for a particular scheme and get an exception thrown if a user tries to call it:
    // 1. The set function should be declared virtual in this file
    // 2. The same function should be re-defined in the scheme-specific derived file using macros DISABLED_FOR_xxxxRNS defined below.
    //
    // Example:
    // the original setter defined in gen-cryptocontext-params.h:
    //
    // virtual void SetPlaintextModulus(PlaintextModulus ptModulus0) {
    //     ptModulus = ptModulus0;
    // }
    //
    // the setter re-defined and disabled in gen-cryptocontext-ckksrns-params.h:
    //
    // void SetPlaintextModulus(PlaintextModulus ptModulus0) override {
    //     DISABLED_FOR_CKKS;
    // }

#define DISABLED_FOR_CKKSRNS OPENFHE_THROW("This function is not available for CKKSRNS.");
#define DISABLED_FOR_BGVRNS  OPENFHE_THROW("This function is not available for BGVRNS.");
#define DISABLED_FOR_BFVRNS  OPENFHE_THROW("This function is not available for BFVRNS.");

public:
    explicit Params(SCHEME scheme0 = INVALID_SCHEME) {
        SetToDefaults(scheme0);
    }

    /**
     * This Params' constructor "explicit Params(const std::vector<std::string>& vals)" is to be used by unittests only.
     *
     * @param vals - vector with override values. sequence of vals' elements must be the same as we get it from getAllParamsDataMembers()
     */
    explicit Params(const std::vector<std::string>& vals);

    Params(const Params& obj) = default;
    Params(Params&& obj)      = default;

    Params& operator=(const Params& obj) = default;
    Params& operator=(Params&& obj)      = default;

    virtual ~Params() = default;

    /**
     * getAllParamsDataMembers() returns names of all data members of Params and the scheme enum ALWAYS goes first.
     * This function is meant for unittests only and holds the correct sequence of the parameters/column names.
     *
     * @return a vector with names of all data members of Params
     */
    static const std::vector<std::string> getAllParamsDataMembers() {
        return {"scheme",
                "ptModulus",
                "digitSize",
                "standardDeviation",
                "secretKeyDist",
                "maxRelinSkDeg",
                "ksTech",
                "scalTech",
                "firstModSize",
                "batchSize",
                "numLargeDigits",
                "multiplicativeDepth",
                "scalingModSize",
                "securityLevel",
                "ringDim",
                "evalAddCount",
                "keySwitchCount",
                "encryptionTechnique",
                "multiplicationTechnique",
                "PRENumHops",
                "PREMode",
                "multipartyMode",
                "executionMode",
                "decryptionNoiseMode",
                "noiseEstimate",
                "desiredPrecision",
                "statisticalSecurity",
                "numAdversarialQueries",
                "thresholdNumOfParties",
                "interactiveBootCompressionLevel",
                "compositeDegree",
                "registerWordSize",
                "ckksDataType"};
    }

    // getters
    SCHEME GetScheme() const {
        return scheme;
    }
    PlaintextModulus GetPlaintextModulus() const {
        return ptModulus;
    }
    uint32_t GetDigitSize() const {
        return digitSize;
    }
    float GetStandardDeviation() const {
        return standardDeviation;
    }
    SecretKeyDist GetSecretKeyDist() const {
        return secretKeyDist;
    }
    uint32_t GetMaxRelinSkDeg() const {
        return maxRelinSkDeg;
    }
    ProxyReEncryptionMode GetPREMode() const {
        return PREMode;
    }
    MultipartyMode GetMultipartyMode() const {
        return multipartyMode;
    }
    ExecutionMode GetExecutionMode() const {
        return executionMode;
    }
    DecryptionNoiseMode GetDecryptionNoiseMode() const {
        return decryptionNoiseMode;
    }
    double GetNoiseEstimate() const {
        return noiseEstimate;
    }
    double GetDesiredPrecision() const {
        return desiredPrecision;
    }
    double GetStatisticalSecurity() const {
        return statisticalSecurity;
    }
    double GetNumAdversarialQueries() const {
        return numAdversarialQueries;
    }

    uint32_t GetThresholdNumOfParties() const {
        return thresholdNumOfParties;
    }

    KeySwitchTechnique GetKeySwitchTechnique() const {
        return ksTech;
    }
    ScalingTechnique GetScalingTechnique() const {
        return scalTech;
    }
    uint32_t GetBatchSize() const {
        return batchSize;
    }
    uint32_t GetFirstModSize() const {
        return firstModSize;
    }
    uint32_t GetNumLargeDigits() const {
        return numLargeDigits;
    }
    uint32_t GetMultiplicativeDepth() const {
        return multiplicativeDepth;
    }
    uint32_t GetScalingModSize() const {
        return scalingModSize;
    }
    SecurityLevel GetSecurityLevel() const {
        return securityLevel;
    }
    uint32_t GetRingDim() const {
        return ringDim;
    }
    uint32_t GetEvalAddCount() const {
        return evalAddCount;
    }
    uint32_t GetKeySwitchCount() const {
        return keySwitchCount;
    }
    EncryptionTechnique GetEncryptionTechnique() const {
        return encryptionTechnique;
    }
    MultiplicationTechnique GetMultiplicationTechnique() const {
        return multiplicationTechnique;
    }
    uint32_t GetPRENumHops() const {
        return PRENumHops;
    }
    COMPRESSION_LEVEL GetInteractiveBootCompressionLevel() const {
        return interactiveBootCompressionLevel;
    }
    uint32_t GetCompositeDegree() const {
        return compositeDegree;
    }
    uint32_t GetRegisterWordSize() const {
        return registerWordSize;
    }
    CKKSDataType GetCKKSDataType() const {
        return ckksDataType;
    }

    // setters
    // They all must be virtual, so any of them can be disabled in the derived class
    virtual void SetPlaintextModulus(PlaintextModulus ptModulus0) {
        ptModulus = ptModulus0;
    }
    virtual void SetDigitSize(uint32_t digitSize0) {
        digitSize = digitSize0;
    }
    virtual void SetStandardDeviation(float standardDeviation0) {
        standardDeviation = standardDeviation0;
    }
    virtual void SetSecretKeyDist(SecretKeyDist secretKeyDist0) {
        secretKeyDist = secretKeyDist0;
    }
    virtual void SetMaxRelinSkDeg(uint32_t maxRelinSkDeg0) {
        maxRelinSkDeg = maxRelinSkDeg0;
    }
    virtual void SetPREMode(ProxyReEncryptionMode PREMode0) {
        PREMode = PREMode0;
    }
    virtual void SetMultipartyMode(MultipartyMode multipartyMode0) {
        multipartyMode = multipartyMode0;
    }
    virtual void SetExecutionMode(ExecutionMode executionMode0) {
        executionMode = executionMode0;
    }
    virtual void SetDecryptionNoiseMode(DecryptionNoiseMode decryptionNoiseMode0) {
        decryptionNoiseMode = decryptionNoiseMode0;
    }
    virtual void SetNoiseEstimate(double noiseEstimate0) {
        noiseEstimate = noiseEstimate0;
    }
    virtual void SetDesiredPrecision(double desiredPrecision0) {
        desiredPrecision = desiredPrecision0;
    }
    virtual void SetStatisticalSecurity(uint32_t statisticalSecurity0) {
        statisticalSecurity = statisticalSecurity0;
    }
    virtual void SetNumAdversarialQueries(uint32_t numAdversarialQueries0) {
        numAdversarialQueries = numAdversarialQueries0;
    }
    virtual void SetThresholdNumOfParties(uint32_t thresholdNumOfParties0) {
        thresholdNumOfParties = thresholdNumOfParties0;
    }
    virtual void SetKeySwitchTechnique(KeySwitchTechnique ksTech0) {
        ksTech = ksTech0;
    }
    virtual void SetScalingTechnique(ScalingTechnique scalTech0) {
        scalTech = scalTech0;
    }
    virtual void SetBatchSize(uint32_t batchSize0) {
        batchSize = batchSize0;
    }
    virtual void SetFirstModSize(uint32_t firstModSize0) {
        firstModSize = firstModSize0;
    }
    virtual void SetNumLargeDigits(uint32_t numLargeDigits0) {
        numLargeDigits = numLargeDigits0;
    }
    virtual void SetMultiplicativeDepth(uint32_t multiplicativeDepth0) {
        multiplicativeDepth = multiplicativeDepth0;
    }
    virtual void SetScalingModSize(uint32_t scalingModSize0) {
        scalingModSize = scalingModSize0;
    }
    virtual void SetSecurityLevel(SecurityLevel securityLevel0) {
        securityLevel = securityLevel0;
    }
    virtual void SetRingDim(uint32_t ringDim0) {
        ringDim = ringDim0;
    }
    virtual void SetEvalAddCount(uint32_t evalAddCount0) {
        evalAddCount = evalAddCount0;
    }
    virtual void SetKeySwitchCount(uint32_t keySwitchCount0) {
        keySwitchCount = keySwitchCount0;
    }
    virtual void SetEncryptionTechnique(EncryptionTechnique encryptionTechnique0) {
        encryptionTechnique = encryptionTechnique0;
    }
    virtual void SetMultiplicationTechnique(MultiplicationTechnique multiplicationTechnique0) {
        multiplicationTechnique = multiplicationTechnique0;
    }
    virtual void SetPRENumHops(uint32_t PRENumHops0) {
        PRENumHops = PRENumHops0;
    }
    virtual void SetInteractiveBootCompressionLevel(COMPRESSION_LEVEL interactiveBootCompressionLevel0) {
        interactiveBootCompressionLevel = interactiveBootCompressionLevel0;
    }
    virtual void SetCompositeDegree(uint32_t compositeDegree0) {
        compositeDegree = compositeDegree0;
    }
    virtual void SetRegisterWordSize(uint32_t registerWordSize0) {
        registerWordSize = registerWordSize0;
    }
    virtual void SetCKKSDataType(CKKSDataType ckksDataType0) {
        ckksDataType = ckksDataType0;
    }

    friend std::ostream& operator<<(std::ostream& os, const Params& obj);
};
// ====================================================================================================================

}  // namespace lbcrypto

#endif  // __GEN_CRYPTOCONTEXT_PARAMS_H__
