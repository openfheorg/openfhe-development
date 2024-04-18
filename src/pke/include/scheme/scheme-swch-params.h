//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
#ifndef __SCHEME_SWCH_PARAMS_H__
#define __SCHEME_SWCH_PARAMS_H__

#include "lattice/stdlatticeparms.h"
#include "binfhe-constants.h"
#include "math/math-hal.h"

#include "utils/exception.h"

#include <cstdint>
#include <iosfwd>

namespace lbcrypto {

class SchSwchParams {
    // security level for CKKS cryptocontext
    SecurityLevel securityLevelCKKS{HEStd_128_classic};
    // security level for FHEW cryptocontext
    BINFHE_PARAMSET securityLevelFHEW{STD128};
    // number of slots in CKKS encryption
    uint32_t numSlotsCKKS{0};
    // number of values to switch
    uint32_t numValues{0};
    // size of ciphertext modulus in FHEW for large-precision evaluation
    uint32_t ctxtModSizeFHEWLargePrec{25};
    // size of ciphertext modulus in intermediate switch for security with the FHEW ring dimension
    uint32_t ctxtModSizeFHEWIntermedSwch{27};
    // baby-step for the linear transform in CKKS to FHEW
    uint32_t bStepLTrCKKStoFHEW{0};
    // baby-step for the linear transform in FHEW to CKKS
    uint32_t bStepLTrFHEWtoCKKS{0};
    // level on which to do the linear transform in CKKS to FHEW
    uint32_t levelLTrCKKStoFHEW{1};
    // level on which to do the linear transform in FHEW to CKKS
    uint32_t levelLTrFHEWtoCKKS{0};
    // binfhecontext created is for arbitrary function evaluation
    bool arbitraryFunctionEvaluation{false};
    bool useDynamicModeFHEW{false};
    bool computeArgmin{false};
    // have the argmin result one hot encoding
    bool oneHotEncoding{true};
    // use the alternative version of argmin which requires fewer automorphism keys
    bool useAltArgmin{false};

    // CKKS cryptocontext data (internally populated, NOT by the user)
    bool setParamsFromCKKSCryptocontextCalled{false};
    NativeInteger initialCKKSModulus{0};
    uint32_t ringDimension{0};
    uint32_t scalingModSize{0};
    uint32_t batchSize{0};

    void VerifyObjectData() const {
        if (!setParamsFromCKKSCryptocontextCalled) {
            OPENFHE_THROW(
                "Objects of class SchSwchParams may be used only after having called SetParamsFromCKKSCryptocontext()");
        }
    }

public:
    friend std::ostream& operator<<(std::ostream& s, const SchSwchParams& obj);
    //=================================================================================================================
    void SetSecurityLevelCKKS(SecurityLevel securityLevelCKKS0) {
        securityLevelCKKS = securityLevelCKKS0;
    }
    void SetSecurityLevelFHEW(BINFHE_PARAMSET securityLevelFHEW0) {
        securityLevelFHEW = securityLevelFHEW0;
    }
    void SetArbitraryFunctionEvaluation(bool arbitraryFunctionEvaluation0) {
        arbitraryFunctionEvaluation = arbitraryFunctionEvaluation0;
    }
    void SetUseDynamicModeFHEW(bool useDynamicModeFHEW0) {
        useDynamicModeFHEW = useDynamicModeFHEW0;
    }
    void SetComputeArgmin(bool computeArgmin0) {
        computeArgmin = computeArgmin0;
    }
    void SetOneHotEncoding(bool oneHotEncoding0) {
        oneHotEncoding = oneHotEncoding0;
    }
    void SetUseAltArgmin(bool useAltArgmin0) {
        useAltArgmin = useAltArgmin0;
    }
    void SetNumSlotsCKKS(uint32_t numSlotsCKKS0) {
        numSlotsCKKS = numSlotsCKKS0;
    }
    void SetNumValues(uint32_t numValues0) {
        numValues = numValues0;
    }
    void SetCtxtModSizeFHEWLargePrec(uint32_t ctxtModSizeFHEWLargePrec0) {
        ctxtModSizeFHEWLargePrec = ctxtModSizeFHEWLargePrec0;
    }
    void SetCtxtModSizeFHEWIntermedSwch(uint32_t ctxtModSizeFHEWIntermedSwch0) {
        ctxtModSizeFHEWIntermedSwch = ctxtModSizeFHEWIntermedSwch0;
    }
    void SetBStepLTrCKKStoFHEW(uint32_t bStepLTrCKKStoFHEW0) {
        bStepLTrCKKStoFHEW = bStepLTrCKKStoFHEW0;
    }
    void SetBStepLTrFHEWtoCKKS(uint32_t bStepLTrFHEWtoCKKS0) {
        bStepLTrFHEWtoCKKS = bStepLTrFHEWtoCKKS0;
    }
    void SetLevelLTrCKKStoFHEW(uint32_t levelLTrCKKStoFHEW0) {
        levelLTrCKKStoFHEW = levelLTrCKKStoFHEW0;
    }
    void SetLevelLTrFHEWtoCKKS(uint32_t levelLTrFHEWtoCKKS0) {
        levelLTrFHEWtoCKKS = levelLTrFHEWtoCKKS0;
    }
    void SetParamsFromCKKSCryptocontextCalled() {
        setParamsFromCKKSCryptocontextCalled = true;
    }
    void SetInitialCKKSModulus(const NativeInteger& initialCKKSModulus0) {
        initialCKKSModulus = initialCKKSModulus0;
    }
    void SetRingDimension(uint32_t ringDimension0) {
        ringDimension = ringDimension0;
    }
    void SetScalingModSize(uint32_t scalingModSize0) {
        scalingModSize = scalingModSize0;
    }
    void SetBatchSize(uint32_t batchSize0) {
        batchSize = batchSize0;
    }
    //=================================================================================================================
    SecurityLevel GetSecurityLevelCKKS() const {
        VerifyObjectData();
        return securityLevelCKKS;
    }
    BINFHE_PARAMSET GetSecurityLevelFHEW() const {
        VerifyObjectData();
        return securityLevelFHEW;
    }
    bool GetArbitraryFunctionEvaluation() const {
        VerifyObjectData();
        return arbitraryFunctionEvaluation;
    }
    bool GetUseDynamicModeFHEW() const {
        VerifyObjectData();
        return useDynamicModeFHEW;
    }
    bool GetComputeArgmin() const {
        VerifyObjectData();
        return computeArgmin;
    }
    bool GetOneHotEncoding() const {
        VerifyObjectData();
        return oneHotEncoding;
    }
    bool GetUseAltArgmin() const {
        VerifyObjectData();
        return useAltArgmin;
    }
    uint32_t GetNumSlotsCKKS() const {
        VerifyObjectData();
        return numSlotsCKKS;
    }
    uint32_t GetNumValues() const {
        VerifyObjectData();
        return numValues;
    }
    uint32_t GetCtxtModSizeFHEWLargePrec() const {
        VerifyObjectData();
        return ctxtModSizeFHEWLargePrec;
    }
    uint32_t GetCtxtModSizeFHEWIntermedSwch() const {
        VerifyObjectData();
        return ctxtModSizeFHEWIntermedSwch;
    }
    uint32_t GetBStepLTrCKKStoFHEW() const {
        VerifyObjectData();
        return bStepLTrCKKStoFHEW;
    }
    uint32_t GetBStepLTrFHEWtoCKKS() const {
        VerifyObjectData();
        return bStepLTrFHEWtoCKKS;
    }
    uint32_t GetLevelLTrCKKStoFHEW() const {
        VerifyObjectData();
        return levelLTrCKKStoFHEW;
    }
    uint32_t GetLevelLTrFHEWtoCKKS() const {
        VerifyObjectData();
        return levelLTrFHEWtoCKKS;
    }
    NativeInteger GetInitialCKKSModulus() const {
        VerifyObjectData();
        return initialCKKSModulus;
    }
    uint32_t GetRingDimension() const {
        VerifyObjectData();
        return ringDimension;
    }
    uint32_t GetScalingModSize() const {
        VerifyObjectData();
        return scalingModSize;
    }
    uint32_t GetBatchSize() const {
        VerifyObjectData();
        return batchSize;
    }
};

}  // namespace lbcrypto

#endif  // __SCHEME_SWCH_PARAMS_H__
