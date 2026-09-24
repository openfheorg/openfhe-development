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
#ifndef SRC_PKE_INCLUDE_SCHEME_SCHEME_SWCH_PARAMS_H_
#define SRC_PKE_INCLUDE_SCHEME_SCHEME_SWCH_PARAMS_H_

#include <cstdint>
#include <iosfwd>

#include "binfhe-constants.h"
#include "lattice/stdlatticeparms.h"
#include "math/math-hal.h"
#include "utils/exception.h"

namespace lbcrypto {

/**
 * @brief Parameters of the CKKS to FHEW and FHEW to CKKS scheme switching setup (EvalCKKStoFHEWSetup,
 * EvalSchemeSwitchingSetup and related calls)
 *
 * The user-facing fields are set with the setters below. The fields marked as populated internally are filled
 * from the CKKS cryptocontext by CryptoContextImpl::SetParamsFromCKKSCryptocontext(), and every getter throws an
 * exception until that call has been made.
 */
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
    /**
   * Prints all parameter values, including the ones populated from the CKKS cryptocontext.
   *
   * @param s the output stream
   * @param obj the parameter object to print
   * @return the output stream
   */
    friend std::ostream& operator<<(std::ostream& s, const SchSwchParams& obj);
    //=================================================================================================================
    /**
   * Sets the security level of the CKKS cryptocontext.
   * @param securityLevelCKKS0 security level of the CKKS cryptocontext
   */
    void SetSecurityLevelCKKS(SecurityLevel securityLevelCKKS0) {
        securityLevelCKKS = securityLevelCKKS0;
    }
    /**
   * Sets the FHEW/BinFHE parameter set (security level) of the FHEW cryptocontext.
   * @param securityLevelFHEW0 FHEW/BinFHE parameter set (security level) of the FHEW cryptocontext
   */
    void SetSecurityLevelFHEW(BINFHE_PARAMSET securityLevelFHEW0) {
        securityLevelFHEW = securityLevelFHEW0;
    }
    /**
   * Sets whether the FHEW cryptocontext is created for arbitrary function evaluation.
   * @param arbitraryFunctionEvaluation0 true if the FHEW cryptocontext is created for arbitrary function evaluation
   */
    void SetArbitraryFunctionEvaluation(bool arbitraryFunctionEvaluation0) {
        arbitraryFunctionEvaluation = arbitraryFunctionEvaluation0;
    }
    /**
   * Sets whether the FHEW cryptocontext is generated in dynamic mode.
   * @param useDynamicModeFHEW0 true to generate the FHEW cryptocontext in dynamic mode
   */
    void SetUseDynamicModeFHEW(bool useDynamicModeFHEW0) {
        useDynamicModeFHEW = useDynamicModeFHEW0;
    }
    /**
   * Sets whether the argmin computation (and its keys) should be supported.
   * @param computeArgmin0 true if the argmin computation (and its keys) should be supported
   */
    void SetComputeArgmin(bool computeArgmin0) {
        computeArgmin = computeArgmin0;
    }
    /**
   * Sets whether the argmin result is returned in one-hot encoding.
   * @param oneHotEncoding0 true to return the argmin result in one-hot encoding
   */
    void SetOneHotEncoding(bool oneHotEncoding0) {
        oneHotEncoding = oneHotEncoding0;
    }
    /**
   * Sets whether to use the alternative argmin version, which requires fewer automorphism keys.
   * @param useAltArgmin0 true to use the alternative argmin version, which requires fewer automorphism keys
   */
    void SetUseAltArgmin(bool useAltArgmin0) {
        useAltArgmin = useAltArgmin0;
    }
    /**
   * Sets the number of slots in the CKKS encryption.
   * @param numSlotsCKKS0 number of slots in the CKKS encryption
   */
    void SetNumSlotsCKKS(uint32_t numSlotsCKKS0) {
        numSlotsCKKS = numSlotsCKKS0;
    }
    /**
   * Sets the number of values to switch.
   * @param numValues0 number of values to switch
   */
    void SetNumValues(uint32_t numValues0) {
        numValues = numValues0;
    }
    /**
   * Sets the bit size of the FHEW ciphertext modulus for large-precision evaluation.
   * @param ctxtModSizeFHEWLargePrec0 bit size of the FHEW ciphertext modulus for large-precision evaluation
   */
    void SetCtxtModSizeFHEWLargePrec(uint32_t ctxtModSizeFHEWLargePrec0) {
        ctxtModSizeFHEWLargePrec = ctxtModSizeFHEWLargePrec0;
    }
    /**
   * Sets the bit size of the ciphertext modulus of the intermediate switch.
   * @param ctxtModSizeFHEWIntermedSwch0 bit size of the ciphertext modulus of the intermediate switch, chosen for
   *        security with the FHEW ring dimension
   */
    void SetCtxtModSizeFHEWIntermedSwch(uint32_t ctxtModSizeFHEWIntermedSwch0) {
        ctxtModSizeFHEWIntermedSwch = ctxtModSizeFHEWIntermedSwch0;
    }
    /**
   * Sets the baby-step of the linear transform in the CKKS to FHEW switching.
   * @param bStepLTrCKKStoFHEW0 baby-step of the linear transform in the CKKS to FHEW switching (0 selects the default)
   */
    void SetBStepLTrCKKStoFHEW(uint32_t bStepLTrCKKStoFHEW0) {
        bStepLTrCKKStoFHEW = bStepLTrCKKStoFHEW0;
    }
    /**
   * Sets the baby-step of the linear transform in the FHEW to CKKS switching.
   * @param bStepLTrFHEWtoCKKS0 baby-step of the linear transform in the FHEW to CKKS switching (0 selects the default)
   */
    void SetBStepLTrFHEWtoCKKS(uint32_t bStepLTrFHEWtoCKKS0) {
        bStepLTrFHEWtoCKKS = bStepLTrFHEWtoCKKS0;
    }
    /**
   * Sets the level at which the linear transform of the CKKS to FHEW switching is performed.
   * @param levelLTrCKKStoFHEW0 level at which the linear transform of the CKKS to FHEW switching is performed
   */
    void SetLevelLTrCKKStoFHEW(uint32_t levelLTrCKKStoFHEW0) {
        levelLTrCKKStoFHEW = levelLTrCKKStoFHEW0;
    }
    /**
   * Sets the level at which the linear transform of the FHEW to CKKS switching is performed.
   * @param levelLTrFHEWtoCKKS0 level at which the linear transform of the FHEW to CKKS switching is performed
   */
    void SetLevelLTrFHEWtoCKKS(uint32_t levelLTrFHEWtoCKKS0) {
        levelLTrFHEWtoCKKS = levelLTrFHEWtoCKKS0;
    }
    /**
   * Marks the object as populated from the CKKS cryptocontext, which unlocks the getters. Called by
   * CryptoContextImpl::SetParamsFromCKKSCryptocontext().
   */
    void SetParamsFromCKKSCryptocontextCalled() {
        setParamsFromCKKSCryptocontextCalled = true;
    }
    /**
   * Sets the first modulus of the CKKS cryptocontext.
   * Populated internally from the CKKS cryptocontext; not meant to be set by the user.
   * @param initialCKKSModulus0 first (largest-level) modulus of the CKKS cryptocontext
   */
    void SetInitialCKKSModulus(NativeInteger initialCKKSModulus0) {
        initialCKKSModulus = initialCKKSModulus0;
    }
    /**
   * Sets the ring dimension of the CKKS cryptocontext.
   * Populated internally from the CKKS cryptocontext; not meant to be set by the user.
   * @param ringDimension0 ring dimension of the CKKS cryptocontext
   */
    void SetRingDimension(uint32_t ringDimension0) {
        ringDimension = ringDimension0;
    }
    /**
   * Sets the bit size of the CKKS scaling modulus.
   * Populated internally from the CKKS cryptocontext; not meant to be set by the user.
   * @param scalingModSize0 bit size of the CKKS scaling modulus
   */
    void SetScalingModSize(uint32_t scalingModSize0) {
        scalingModSize = scalingModSize0;
    }
    /**
   * Sets the batch size of the CKKS cryptocontext.
   * Populated internally from the CKKS cryptocontext; not meant to be set by the user.
   * @param batchSize0 batch size of the CKKS cryptocontext
   */
    void SetBatchSize(uint32_t batchSize0) {
        batchSize = batchSize0;
    }
    //=================================================================================================================
    /**
   * Returns the security level of the CKKS cryptocontext.
   * Throws an exception if SetParamsFromCKKSCryptocontext() has not been called.
   * @return the security level of the CKKS cryptocontext
   */
    SecurityLevel GetSecurityLevelCKKS() const {
        VerifyObjectData();
        return securityLevelCKKS;
    }
    /**
   * Returns the FHEW parameter set.
   * Throws an exception if SetParamsFromCKKSCryptocontext() has not been called.
   * @return the FHEW parameter set
   */
    BINFHE_PARAMSET GetSecurityLevelFHEW() const {
        VerifyObjectData();
        return securityLevelFHEW;
    }
    /**
   * Returns whether the FHEW cryptocontext is created for arbitrary function evaluation.
   * Throws an exception if SetParamsFromCKKSCryptocontext() has not been called.
   * @return whether the FHEW cryptocontext is created for arbitrary function evaluation
   */
    bool GetArbitraryFunctionEvaluation() const {
        VerifyObjectData();
        return arbitraryFunctionEvaluation;
    }
    /**
   * Returns whether the FHEW cryptocontext is generated in dynamic mode.
   * Throws an exception if SetParamsFromCKKSCryptocontext() has not been called.
   * @return whether the FHEW cryptocontext is generated in dynamic mode
   */
    bool GetUseDynamicModeFHEW() const {
        VerifyObjectData();
        return useDynamicModeFHEW;
    }
    /**
   * Returns whether the argmin computation is supported.
   * Throws an exception if SetParamsFromCKKSCryptocontext() has not been called.
   * @return whether the argmin computation is supported
   */
    bool GetComputeArgmin() const {
        VerifyObjectData();
        return computeArgmin;
    }
    /**
   * Returns whether the argmin result is returned in one-hot encoding.
   * Throws an exception if SetParamsFromCKKSCryptocontext() has not been called.
   * @return whether the argmin result is returned in one-hot encoding
   */
    bool GetOneHotEncoding() const {
        VerifyObjectData();
        return oneHotEncoding;
    }
    /**
   * Returns whether the alternative argmin version is used.
   * Throws an exception if SetParamsFromCKKSCryptocontext() has not been called.
   * @return whether the alternative argmin version is used
   */
    bool GetUseAltArgmin() const {
        VerifyObjectData();
        return useAltArgmin;
    }
    /**
   * Returns the number of slots in the CKKS encryption.
   * Throws an exception if SetParamsFromCKKSCryptocontext() has not been called.
   * @return the number of slots in the CKKS encryption
   */
    uint32_t GetNumSlotsCKKS() const {
        VerifyObjectData();
        return numSlotsCKKS;
    }
    /**
   * Returns the number of values to switch.
   * Throws an exception if SetParamsFromCKKSCryptocontext() has not been called.
   * @return the number of values to switch
   */
    uint32_t GetNumValues() const {
        VerifyObjectData();
        return numValues;
    }
    /**
   * Returns the bit size of the FHEW ciphertext modulus for large-precision evaluation.
   * Throws an exception if SetParamsFromCKKSCryptocontext() has not been called.
   * @return the bit size of the FHEW ciphertext modulus for large-precision evaluation
   */
    uint32_t GetCtxtModSizeFHEWLargePrec() const {
        VerifyObjectData();
        return ctxtModSizeFHEWLargePrec;
    }
    /**
   * Returns the bit size of the intermediate-switch ciphertext modulus.
   * Throws an exception if SetParamsFromCKKSCryptocontext() has not been called.
   * @return the bit size of the intermediate-switch ciphertext modulus
   */
    uint32_t GetCtxtModSizeFHEWIntermedSwch() const {
        VerifyObjectData();
        return ctxtModSizeFHEWIntermedSwch;
    }
    /**
   * Returns the baby-step of the CKKS to FHEW linear transform.
   * Throws an exception if SetParamsFromCKKSCryptocontext() has not been called.
   * @return the baby-step of the CKKS to FHEW linear transform
   */
    uint32_t GetBStepLTrCKKStoFHEW() const {
        VerifyObjectData();
        return bStepLTrCKKStoFHEW;
    }
    /**
   * Returns the baby-step of the FHEW to CKKS linear transform.
   * Throws an exception if SetParamsFromCKKSCryptocontext() has not been called.
   * @return the baby-step of the FHEW to CKKS linear transform
   */
    uint32_t GetBStepLTrFHEWtoCKKS() const {
        VerifyObjectData();
        return bStepLTrFHEWtoCKKS;
    }
    /**
   * Returns the level of the CKKS to FHEW linear transform.
   * Throws an exception if SetParamsFromCKKSCryptocontext() has not been called.
   * @return the level of the CKKS to FHEW linear transform
   */
    uint32_t GetLevelLTrCKKStoFHEW() const {
        VerifyObjectData();
        return levelLTrCKKStoFHEW;
    }
    /**
   * Returns the level of the FHEW to CKKS linear transform.
   * Throws an exception if SetParamsFromCKKSCryptocontext() has not been called.
   * @return the level of the FHEW to CKKS linear transform
   */
    uint32_t GetLevelLTrFHEWtoCKKS() const {
        VerifyObjectData();
        return levelLTrFHEWtoCKKS;
    }
    /**
   * Returns the first modulus of the CKKS cryptocontext.
   * Throws an exception if SetParamsFromCKKSCryptocontext() has not been called.
   * @return the first modulus of the CKKS cryptocontext
   */
    NativeInteger GetInitialCKKSModulus() const {
        VerifyObjectData();
        return initialCKKSModulus;
    }
    /**
   * Returns the CKKS ring dimension.
   * Throws an exception if SetParamsFromCKKSCryptocontext() has not been called.
   * @return the CKKS ring dimension
   */
    uint32_t GetRingDimension() const {
        VerifyObjectData();
        return ringDimension;
    }
    /**
   * Returns the bit size of the CKKS scaling modulus.
   * Throws an exception if SetParamsFromCKKSCryptocontext() has not been called.
   * @return the bit size of the CKKS scaling modulus
   */
    uint32_t GetScalingModSize() const {
        VerifyObjectData();
        return scalingModSize;
    }
    /**
   * Returns the CKKS batch size.
   * Throws an exception if SetParamsFromCKKSCryptocontext() has not been called.
   * @return the CKKS batch size
   */
    uint32_t GetBatchSize() const {
        VerifyObjectData();
        return batchSize;
    }
};

}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_SCHEME_SCHEME_SWCH_PARAMS_H_
