// @file cryptocontextparams-base.h -- PALISADE.
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef _CRYPTOCONTEXTPARAMS_BASE_H_
#define _CRYPTOCONTEXTPARAMS_BASE_H_

// Had to include cryptocontext.h as the includes below give a compiler error.
// Those headers probably depend on some order/sequence.
//TODO: fix the problem with header described above (dsuponit)
//#include "lattice/stdlatticeparms.h" // SecurityLevel
//#include "pubkeylp.h" // KeySwitchTechnique
#include "cryptocontext.h"
#include "scheme/scheme-id.h" // SCHEME
#include "utils/inttypes.h"
#include "constants.h"

#include <iosfwd>


namespace lbcrypto {

//====================================================================================================================
class Params {
    // NOTE: if any data member (below) is added/removed then update
    // cryptocontextparams-case.cpp and cryptocontextparams-defaults.h
    SCHEME                    scheme;
    PlaintextModulus          ptModulus;
    usint                     relinWindow;
    float                     standardDeviation;
    float                     rootHermiteFactor;
    float                     assuranceMeasure;
    MODE                      mode;
    int                       depth;
    int                       maxDepth;
    KeySwitchTechnique        ksTech;
    RescalingTechnique        rsTech;
    usint                     cyclOrder;
    usint                     numPrimes;
    usint                     scaleExp;
    usint                     batchSize;
    usint                     firstModSize;
    usint                     numLargeDigits;
    usint                     multiplicativeDepth;
    usint                     scalingFactorBits; // or dcrtBits
    SecurityLevel             securityLevel;
    usint                     ringDim;
    ModSwitchMethod           msMethod;
    usint                     multiHopQModulusLowerBound;

    void SetToDefaults(SCHEME scheme);

public:
    Params(SCHEME scheme0 = INVALID_SCHEME) {
        SetToDefaults(scheme0);
    }

    Params(const Params& obj) = default;
    Params(Params&& obj) = default;

    Params& operator=(const Params& obj) = default;
    Params& operator=(Params&& obj) = default;

    ~Params() = default;

    bool IsValidRootHermiteFactor() const {
        // rootHermiteFactor is valid or set if it is greater than or equal to 1.0
        float epsilon = 0.001;
        return (rootHermiteFactor >= (1.0-epsilon));
    }
    // getters
    SCHEME GetScheme() const {
        return scheme;
    }
    PlaintextModulus GetPlaintextModulus() const {
        return ptModulus;
    }
    usint GetRelinWindow() const {
        return relinWindow;
    }
    float GetStandardDeviation() const {
        return standardDeviation;
    }
    float GetRootHermiteFactor() const {
        return rootHermiteFactor;
    }
    float GetAssuranceMeasure() const {
        return assuranceMeasure;
    }
    MODE GetMode() const {
        return mode;
    }
    int GetDepth() const {
        return depth;
    }
    int GetMaxDepth() const {
        return maxDepth;
    }
    KeySwitchTechnique GetKeySwitchTechnique() const {
        return ksTech;
    }
    RescalingTechnique GetRescalingTechnique() const {
        return rsTech;
    }
    usint GetCyclotomicOrder() const {
        return cyclOrder;
    }
    usint GetNumPrimes() const {
        return numPrimes;
    }
    usint GetScaleExp() const {
        return scaleExp;
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
    usint GetScalingFactorBits() const {
        return scalingFactorBits;
    }
    SecurityLevel GetSecurityLevel() const {
        return securityLevel;
    }
    usint GetRingDim() const {
        return ringDim;
    }
    ModSwitchMethod GetModSwitchMethod() const {
        return msMethod;
    }
    usint GetMultiHopQModulusLowerBound() const {
        return multiHopQModulusLowerBound;
    }

    // setters
    void SetPlaintextModulus(PlaintextModulus ptModulus0) {
        ptModulus = ptModulus0;
    }
    void SetRelinWindow(usint relinWindow0) {
        relinWindow = relinWindow0;
    }
    void SetStandardDeviation(float standardDeviation0) {
        standardDeviation = standardDeviation0;
    }
    void SetRootHermiteFactor(float rootHermiteFactor0) {
        rootHermiteFactor = rootHermiteFactor0;
    }
    void SetAssuranceMeasure(float assuranceMeasure0) {
        assuranceMeasure = assuranceMeasure0;
    }
    void SetMode(MODE mode0) {
        mode = mode0;
    }
    void SetDepth(int depth0) {
        depth = depth0;
    }
    void SetMaxDepth(int maxDepth0) {
        maxDepth = maxDepth0;
    }
    void SetKeySwitchTechnique(KeySwitchTechnique ksTech0) {
        ksTech = ksTech0;
    }
    void SetRescalingTechnique(RescalingTechnique rsTech0) {
        rsTech = rsTech0;
    }
    void SetCyclotomicOrder(usint cyclOrder0) {
        cyclOrder = cyclOrder0;
    }
    void SetNumPrimes(usint numPrimes0) {
        numPrimes = numPrimes0;
    }
    void SetScaleExp(usint scaleExp0) {
        scaleExp = scaleExp0;
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
    void SetScalingFactorBits(usint scalingFactorBits0) {
        scalingFactorBits = scalingFactorBits0;
    }
    void SetSecurityLevel(SecurityLevel securityLevel0) {
        securityLevel = securityLevel0;
    }
    void SetRingDim(usint ringDim0) {
        ringDim = ringDim0;
    }
    void SetModSwitchMethod(ModSwitchMethod msMethod0) {
        msMethod = msMethod0;
    }
    void SetMultiHopQModulusLowerBound(usint multiHopQModulusLowerBound0) {
        multiHopQModulusLowerBound = multiHopQModulusLowerBound0;
    }

    friend std::ostream& operator<<(std::ostream& os, const Params& obj);
};
//====================================================================================================================

}  // namespace lbcrypto


#endif // _CRYPTOCONTEXTPARAMS_BASE_H_

