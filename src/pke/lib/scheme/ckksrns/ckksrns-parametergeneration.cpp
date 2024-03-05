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
CKKS implementation. See https://eprint.iacr.org/2020/1118 for details.
 */

#define PROFILE

#include "cryptocontext.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "scheme/ckksrns/ckksrns-parametergeneration.h"

namespace lbcrypto {

#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
const size_t AUXMODSIZE = 119;
#else
const size_t AUXMODSIZE = 60;
#endif

bool ParameterGenerationCKKSRNS::ParamsGenCKKSRNS(std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams,
                                                  usint cyclOrder, usint numPrimes, usint scalingModSize,
                                                  usint firstModSize, uint32_t numPartQ,
                                                  COMPRESSION_LEVEL mPIntBootCiphertextCompressionLevel) const {
    const auto cryptoParamsCKKSRNS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cryptoParams);

    KeySwitchTechnique ksTech        = cryptoParamsCKKSRNS->GetKeySwitchTechnique();
    ScalingTechnique scalTech        = cryptoParamsCKKSRNS->GetScalingTechnique();
    EncryptionTechnique encTech      = cryptoParamsCKKSRNS->GetEncryptionTechnique();
    MultiplicationTechnique multTech = cryptoParamsCKKSRNS->GetMultiplicationTechnique();
    ProxyReEncryptionMode PREMode    = cryptoParamsCKKSRNS->GetPREMode();

    if ((PREMode != INDCPA) && (PREMode != NOT_SET)) {
        std::stringstream s;
        s << "This PRE mode " << PREMode << " is not supported for CKKSRNS";
        OPENFHE_THROW(s.str());
    }

    usint extraModSize = 0;
    if (scalTech == FLEXIBLEAUTOEXT) {
        // TODO: Allow the user to specify this?
        extraModSize = DCRT_MODULUS::DEFAULT_EXTRA_MOD_SIZE;
    }

    //// HE Standards compliance logic/check
    SecurityLevel stdLevel = cryptoParamsCKKSRNS->GetStdLevel();
    uint32_t auxBits       = AUXMODSIZE;
    uint32_t n             = cyclOrder / 2;
    uint32_t qBound        = firstModSize + (numPrimes - 1) * scalingModSize + extraModSize;
    // Estimate ciphertext modulus Q bound (in case of GHS/HYBRID P*Q)
    if (ksTech == HYBRID) {
        qBound += ceil(ceil(static_cast<double>(qBound) / numPartQ) / auxBits) * auxBits;
    }

    // GAUSSIAN security constraint
    DistributionType distType = (cryptoParamsCKKSRNS->GetSecretKeyDist() == GAUSSIAN) ? HEStd_error : HEStd_ternary;
    auto nRLWE                = [&](usint q) -> uint32_t {
        return StdLatticeParm::FindRingDim(distType, stdLevel, q);
    };

    // Case 1: SecurityLevel specified as HEStd_NotSet -> Do nothing
    if (stdLevel != HEStd_NotSet) {
        if (n == 0) {
            // Case 2: SecurityLevel specified, but ring dimension not specified

            // Choose ring dimension based on security standards
            n         = nRLWE(qBound);
            cyclOrder = 2 * n;
        }
        else {  // if (n!=0)
            // Case 3: Both SecurityLevel and ring dimension specified

            // Check whether particular selection is standards-compliant
            auto he_std_n = nRLWE(qBound);
            if (he_std_n > n) {
                OPENFHE_THROW("The specified ring dimension (" + std::to_string(n) +
                              ") does not comply with HE standards recommendation (" + std::to_string(he_std_n) + ").");
            }
        }
    }
    else if (n == 0) {
        OPENFHE_THROW("Please specify the ring dimension or desired security level.");
    }
    //// End HE Standards compliance logic/check

    usint dcrtBits = scalingModSize;

    uint32_t vecSize = (extraModSize == 0) ? numPrimes : numPrimes + 1;
    std::vector<NativeInteger> moduliQ(vecSize);
    std::vector<NativeInteger> rootsQ(vecSize);

    NativeInteger q        = FirstPrime<NativeInteger>(dcrtBits, cyclOrder);
    moduliQ[numPrimes - 1] = q;
    rootsQ[numPrimes - 1]  = RootOfUnity(cyclOrder, moduliQ[numPrimes - 1]);

    NativeInteger qNext = q;
    NativeInteger qPrev = q;
    if (numPrimes > 1) {
        if (scalTech != FLEXIBLEAUTO && scalTech != FLEXIBLEAUTOEXT) {
            uint32_t cnt = 0;
            for (usint i = numPrimes - 2; i >= 1; i--) {
                if ((cnt % 2) == 0) {
                    qPrev = PreviousPrime(qPrev, cyclOrder);
                    q     = qPrev;
                }
                else {
                    qNext = NextPrime(qNext, cyclOrder);
                    q     = qNext;
                }

                moduliQ[i] = q;
                rootsQ[i]  = RootOfUnity(cyclOrder, moduliQ[i]);
                cnt++;
            }
        }
        else {  // FLEXIBLEAUTO
            /* Scaling factors in FLEXIBLEAUTO are a bit fragile,
       * in the sense that once one scaling factor gets far enough from the
       * original scaling factor, subsequent level scaling factors quickly
       * diverge to either 0 or infinity. To mitigate this problem to a certain
       * extend, we have a special prime selection process in place. The goal is
       * to maintain the scaling factor of all levels as close to the original
       * scale factor of level 0 as possible.
       */

            double sf    = moduliQ[numPrimes - 1].ConvertToDouble();
            uint32_t cnt = 0;
            for (usint i = numPrimes - 2; i >= 1; i--) {
                sf = static_cast<double>(pow(sf, 2) / moduliQ[i + 1].ConvertToDouble());
                if ((cnt % 2) == 0) {
                    NativeInteger sfInt = std::llround(sf);
                    NativeInteger sfRem = sfInt.Mod(cyclOrder);
                    NativeInteger qPrev = sfInt - NativeInteger(cyclOrder) - sfRem + NativeInteger(1);

                    bool hasSameMod = true;
                    while (hasSameMod) {
                        hasSameMod = false;
                        qPrev      = PreviousPrime(qPrev, cyclOrder);
                        for (uint32_t j = i + 1; j < numPrimes; j++) {
                            if (qPrev == moduliQ[j]) {
                                hasSameMod = true;
                            }
                        }
                    }
                    moduliQ[i] = qPrev;
                }
                else {
                    NativeInteger sfInt = std::llround(sf);
                    NativeInteger sfRem = sfInt.Mod(cyclOrder);
                    NativeInteger qNext = sfInt + NativeInteger(cyclOrder) - sfRem + NativeInteger(1);
                    bool hasSameMod     = true;
                    while (hasSameMod) {
                        hasSameMod = false;
                        qNext      = NextPrime(qNext, cyclOrder);
                        for (uint32_t j = i + 1; j < numPrimes; j++) {
                            if (qNext == moduliQ[j]) {
                                hasSameMod = true;
                            }
                        }
                    }
                    moduliQ[i] = qNext;
                }

                rootsQ[i] = RootOfUnity(cyclOrder, moduliQ[i]);
                cnt++;
            }
        }
    }

    if (firstModSize == dcrtBits) {  // this requires dcrtBits < 60
        moduliQ[0] = PreviousPrime<NativeInteger>(qPrev, cyclOrder);
    }
    else {
        moduliQ[0] = LastPrime<NativeInteger>(firstModSize, cyclOrder);
    }
    rootsQ[0] = RootOfUnity(cyclOrder, moduliQ[0]);

    if (scalTech == FLEXIBLEAUTOEXT) {
        // no need for extra checking as extraModSize is automatically chosen by the library
        moduliQ[numPrimes] = FirstPrime<NativeInteger>(extraModSize - 1, cyclOrder);
        rootsQ[numPrimes]  = RootOfUnity(cyclOrder, moduliQ[numPrimes]);
    }

    auto paramsDCRT = std::make_shared<ILDCRTParams<BigInteger>>(cyclOrder, moduliQ, rootsQ);

    cryptoParamsCKKSRNS->SetElementParams(paramsDCRT);

    const EncodingParams encodingParams = cryptoParamsCKKSRNS->GetEncodingParams();
    if (encodingParams->GetBatchSize() > n / 2)
        OPENFHE_THROW("The batch size cannot be larger than ring dimension / 2.");

    if (encodingParams->GetBatchSize() & (encodingParams->GetBatchSize() - 1))
        OPENFHE_THROW("The batch size can only be set to zero (for full packing) or a power of two.");

    // if no batch size was specified, we set batchSize = n/2 by default (for full
    // packing)
    if (encodingParams->GetBatchSize() == 0) {
        uint32_t batchSize = n / 2;
        EncodingParams encodingParamsNew(
            std::make_shared<EncodingParamsImpl>(encodingParams->GetPlaintextModulus(), batchSize));
        cryptoParamsCKKSRNS->SetEncodingParams(encodingParamsNew);
    }

    cryptoParamsCKKSRNS->PrecomputeCRTTables(ksTech, scalTech, encTech, multTech, numPartQ, auxBits, extraModSize);

    return true;
}

}  // namespace lbcrypto
