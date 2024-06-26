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
    // the "const" modifier for cryptoParamsCKKSRNS and encodingParams below doesn't mean that the objects those 2 pointers
    // point to are const (not changeable). it means that the pointers themselves are const only.
    const auto cryptoParamsCKKSRNS      = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cryptoParams);
    const EncodingParams encodingParams = cryptoParamsCKKSRNS->GetEncodingParams();

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

    // TODO: Allow the user to specify this?
    uint32_t extraModSize = (scalTech == FLEXIBLEAUTOEXT) ? DCRT_MODULUS::DEFAULT_EXTRA_MOD_SIZE : 0;

    //// HE Standards compliance logic/check
    SecurityLevel stdLevel = cryptoParamsCKKSRNS->GetStdLevel();
    uint32_t auxBits       = AUXMODSIZE;
    uint32_t n             = cyclOrder / 2;
    uint32_t qBound        = firstModSize + (numPrimes - 1) * scalingModSize + extraModSize;

    // Estimate ciphertext modulus Q*P bound (in case of HYBRID P*Q)
    if (ksTech == HYBRID) {
        auto hybridKSInfo =
            CryptoParametersRNS::EstimateLogP(numPartQ, firstModSize, scalingModSize, extraModSize, numPrimes, auxBits);
        qBound += std::get<0>(hybridKSInfo);
    }

    // GAUSSIAN security constraint
    DistributionType distType = (cryptoParamsCKKSRNS->GetSecretKeyDist() == GAUSSIAN) ? HEStd_error : HEStd_ternary;
    auto nRLWE                = [&](uint32_t q) -> uint32_t {
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

    if (encodingParams->GetBatchSize() > n / 2)
        OPENFHE_THROW("The batch size cannot be larger than ring dimension / 2.");

    if (encodingParams->GetBatchSize() & (encodingParams->GetBatchSize() - 1))
        OPENFHE_THROW("The batch size can only be set to zero (for full packing) or a power of two.");
    //// End HE Standards compliance logic/check

    uint32_t dcrtBits = scalingModSize;

    uint32_t vecSize = (extraModSize == 0) ? numPrimes : numPrimes + 1;
    std::vector<NativeInteger> moduliQ(vecSize);
    std::vector<NativeInteger> rootsQ(vecSize);

    NativeInteger q        = FirstPrime<NativeInteger>(dcrtBits, cyclOrder);
    moduliQ[numPrimes - 1] = q;
    rootsQ[numPrimes - 1]  = RootOfUnity(cyclOrder, moduliQ[numPrimes - 1]);

    NativeInteger maxPrime{q};
    NativeInteger minPrime{q};
    if (numPrimes > 1) {
        if (scalTech != FLEXIBLEAUTO && scalTech != FLEXIBLEAUTOEXT) {
            NativeInteger qPrev = q;
            NativeInteger qNext = q;
            for (size_t i = numPrimes - 2, cnt = 0; i >= 1; --i, ++cnt) {
                if ((cnt % 2) == 0) {
                    qPrev      = PreviousPrime(qPrev, cyclOrder);
                    moduliQ[i] = qPrev;
                }
                else {
                    qNext      = NextPrime(qNext, cyclOrder);
                    moduliQ[i] = qNext;
                }

                if (moduliQ[i] > maxPrime)
                    maxPrime = moduliQ[i];
                else if (moduliQ[i] < minPrime)
                    minPrime = moduliQ[i];

                rootsQ[i] = RootOfUnity(cyclOrder, moduliQ[i]);
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
            double sf = moduliQ[numPrimes - 1].ConvertToDouble();
            for (size_t i = numPrimes - 2, cnt = 0; i >= 1; --i, ++cnt) {
                sf                  = static_cast<double>(pow(sf, 2) / moduliQ[i + 1].ConvertToDouble());
                NativeInteger sfInt = std::llround(sf);
                NativeInteger sfRem = sfInt.Mod(cyclOrder);
                bool hasSameMod     = true;
                if ((cnt % 2) == 0) {
                    NativeInteger qPrev = sfInt - NativeInteger(cyclOrder) - sfRem + NativeInteger(1);
                    while (hasSameMod) {
                        hasSameMod = false;
                        qPrev      = PreviousPrime(qPrev, cyclOrder);
                        for (size_t j = i + 1; j < numPrimes; j++) {
                            if (qPrev == moduliQ[j]) {
                                hasSameMod = true;
                                break;
                            }
                        }
                    }
                    moduliQ[i] = qPrev;
                }
                else {
                    NativeInteger qNext = sfInt + NativeInteger(cyclOrder) - sfRem + NativeInteger(1);
                    while (hasSameMod) {
                        hasSameMod = false;
                        qNext      = NextPrime(qNext, cyclOrder);
                        for (size_t j = i + 1; j < numPrimes; j++) {
                            if (qNext == moduliQ[j]) {
                                hasSameMod = true;
                                break;
                            }
                        }
                    }
                    moduliQ[i] = qNext;
                }
                if (moduliQ[i] > maxPrime)
                    maxPrime = moduliQ[i];
                else if (moduliQ[i] < minPrime)
                    minPrime = moduliQ[i];

                rootsQ[i] = RootOfUnity(cyclOrder, moduliQ[i]);
            }
        }
    }

    if (firstModSize == dcrtBits) {  // this requires dcrtBits < 60
        moduliQ[0] = NextPrime<NativeInteger>(maxPrime, cyclOrder);
    }
    else {
        moduliQ[0] = LastPrime<NativeInteger>(firstModSize, cyclOrder);

        // find if the value of moduliQ[0] is already in the vector starting with moduliQ[1] and
        // if there is, then get another prime for moduliQ[0]
        const auto pos = std::find(moduliQ.begin() + 1, moduliQ.end(), moduliQ[0]);
        if (pos != moduliQ.end()) {
            moduliQ[0] = NextPrime<NativeInteger>(maxPrime, cyclOrder);
        }
    }
    if (moduliQ[0] > maxPrime)
        maxPrime = moduliQ[0];

    rootsQ[0] = RootOfUnity(cyclOrder, moduliQ[0]);

    if (scalTech == FLEXIBLEAUTOEXT) {
        // moduliQ[numPrimes] must still be 0, so it has to be populated now

        // no need for extra checking as extraModSize is automatically chosen by the library
        auto tempMod = FirstPrime<NativeInteger>(extraModSize - 1, cyclOrder);
        // check if tempMod has a duplicate in the vector (exclude moduliQ[numPrimes] from this operation):
        const auto endPos = moduliQ.end() - 1;
        auto pos          = std::find(moduliQ.begin(), endPos, tempMod);
        // if there is a duplicate, then we call NextPrime()
        moduliQ[numPrimes] = (pos != endPos) ? NextPrime<NativeInteger>(maxPrime, cyclOrder) : tempMod;

        rootsQ[numPrimes] = RootOfUnity(cyclOrder, moduliQ[numPrimes]);
    }

    auto paramsDCRT = std::make_shared<ILDCRTParams<BigInteger>>(cyclOrder, moduliQ, rootsQ);

    cryptoParamsCKKSRNS->SetElementParams(paramsDCRT);

    // if no batch size was specified, we set batchSize = n/2 by default (for full packing)
    if (encodingParams->GetBatchSize() == 0) {
        uint32_t batchSize = n / 2;
        EncodingParams encodingParamsNew(
            std::make_shared<EncodingParamsImpl>(encodingParams->GetPlaintextModulus(), batchSize));
        cryptoParamsCKKSRNS->SetEncodingParams(encodingParamsNew);
    }

    cryptoParamsCKKSRNS->PrecomputeCRTTables(ksTech, scalTech, encTech, multTech, numPartQ, auxBits, extraModSize);

    // Validate the ring dimension found using estimated logQ(P) against actual logQ(P)
    if (stdLevel != HEStd_NotSet) {
        uint32_t logActualQ = 0;
        if (ksTech == HYBRID) {
            logActualQ = cryptoParamsCKKSRNS->GetParamsQP()->GetModulus().GetMSB();
        }
        else {
            logActualQ = cryptoParamsCKKSRNS->GetElementParams()->GetModulus().GetMSB();
        }

        uint32_t nActual = StdLatticeParm::FindRingDim(distType, stdLevel, logActualQ);
        if (n < nActual) {
            std::string errMsg("The ring dimension found using estimated logQ(P) [");
            errMsg += std::to_string(n) + "] does does not meet security requirements. ";
            errMsg += "Report this problem to OpenFHE developers and set the ring dimension manually to ";
            errMsg += std::to_string(nActual) + ".";

            OPENFHE_THROW(errMsg);
        }
    }

    return true;
}

}  // namespace lbcrypto
