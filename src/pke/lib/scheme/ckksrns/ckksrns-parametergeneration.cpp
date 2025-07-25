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

#include <vector>
#include <memory>
#include <string>
#include <unordered_set>
#include <iostream>

namespace lbcrypto {

#if NATIVEINT == 128
constexpr size_t AUXMODSIZE = 119;
#elif NATIVEINT == 32
constexpr size_t AUXMODSIZE = 28;
#else
constexpr size_t AUXMODSIZE = 60;
#endif

bool ParameterGenerationCKKSRNS::ParamsGenCKKSRNSInternal(std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams,
                                                          uint32_t cyclOrder, uint32_t numPrimes,
                                                          uint32_t scalingModSize, uint32_t firstModSize,
                                                          uint32_t numPartQ,
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

    // Determine appropriate composite degree automatically if scaling technique set to COMPOSITESCALINGAUTO
    cryptoParamsCKKSRNS->ConfigureCompositeDegree(firstModSize);

    uint32_t compositeDegree  = cryptoParamsCKKSRNS->GetCompositeDegree();
    uint32_t registerWordSize = cryptoParamsCKKSRNS->GetRegisterWordSize();

    if (scalTech == COMPOSITESCALINGAUTO || scalTech == COMPOSITESCALINGMANUAL) {
        // TODO (Duhyeong): We need more exception cases in terms of
        //                  prime size (= scalingModSize / compositeDegree), registerSize, and numPrimes
        //                  e.g.1, assertion: prime size < registerSize (we may need at least 1-2 bit gap)
        //                  e.g.2, prime size > ??? if numPrimes > ???
        if (compositeDegree > 2 && scalingModSize < 60) {
            std::string errorMsg = "Prime moduli size is too small. It must generally be greater than 19,";
            errorMsg += " especially for larger multiplicative depth.";
            errorMsg += " Please increase the scaling factor (scalingModSize) or the register word size.";
            errorMsg += " Also, you can use COMPOSITESCALINGMANUAL at your own risk.";
            OPENFHE_THROW(errorMsg);
        }
        else if (compositeDegree == 1 && registerWordSize < 64) {
            OPENFHE_THROW(
                "This COMPOSITESCALING* version does not support composite degree == 1 with register size < 64.");
        }
        else if (compositeDegree < 1) {
            OPENFHE_THROW("Composite degree must be greater than or equal to 1.");
        }

        if (registerWordSize < 20 && scalTech == COMPOSITESCALINGAUTO) {
            OPENFHE_THROW(
                "Register word size must be greater than or equal to 20 for COMPOSITESCALINGAUTO. Otherwise, try it with COMPOSITESCALINGMANUAL.");
        }
    }

    if ((PREMode != INDCPA) && (PREMode != NOT_SET)) {
        std::stringstream s;
        s << "This PRE mode " << PREMode << " is not supported for CKKSRNS";
        OPENFHE_THROW(s.str());
    }

    // TODO: Allow the user to specify this?
    uint32_t extraModSize = (scalTech == FLEXIBLEAUTOEXT) ? DCRT_MODULUS::DEFAULT_EXTRA_MOD_SIZE : 0;

    //// HE Standards compliance logic/check
    SecurityLevel stdLevel = cryptoParamsCKKSRNS->GetStdLevel();
    // TODO Duhyeong: Let's check if auxBits = registerWordSize makes an error in the P prime generation.
    uint32_t auxBits =
        ((scalTech == COMPOSITESCALINGAUTO || scalTech == COMPOSITESCALINGMANUAL) && registerWordSize <= AUXMODSIZE) ?
            (registerWordSize - 1) :
            AUXMODSIZE;
    uint32_t n = cyclOrder / 2;

    // GAUSSIAN security constraint
    DistributionType distType = (cryptoParamsCKKSRNS->GetSecretKeyDist() == GAUSSIAN) ? HEStd_error : HEStd_ternary;
    if (stdLevel != HEStd_NotSet) {
        uint32_t qBound = firstModSize + (numPrimes - 1) * scalingModSize + extraModSize;

        // we add an extra bit to account for the alternating logic of selecting the RNS moduli in CKKS
        // ignore the case when there is only one max size modulus
        if (qBound != auxBits)
            ++qBound;

        // Estimate ciphertext modulus Q*P bound (in case of HYBRID P*Q)
        if (ksTech == HYBRID)
            qBound += std::get<0>(CryptoParametersRNS::EstimateLogP(numPartQ, firstModSize, scalingModSize,
                                                                    extraModSize, numPrimes, auxBits, scalTech, true));

        uint32_t he_std_n = StdLatticeParm::FindRingDim(distType, stdLevel, qBound);

        if (n == 0) {
            // Choose ring dimension based on security standards
            n         = he_std_n;
            cyclOrder = 2 * n;
        }
        else {
            // Check whether particular selection is standards-compliant
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

    // In COMPOSITESCALING mode, each modulus consists of compositeDegree number of primes
    numPrimes *= compositeDegree;

    uint32_t vecSize = (extraModSize == 0) ? numPrimes : numPrimes + 1;
    std::vector<NativeInteger> moduliQ(vecSize);
    std::vector<NativeInteger> rootsQ(vecSize);

    if ((scalTech == COMPOSITESCALINGAUTO || scalTech == COMPOSITESCALINGMANUAL) && (compositeDegree > 1)) {
        CompositePrimeModuliGen(moduliQ, rootsQ, compositeDegree, numPrimes, firstModSize, dcrtBits, cyclOrder,
                                registerWordSize);
    }
    else
        SinglePrimeModuliGen(moduliQ, rootsQ, scalTech, numPrimes, firstModSize, dcrtBits, cyclOrder, extraModSize);

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
        uint32_t logActualQ = (ksTech == HYBRID) ? cryptoParamsCKKSRNS->GetParamsQP()->GetModulus().GetMSB() :
                                                   cryptoParamsCKKSRNS->GetElementParams()->GetModulus().GetMSB();

        uint32_t nActual = StdLatticeParm::FindRingDim(distType, stdLevel, logActualQ);
        if (n < nActual) {
            std::string errMsg("The ring dimension [");
            errMsg += std::to_string(n) + "] does not meet security requirements. ";
            OPENFHE_THROW(errMsg);
        }
    }

    return true;
}

void ParameterGenerationCKKSRNS::CompositePrimeModuliGen(std::vector<NativeInteger>& moduliQ,
                                                         std::vector<NativeInteger>& rootsQ, uint32_t compositeDegree,
                                                         uint32_t numPrimes, uint32_t firstModSize, uint32_t dcrtBits,
                                                         uint32_t cyclOrder, uint32_t registerWordSize) const {
    if (firstModSize <= dcrtBits) {
        OPENFHE_THROW("firstModSize must be > scalingModSize.");
    }

    std::unordered_set<uint64_t> moduliQRecord;

    for (uint32_t d = 1, remBits = dcrtBits; d <= compositeDegree; ++d) {
        uint32_t qBitSize = std::ceil(static_cast<double>(remBits) / (compositeDegree - d + 1));
        NativeInteger q   = FirstPrime<NativeInteger>(qBitSize, cyclOrder);
        q                 = PreviousPrime<NativeInteger>(q, cyclOrder);
        while (std::log2(q.ConvertToDouble()) > registerWordSize || std::log2(q.ConvertToDouble()) > qBitSize ||
               moduliQRecord.find(q.ConvertToInt()) != moduliQRecord.end()) {
            q = PreviousPrime<NativeInteger>(q, cyclOrder);
        }
        moduliQ[numPrimes - d] = q;
        rootsQ[numPrimes - d]  = RootOfUnity(cyclOrder, moduliQ[numPrimes - d]);
        moduliQRecord.emplace(q.ConvertToInt());
        remBits -= std::ceil(std::log2(q.ConvertToDouble()));
    }

    const std::string compositeScalingErrMsg =
        "COMPOSITE SCALING prime sampling error. Consider increasing the scaling factor or the register word size.";

    if (numPrimes > 1) {
        std::vector<NativeInteger> qPrev(std::ceil(static_cast<double>(compositeDegree) / 2));
        std::vector<NativeInteger> qNext(compositeDegree - static_cast<uint32_t>(qPrev.size()));

        // Prep to compute initial scaling factor
        double sf = moduliQ[numPrimes - 1].ConvertToDouble();
        for (uint32_t d = 2; d <= compositeDegree; ++d) {
            sf *= moduliQ[numPrimes - d].ConvertToDouble();
        }

        bool flag = true;
        for (uint32_t i = numPrimes - compositeDegree; i >= 2 * compositeDegree; i -= compositeDegree) {
            // Compute initial scaling factor
            sf = std::pow(sf, 2);
            for (uint32_t d = 0; d < compositeDegree; ++d) {
                sf /= moduliQ[i + d].ConvertToDouble();
            }

            auto sf_sqrt = std::pow(sf, 1.0 / compositeDegree);

            NativeInteger sfInt = std::llround(sf_sqrt);
            NativeInteger sfRem = sfInt.Mod(cyclOrder);

            double primeProduct = 1.0;
            std::unordered_set<uint64_t> qCurrentRecord;  // current prime tracker

            for (size_t step = 0; step < qPrev.size(); ++step) {
                qPrev[step] = sfInt - sfRem + NativeInteger(1) - NativeInteger(cyclOrder);
                do {
                    try {
                        qPrev[step] = lbcrypto::PreviousPrime(qPrev[step], cyclOrder);
                    }
                    catch (const OpenFHEException& ex) {
                        OPENFHE_THROW(compositeScalingErrMsg);
                    }
                } while (std::log2(qPrev[step].ConvertToDouble()) > registerWordSize ||
                         moduliQRecord.find(qPrev[step].ConvertToInt()) != moduliQRecord.end() ||
                         qCurrentRecord.find(qPrev[step].ConvertToInt()) != qCurrentRecord.end());
                qCurrentRecord.emplace(qPrev[step].ConvertToInt());
                primeProduct *= qPrev[step].ConvertToDouble();
            }

            bool fitsRegister = true;
            for (size_t step = 0; step < qNext.size(); ++step) {
                qNext[step] = sfInt - sfRem + NativeInteger(1) + NativeInteger(cyclOrder);
                do {
                    try {
                        if (fitsRegister == true) {
                            qNext[step] = lbcrypto::NextPrime(qNext[step], cyclOrder);
                        }
                        else {
                            qNext[step] = lbcrypto::PreviousPrime(qNext[step], cyclOrder);
                        }
                    }
                    catch (const OpenFHEException& ex) {
                        OPENFHE_THROW(compositeScalingErrMsg);
                    }
                    if (std::log2(qNext[step].ConvertToDouble()) > registerWordSize) {
                        fitsRegister = false;
                    }
                } while (std::log2(qNext[step].ConvertToDouble()) > registerWordSize ||
                         moduliQRecord.find(qNext[step].ConvertToInt()) != moduliQRecord.end() ||
                         qCurrentRecord.find(qNext[step].ConvertToInt()) != qCurrentRecord.end());
                qCurrentRecord.emplace(qNext[step].ConvertToInt());
                primeProduct *= qNext[step].ConvertToDouble();
            }

            if (flag == false) {
                NativeInteger qPrevNext = NativeInteger(qNext[qNext.size() - 1].ConvertToInt());
                while (primeProduct > sf) {
                    do {
                        qCurrentRecord.erase(qPrevNext.ConvertToInt());  // constant time
                        try {
                            qPrevNext = lbcrypto::PreviousPrime(qPrevNext, cyclOrder);
                        }
                        catch (const OpenFHEException& ex) {
                            OPENFHE_THROW(compositeScalingErrMsg);
                        }
                    } while (std::log2(qPrevNext.ConvertToDouble()) > registerWordSize ||
                             moduliQRecord.find(qPrevNext.ConvertToInt()) != moduliQRecord.end() ||
                             qCurrentRecord.find(qPrevNext.ConvertToInt()) != qCurrentRecord.end());
                    qCurrentRecord.emplace(qPrevNext.ConvertToInt());

                    primeProduct /= qNext[qNext.size() - 1].ConvertToDouble();
                    qNext[qNext.size() - 1] = qPrevNext;
                    primeProduct *= qPrevNext.ConvertToDouble();
                }

                uint32_t m = qPrev.size();
                for (uint32_t d = 1; d <= m; ++d) {
                    moduliQ[i - d] = qPrev[d - 1];
                }
                for (uint32_t d = m + 1; d <= compositeDegree; ++d) {
                    moduliQ[i - d] = qNext[d - (m + 1)];
                }

                for (uint32_t d = 1; d <= compositeDegree; ++d) {
                    rootsQ[i - d] = RootOfUnity(cyclOrder, moduliQ[i - d]);
                    moduliQRecord.emplace(moduliQ[i - d].ConvertToInt());
                }

                flag = true;
            }
            else {
                NativeInteger qNextPrev = NativeInteger(qPrev[qPrev.size() - 1].ConvertToInt());
                fitsRegister            = true;
                while (primeProduct < sf) {
                    do {
                        qCurrentRecord.erase(qNextPrev.ConvertToInt());  // constant time
                        try {
                            if (fitsRegister) {
                                qNextPrev = lbcrypto::NextPrime(qNextPrev, cyclOrder);
                            }
                            else {
                                qNextPrev = lbcrypto::PreviousPrime(qNextPrev, cyclOrder);
                            }
                        }
                        catch (const OpenFHEException& ex) {
                            OPENFHE_THROW(compositeScalingErrMsg);
                        }
                        if (std::log2(qNextPrev.ConvertToDouble()) > registerWordSize) {
                            fitsRegister = false;
                        }
                    } while (std::log2(qNextPrev.ConvertToDouble()) > registerWordSize ||
                             moduliQRecord.find(qNextPrev.ConvertToInt()) != moduliQRecord.end() ||
                             qCurrentRecord.find(qNextPrev.ConvertToInt()) != qCurrentRecord.end());
                    qCurrentRecord.emplace(qNextPrev.ConvertToInt());

                    primeProduct /= qPrev[qPrev.size() - 1].ConvertToDouble();
                    qPrev[qPrev.size() - 1] = qNextPrev;
                    primeProduct *= qNextPrev.ConvertToDouble();
                }

                uint32_t m = qPrev.size();
                for (uint32_t d = 1; d <= m; ++d) {
                    moduliQ[i - d] = qPrev[d - 1];
                }
                for (uint32_t d = m + 1; d <= compositeDegree; ++d) {
                    moduliQ[i - d] = qNext[d - (m + 1)];
                }

                for (uint32_t d = 1; d <= compositeDegree; ++d) {
                    rootsQ[i - d] = RootOfUnity(cyclOrder, moduliQ[i - d]);
                    moduliQRecord.emplace(moduliQ[i - d].ConvertToInt());
                }

                flag = false;
            }
        }  // for loop
    }      // if numPrimes > 1

    for (uint32_t d = 1, remBits = firstModSize; d <= compositeDegree; ++d) {
        uint32_t qBitSize = std::ceil(static_cast<double>(remBits) / (compositeDegree - d + 1));
        try {
            // Find next prime
            NativeInteger nextInteger = FirstPrime<NativeInteger>(qBitSize, cyclOrder);
            nextInteger               = PreviousPrime<NativeInteger>(nextInteger, cyclOrder);

            while (std::log2(nextInteger.ConvertToDouble()) > qBitSize ||
                   std::log2(nextInteger.ConvertToDouble()) > registerWordSize ||
                   moduliQRecord.find(nextInteger.ConvertToInt()) != moduliQRecord.end())
                nextInteger = PreviousPrime<NativeInteger>(nextInteger, cyclOrder);

            // Store prime
            moduliQ[d - 1] = nextInteger;
            rootsQ[d - 1]  = RootOfUnity(cyclOrder, moduliQ[d - 1]);
            // Keep track of existing primes
            moduliQRecord.emplace(moduliQ[d - 1].ConvertToInt());
            remBits -= qBitSize;
        }
        catch (const OpenFHEException& ex) {
            OPENFHE_THROW(compositeScalingErrMsg);
        }
    }

    return;
}

void ParameterGenerationCKKSRNS::SinglePrimeModuliGen(std::vector<NativeInteger>& moduliQ,
                                                      std::vector<NativeInteger>& rootsQ, ScalingTechnique scalTech,
                                                      uint32_t numPrimes, uint32_t firstModSize, uint32_t dcrtBits,
                                                      uint32_t cyclOrder, uint32_t extraModSize) const {
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
                sf                  = pow(sf, 2) / moduliQ[i + 1].ConvertToDouble();
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
}

}  // namespace lbcrypto
