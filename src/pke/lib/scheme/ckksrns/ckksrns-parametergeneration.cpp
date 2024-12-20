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

    // Determine appropriate composite degree automatically if scaling technique set to COMPOSITESCALINGAUTO
    cryptoParamsCKKSRNS->ConfigureCompositeDegree(firstModSize);
    uint32_t compositeDegree  = cryptoParamsCKKSRNS->GetCompositeDegree();
    uint32_t registerWordSize = cryptoParamsCKKSRNS->GetRegisterWordSize();

    if (scalTech == COMPOSITESCALINGAUTO || scalTech == COMPOSITESCALINGMANUAL) {
        // if (compositeDegree > 2 && (firstModSize <= 68 || scalingModSize <= 67)) {
        //     OPENFHE_THROW(
        //         config_error,
        //         "This COMPOSITESCALING* version does not fully support composite degree > 2 for small prime moduli. Prime moduli size must generally be greater than 22.");
        // }
        // else
        if (compositeDegree == 1 && registerWordSize < 32) {
            OPENFHE_THROW(config_error, "This COMPOSITESCALING* version does not support composite degree == 1.");
        }
        else if (compositeDegree < 1) {
            OPENFHE_THROW(config_error, "Composite degree must be greater than or equal to 1.");
        }

        if (registerWordSize < 24 && scalTech == COMPOSITESCALINGAUTO) {
            OPENFHE_THROW(
                config_error,
                "Register word size must be greater than or equal to 24 for COMPOSITESCALINGAUTO. Otherwise, try it with COMPOSITESCALINGMANUAL.");
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
    uint32_t auxBits       = (scalTech == COMPOSITESCALINGAUTO || scalTech == COMPOSITESCALINGMANUAL) ? 30 : AUXMODSIZE;
    uint32_t n             = cyclOrder / 2;
    uint32_t qBound        = firstModSize + (numPrimes - 1) * scalingModSize + extraModSize;

    // we add an extra bit to account for the alternating logic of selecting the RNS moduli in CKKS
    // ignore the case when there is only one max size modulus
    if (qBound != auxBits)
        qBound++;

    // Estimate ciphertext modulus Q*P bound (in case of HYBRID P*Q)
    if (ksTech == HYBRID) {
        auto hybridKSInfo = CryptoParametersRNS::EstimateLogP(numPartQ, firstModSize, scalingModSize, extraModSize,
                                                              numPrimes, auxBits, scalTech, compositeDegree, true);
        if (scalTech == COMPOSITESCALINGAUTO || scalTech == COMPOSITESCALINGMANUAL) {
            uint32_t tmpFactor = (compositeDegree == 2) ? 2 : 4;
            qBound += ceil(ceil(static_cast<double>(qBound) / numPartQ) / (tmpFactor * auxBits)) * tmpFactor * auxBits;
        }
        else {
            qBound += std::get<0>(hybridKSInfo);
        }
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

    if (scalTech == COMPOSITESCALINGAUTO || scalTech == COMPOSITESCALINGMANUAL) {
        numPrimes *= compositeDegree;
        std::cout << __FUNCTION__ << "::" << __LINE__ << " numPrimes: " << numPrimes << " qBound: " << qBound
                  << std::endl;
    }

    uint32_t vecSize = (extraModSize == 0) ? numPrimes : numPrimes + 1;
    std::vector<NativeInteger> moduliQ(vecSize);
    std::vector<NativeInteger> rootsQ(vecSize);

    if (scalTech == COMPOSITESCALINGAUTO || scalTech == COMPOSITESCALINGMANUAL) {
        if (compositeDegree > 1) {
            CompositePrimeModuliGen(moduliQ, rootsQ, compositeDegree, numPrimes, firstModSize, dcrtBits, cyclOrder,
                                    registerWordSize);
        }
        else {
            SinglePrimeModuliGen(moduliQ, rootsQ, scalTech, numPrimes, firstModSize, dcrtBits, cyclOrder, extraModSize);
        }
    }
    else {
        SinglePrimeModuliGen(moduliQ, rootsQ, scalTech, numPrimes, firstModSize, dcrtBits, cyclOrder, extraModSize);
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

void ParameterGenerationCKKSRNS::CompositePrimeModuliGen(std::vector<NativeInteger>& moduliQ,
                                                         std::vector<NativeInteger>& rootsQ, usint compositeDegree,
                                                         usint numPrimes, usint firstModSize, usint dcrtBits,
                                                         usint cyclOrder, usint registerWordSize) const {
    std::unordered_set<uint64_t> moduliQRecord;

    std::cout << __FUNCTION__ << "::" << __LINE__ << " numPrimes=" << numPrimes
              << " compositeDegree=" << compositeDegree << std::endl;

    // Sample q0, the first primes in the modulus chain
    NativeInteger q;
    uint32_t qBitSize = static_cast<double>(dcrtBits) / compositeDegree;
    uint32_t remBits  = dcrtBits;

    for (uint32_t d = 1; d <= compositeDegree; ++d) {
        // qBitSize = static_cast<uint32_t>(std::ceil(static_cast<double>(remBits) / (compositeDegree - d + 1)));
        double numBits = static_cast<double>(remBits) / (compositeDegree - d + 1);
        qBitSize       = std::ceil(numBits);
        q              = FirstPrime<NativeInteger>(qBitSize, cyclOrder);
        q              = PreviousPrime<NativeInteger>(q, cyclOrder);
        while (std::log2(q.ConvertToDouble()) > registerWordSize || std::log2(q.ConvertToDouble()) > numBits ||
               moduliQRecord.find(q.ConvertToInt()) != moduliQRecord.end()) {
            q = PreviousPrime<NativeInteger>(q, cyclOrder);
        }
        std::cout << __FUNCTION__ << "::" << __LINE__ << " d=" << d << " moduliQ=" << q
                  << " logq2=" << std::log2(q.ConvertToDouble()) << " remBits=" << remBits << "\n";
        std::cout << __FUNCTION__ << "::" << __LINE__ << " d=" << d << " moduliQ=" << q
                  << " logq2=" << std::log2(q.ConvertToDouble()) << "\n";
        moduliQ[numPrimes - d] = q;
        rootsQ[numPrimes - d]  = RootOfUnity(cyclOrder, moduliQ[numPrimes - d]);
        moduliQRecord.emplace(q.ConvertToInt());
        remBits -= qBitSize;
        //        remBits -= std::ceil(std::log2(q.ConvertToDouble()));
    }

#ifdef DEBUG_COMPOSITE_SCALING
    std::cout << __FUNCTION__ << "::" << __LINE__ << " numPrimes=" << numPrimes
              << " compositeDegree=" << compositeDegree << std::endl;
#endif

    // std::vector<NativeInteger> qPrev(std::ceil(static_cast<double>(compositeDegree) / 2));
    // std::vector<NativeInteger> qNext(compositeDegree - (uint32_t)qPrev.size());
    std::vector<NativeInteger> qPrev(1);
    std::vector<NativeInteger> innerPrimes((compositeDegree > 2) ? compositeDegree - 2 : 1);
    std::vector<NativeInteger> qNext(1);
    bool altPrevNext = false;

    if (numPrimes > 1) {
        // Prep to compute initial scaling factor
        double sf = moduliQ[numPrimes - 1].ConvertToDouble();
        for (uint32_t d = 2; d <= compositeDegree; ++d) {
            sf *= moduliQ[numPrimes - d].ConvertToDouble();
            std::cout << __FUNCTION__ << "::" << __LINE__ << " d=" << d << " moduliQ=" << q
                      << " logq2=" << std::log2(q.ConvertToDouble()) << " sf=" << sf << "\n";
        }

        std::cout << "Composite degree: " << compositeDegree << std::endl;

        uint32_t cnt = 1;
        for (usint i = numPrimes - compositeDegree; i >= 2 * compositeDegree; i -= compositeDegree) {
            std::cout << "Selecting Prime Moduli for L=" << i / compositeDegree << std::endl;
            // Compute initial scaling factor
            sf = static_cast<double>(std::pow(sf, 2));
            for (usint d = 0; d < compositeDegree; ++d) {
                std::cout << "moduliQ[" << i + d << "] = " << moduliQ[i + d] << ", ";
                sf /= moduliQ[i + d].ConvertToDouble();
            }
            std::cout << std::endl;

            // denom = moduliQ[i].ConvertToDouble();
            // for (usint d = 1; d < compositeDegree; ++d) {
            //     denom *= moduliQ[i + d].ConvertToDouble();
            // }

            auto sf_sqrt = std::pow(sf, 1.0 / compositeDegree);
            // auto sf_sqrt = std::pow((sf * sf) / denom, 1.0 / compositeDegree);  // std::sqrt((sf * sf) / denom);
            std::cout << __FUNCTION__ << "::" << __LINE__ << " i=" << i << " sf_sqrt=" << sf_sqrt
                      << " logsf_sqrt2=" << std::ceil(std::log2(sf_sqrt)) << " sf=" << sf << "\n";

            qBitSize = std::ceil(std::log2(sf_sqrt));

            NativeInteger sfInt = std::llround(sf_sqrt);
            NativeInteger sfRem = sfInt.Mod(cyclOrder);

#ifdef DEBUG_COMPOSITE_SCALING
            std::cout << __FUNCTION__ << "::" << __LINE__ << " i=" << i << " sfInt=" << sfInt
                      << " logq2=" << std::log2(sfInt.ConvertToDouble()) << "\n";
#endif
            double primeProduct = 1.0;
            std::unordered_set<uint64_t> qCurrentRecord;  // current prime tracker

            // for (uint32_t step = 0; step < (uint32_t)qPrev.size(); ++step) {
            //     //qPrev[step] = sfInt - (NativeInteger(step + 1) * NativeInteger(cyclOrder)) - sfRem + NativeInteger(1);
            //     qPrev[step] = sfInt - sfRem + NativeInteger(1) - NativeInteger(cyclOrder);
            //     do {
            //         // if (step % 2 == 0) {
            //         //     qPrev[step] = lbcrypto::PreviousPrime(qPrev[step], cyclOrder);
            //         // } else {
            //         //     qPrev[step] = lbcrypto::NextPrime(qPrev[step], cyclOrder);
            //         // }
            //         qPrev[step] = lbcrypto::PreviousPrime(qPrev[step], cyclOrder);
            //     } while (//std::log2(qPrev[step].ConvertToDouble()) > qBitSize ||
            //              std::log2(qPrev[step].ConvertToDouble()) > registerWordSize ||
            //              moduliQRecord.find(qPrev[step].ConvertToInt()) != moduliQRecord.end() ||
            //              qCurrentRecord.find(qPrev[step].ConvertToInt()) != qCurrentRecord.end());
            //     qCurrentRecord.emplace(qPrev[step].ConvertToInt());
            //     primeProduct *= qPrev[step].ConvertToDouble();
            //     // sfInt = qPrev[step];
            //     // sfRem = sfInt.Mod(cyclOrder);
            // }

            for (uint32_t step = 0; step < compositeDegree - 2; step++) {
                std::cout << "step: " << step << std::endl;
                // innerPrimes[step] = sfInt - (NativeInteger(step + 1) * NativeInteger(cyclOrder)) - sfRem + NativeInteger(1);
                // innerPrimes[step] = sfInt - sfRem + NativeInteger(1);
                if (altPrevNext) {
                    innerPrimes[step] = sfInt - sfRem + NativeInteger(1) - NativeInteger(cyclOrder);
                    // innerPrimes[step] = lbcrypto::PreviousPrime(innerPrimes[step], cyclOrder);
                }
                else {
                    innerPrimes[step] = sfInt - sfRem + NativeInteger(1) + NativeInteger(cyclOrder);
                    // innerPrimes[step] = lbcrypto::NextPrime(innerPrimes[step], cyclOrder);
                }
                do {
                    switch (altPrevNext) {
                        case true:
                            innerPrimes[step] = lbcrypto::PreviousPrime(innerPrimes[step], cyclOrder);
                            break;
                        default:
                            innerPrimes[step] = lbcrypto::NextPrime(innerPrimes[step], cyclOrder);
                            break;
                    }
                } while (std::log2(innerPrimes[step].ConvertToDouble()) > registerWordSize ||
                         moduliQRecord.find(innerPrimes[step].ConvertToInt()) != moduliQRecord.end() ||
                         qCurrentRecord.find(innerPrimes[step].ConvertToInt()) != qCurrentRecord.end());
                qCurrentRecord.emplace(innerPrimes[step].ConvertToInt());
                primeProduct *= innerPrimes[step].ConvertToDouble();

                altPrevNext = !altPrevNext;

                sfInt = innerPrimes[step];
                sfRem = sfInt.Mod(cyclOrder);
            }

            qPrev[0] = sfInt - sfRem + NativeInteger(1) - NativeInteger(cyclOrder);
            do {
                qPrev[0] = lbcrypto::PreviousPrime(qPrev[0], cyclOrder);
            } while (std::log2(qPrev[0].ConvertToDouble()) > registerWordSize ||
                     moduliQRecord.find(qPrev[0].ConvertToInt()) != moduliQRecord.end() ||
                     qCurrentRecord.find(qPrev[0].ConvertToInt()) != qCurrentRecord.end());
            qCurrentRecord.emplace(qPrev[0].ConvertToInt());
            primeProduct *= qPrev[0].ConvertToDouble();
            sfInt = qPrev[0];
            sfRem = sfInt.Mod(cyclOrder);

            qNext[0] = sfInt - sfRem + NativeInteger(1) + NativeInteger(cyclOrder);
            std::cout << "find last prime" << std::endl;
            do {
                std::cout << "qNext[0]: " << qNext[0] << std::endl;
                qNext[0] = lbcrypto::NextPrime(qNext[0], cyclOrder);
            } while (std::log2(qNext[0].ConvertToDouble()) > registerWordSize ||
                     moduliQRecord.find(qNext[0].ConvertToInt()) != moduliQRecord.end() ||
                     qCurrentRecord.find(qNext[0].ConvertToInt()) != qCurrentRecord.end());
            qCurrentRecord.emplace(qNext[0].ConvertToInt());
            primeProduct *= qNext[0].ConvertToDouble();
            sfInt = qNext[0];
            sfRem = sfInt.Mod(cyclOrder);

            // for (uint32_t step = 0; step < (uint32_t)qNext.size(); ++step) {
            //     // qNext[step] = sfInt + (NativeInteger(step + 1) * NativeInteger(cyclOrder)) - sfRem + NativeInteger(1);
            //     qNext[step] = sfInt - sfRem + NativeInteger(1) + NativeInteger(cyclOrder);
            //     // qBitSize = std::ceil(std::log2(qNext[step].ConvertToDouble()));
            //     // qNext[step]        = FirstPrime<NativeInteger>(qBitSize, cyclOrder);
            //     // qNext[step]        = NextPrime<NativeInteger>(q, cyclOrder);
            //     do {
            //         // if (step % 2) {
            //         //     qNext[step] = lbcrypto::NextPrime(qNext[step], cyclOrder);
            //         // } else {
            //         //     qNext[step] = lbcrypto::PreviousPrime(qNext[step], cyclOrder);
            //         // }
            //         qNext[step] = lbcrypto::NextPrime(qNext[step], cyclOrder);
            //     } while (//std::log2(qNext[step].ConvertToDouble()) > qBitSize ||
            //              std::log2(qNext[step].ConvertToDouble()) > registerWordSize ||
            //              moduliQRecord.find(qNext[step].ConvertToInt()) != moduliQRecord.end() ||
            //              qCurrentRecord.find(qNext[step].ConvertToInt()) != qCurrentRecord.end());
            //     qCurrentRecord.emplace(qNext[step].ConvertToInt());
            //     primeProduct *= qNext[step].ConvertToDouble();
            //     // sfInt = qNext[step];
            //     // sfRem = sfInt.Mod(cyclOrder);
            // }

#ifdef DEBUG_COMPOSITE_SCALING
            std::cout << __FUNCTION__ << "::" << __LINE__ << " i=" << i << " primeProduct=" << primeProduct
                      << " sf=" << sf << "\n";
#endif

            if (cnt == 0) {
                // NativeInteger qPrevNext = NativeInteger(qNext[qNext.size() - 1].ConvertToInt());
                NativeInteger qPrevNext = NativeInteger(qNext[0].ConvertToInt());
#ifdef DEBUG_COMPOSITE_SCALING
                std::cout << __FUNCTION__ << "::" << __LINE__ << " i=" << i << " qPrevPrev=" << qPrevPrev << "\n";
#endif
                while (primeProduct > sf) {
                    // while (primeProduct > sf0) {
                    do {
                        qCurrentRecord.erase(qPrevNext.ConvertToInt());  // constant time
                        qPrevNext = lbcrypto::PreviousPrime(qPrevNext, cyclOrder);
                    } while (  // std::log2(qPrevNext.ConvertToDouble()) > qBitSize ||
                        std::log2(qPrevNext.ConvertToDouble()) > registerWordSize ||
                        moduliQRecord.find(qPrevNext.ConvertToInt()) != moduliQRecord.end() ||
                        qCurrentRecord.find(qPrevNext.ConvertToInt()) != qCurrentRecord.end());
                    qCurrentRecord.emplace(qPrevNext.ConvertToInt());

#ifdef DEBUG_COMPOSITE_SCALING
                    std::cout << __FUNCTION__ << "::" << __LINE__ << " i=" << i << " primeFound=" << qPrevPrev
                              << " primeProduct=" << primeProduct << " sf=" << sf << "\n";
#endif

                    //    primeProduct /= qNext[qNext.size() - 1].ConvertToDouble();
                    //    qNext[qNext.size() - 1] = qPrevNext;
                    primeProduct /= qNext[0].ConvertToDouble();
                    qNext[0] = qPrevNext;
                    primeProduct *= qPrevNext.ConvertToDouble();

                    if (std::log2(primeProduct) > std::log2(sf)) {
                        std::cout << "************* VIOLATION ************* cnt: " << cnt << std::endl;
                        std::cout << "primeProduct " << (numPrimes - i) / compositeDegree << ": " << primeProduct
                                  << " > sf: " << sf << " log2(primeProduct): " << std::log2(primeProduct)
                                  << " log2(sf): " << std::log2(sf) << std::endl;
                    }

#ifdef DEBUG_COMPOSITE_SCALING
                    std::cout << __FUNCTION__ << "::" << __LINE__ << " i=" << i << " qPrevPrev" << qPrevPrev
                              << " logq2=" << std::log2(qPrevPrev.ConvertToDouble()) << " primeProduct=" << primeProduct
                              << " sf=" << sf << "\n";
#endif
                }

                moduliQ[i - 1] = qPrev[0];
                for (uint32_t d = 2; d < compositeDegree; ++d) {
                    moduliQ[i - d] = innerPrimes[d - 2];
                }
                moduliQ[i - compositeDegree] = qNext[0];

                // uint32_t m = qPrev.size();
                // for (uint32_t d = 1; d <= m; ++d) {
                //     moduliQ[i - d] = qPrev[d - 1];
                // }
                // for (uint32_t d = m+1; d <= compositeDegree; ++d) {
                //     moduliQ[i - d] = qNext[d - (m+1)];
                // }

                for (uint32_t d = 1; d <= compositeDegree; ++d) {
                    std::cout << __FUNCTION__ << "::" << __LINE__ << " i: " << i << " moduliQ: " << moduliQ[i - d]
                              << " logq2: " << std::log2(moduliQ[i - d].ConvertToDouble()) << "\n";
                    rootsQ[i - d] = RootOfUnity(cyclOrder, moduliQ[i - d]);
                    moduliQRecord.emplace(moduliQ[i - d].ConvertToInt());
                }

                // //#ifdef DEBUG_COMPOSITE_SCALING
                //                     std::cout << __FUNCTION__ << "::" << __LINE__ << " i=" << i << " moduliQ=" << moduliQ[i - d]
                //                               << " logq2=" << std::log2(moduliQ[i - d].ConvertToDouble()) << "\n";
                // //#endif
                //                     rootsQ[i - d] = RootOfUnity(cyclOrder, moduliQ[i - d]);
                //                     moduliQRecord.emplace(moduliQ[i - d].ConvertToInt());
                //                 }
                cnt = 1;
            }
            else {
                // NativeInteger qNextPrev = NativeInteger(qPrev[qPrev.size()-1].ConvertToInt());
                NativeInteger qNextPrev = NativeInteger(qPrev[0].ConvertToInt());
#ifdef DEBUG_COMPOSITE_SCALING
                std::cout << __FUNCTION__ << "::" << __LINE__ << " i=" << i << " qNextNext=" << qNextNext << "\n";
#endif
                while (primeProduct < sf) {
                    // while (primeProduct < sf0) {
                    do {
                        qCurrentRecord.erase(qNextPrev.ConvertToInt());  // constant time
                        qNextPrev = lbcrypto::NextPrime(qNextPrev, cyclOrder);
                    } while (  // std::log2(qNextPrev.ConvertToDouble()) > qBitSize ||
                        std::log2(qNextPrev.ConvertToDouble()) > registerWordSize ||
                        moduliQRecord.find(qNextPrev.ConvertToInt()) != moduliQRecord.end() ||
                        qCurrentRecord.find(qNextPrev.ConvertToInt()) != qCurrentRecord.end());
                    qCurrentRecord.emplace(qNextPrev.ConvertToInt());

#ifdef DEBUG_COMPOSITE_SCALING
                    std::cout << __FUNCTION__ << "::" << __LINE__ << " i=" << i << " primeFound=" << qNextNext
                              << " primeProduct=" << primeProduct << " sf=" << sf << "\n";
#endif
                    // primeProduct /= qPrev[qPrev.size()-1].ConvertToDouble();
                    // qPrev[qPrev.size()-1] = qNextPrev;
                    primeProduct /= qPrev[0].ConvertToDouble();
                    qPrev[0] = qNextPrev;
                    primeProduct *= qNextPrev.ConvertToDouble();

                    if (std::log2(primeProduct) > std::log2(sf)) {
                        std::cout << "************* VIOLATION ************* cnt: " << cnt << std::endl;
                        std::cout << "primeProduct " << (numPrimes - i) / compositeDegree << ": " << primeProduct
                                  << " > sf: " << sf << " log2(primeProduct): " << std::log2(primeProduct)
                                  << " log2(sf): " << std::log2(sf) << std::endl;
                    }

#ifdef DEBUG_COMPOSITE_SCALING
                    std::cout << __FUNCTION__ << "::" << __LINE__ << " i=" << i << " qNextNext" << qNextNext
                              << " logq2=" << std::log2(qNextNext.ConvertToDouble()) << " primeProduct=" << primeProduct
                              << " sf=" << sf << "\n";
#endif
                }

                // assgin samples prime moduli to the chain
                moduliQ[i - 1] = qPrev[0];
                for (uint32_t d = 2; d < compositeDegree; ++d) {
                    moduliQ[i - d] = innerPrimes[d - 2];
                }
                moduliQ[i - compositeDegree] = qNext[0];

                // uint32_t m = qPrev.size();
                // for (uint32_t d = 1; d <= m; ++d) {
                //     moduliQ[i - d] = qPrev[d - 1];
                // }
                // for (uint32_t d = m+1; d <= compositeDegree; ++d) {
                //     moduliQ[i - d] = qNext[d - (m+1)];
                // }

                for (uint32_t d = 1; d <= compositeDegree; ++d) {
                    std::cout << __FUNCTION__ << "::" << __LINE__ << " i: " << i << " moduliQ: " << moduliQ[i - d]
                              << " logq2: " << std::log2(moduliQ[i - d].ConvertToDouble()) << "\n";
                    rootsQ[i - d] = RootOfUnity(cyclOrder, moduliQ[i - d]);
                    moduliQRecord.emplace(moduliQ[i - d].ConvertToInt());
                }

                cnt = 0;
            }
        }  // for loop
    }  // if numPrimes > 1

    if (firstModSize == dcrtBits) {  // this requires dcrtBits < 60
        OPENFHE_THROW(config_error, "firstModSize must be > scalingModSize.");
    }
    else {
        qBitSize = 0;
        remBits  = static_cast<uint32_t>(firstModSize);
        for (uint32_t d = 1; d <= compositeDegree; ++d) {
            qBitSize = std::ceil(static_cast<double>(remBits) / (compositeDegree - d + 1));
            // Find next prime
            NativeInteger nextInteger = FirstPrime<NativeInteger>(qBitSize, cyclOrder);
            nextInteger               = PreviousPrime<NativeInteger>(nextInteger, cyclOrder);
            // nextInteger               = NextPrime<NativeInteger>(nextInteger, cyclOrder);
            // Ensure it fits in 32-bit register
            while (std::log2(nextInteger.ConvertToDouble()) > qBitSize ||
                   std::log2(nextInteger.ConvertToDouble()) > registerWordSize ||
                   moduliQRecord.find(nextInteger.ConvertToInt()) != moduliQRecord.end())
                nextInteger = PreviousPrime<NativeInteger>(nextInteger, cyclOrder);
            // nextInteger = NextPrime<NativeInteger>(nextInteger, cyclOrder);
            // Store prime
            moduliQ[d - 1] = nextInteger;
            rootsQ[d - 1]  = RootOfUnity(cyclOrder, moduliQ[d - 1]);
            // Keep track of existing primes
            moduliQRecord.emplace(moduliQ[d - 1].ConvertToInt());
            remBits -= qBitSize;
            // #ifdef DEBUG_COMPOSITE_SCALING
            std::cout << __FUNCTION__ << "::" << __LINE__ << " i=" << 1 << " moduliQ=" << moduliQ[d - 1]
                      << " logq2=" << std::log2(moduliQ[d - 1].ConvertToDouble()) << "\n";
            // #endif
        }
    }

#ifdef DEBUG_COMPOSITE_SCALING
    std::cout << __FUNCTION__ << "::" << __LINE__ << " prime moduli:" << std::endl;
    for (size_t i = 0; i < moduliQ.size(); i++) {
        std::cout << "moduliQ[" << i << "]=" << moduliQ[i] << " logq[" << i
                  << "]=" << std::log2(moduliQ[i].ConvertToDouble()) << std::endl;
    }
#endif

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
}

}  // namespace lbcrypto
