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
BGV implementation. See https://eprint.iacr.org/2021/204 for details.
 */

#define PROFILE

#include "cryptocontext.h"
#include "scheme/bgvrns/bgvrns-cryptoparameters.h"
#include "scheme/bgvrns/bgvrns-parametergeneration.h"

namespace lbcrypto {

uint32_t ParameterGenerationBGVRNS::computeRingDimension(std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams,
                                                         uint32_t qBound, usint cyclOrder) const {
    const auto cryptoParamsBGVRNS = std::dynamic_pointer_cast<CryptoParametersBGVRNS>(cryptoParams);
    //// HE Standards compliance logic/check
    SecurityLevel stdLevel = cryptoParamsBGVRNS->GetStdLevel();

    uint32_t ringDimension = cyclOrder / 2;

    // GAUSSIAN security constraint
    DistributionType distType = (cryptoParamsBGVRNS->GetSecretKeyDist() == GAUSSIAN) ? HEStd_error : HEStd_ternary;
    auto nRLWE                = [&](usint q) -> uint32_t {
        return StdLatticeParm::FindRingDim(distType, stdLevel, q);
    };

    // Case 1: SecurityLevel specified as HEStd_NotSet -> Do nothing
    if (stdLevel != HEStd_NotSet) {
        if (ringDimension == 0) {
            // Case 2: SecurityLevel specified, but ring dimension not specified
            // Choose ring dimension based on security standards
            ringDimension = nRLWE(qBound);
        }
        else {
            // Case 3: Both SecurityLevel and ring dimension specified
            // Check whether particular selection is standards-compliant
            auto he_std_n = nRLWE(qBound);
            if (he_std_n > ringDimension) {
                OPENFHE_THROW(math_error, "The specified ring dimension (" + std::to_string(ringDimension) +
                                              ") does not comply with HE standards recommendation (" +
                                              std::to_string(he_std_n) + ").");
            }
        }
    }
    else if (ringDimension == 0) {
        OPENFHE_THROW(math_error, "Please specify the ring dimension or desired security level.");
    }
    return ringDimension;
}

BGVNoiseEstimates ParameterGenerationBGVRNS::computeNoiseEstimates(
    std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams, uint32_t ringDimension, uint32_t evalAddCount,
    uint32_t keySwitchCount, uint32_t auxBits, usint numPrimes) const {
    const auto cryptoParamsBGVRNS = std::dynamic_pointer_cast<CryptoParametersBGVRNS>(cryptoParams);
    usint digitSize               = cryptoParamsBGVRNS->GetDigitSize();
    KeySwitchTechnique ksTech     = cryptoParamsBGVRNS->GetKeySwitchTechnique();
    ScalingTechnique scalTech     = cryptoParamsBGVRNS->GetScalingTechnique();
    double sigma                  = cryptoParamsBGVRNS->GetDistributionParameter();
    double alpha                  = cryptoParamsBGVRNS->GetAssuranceMeasure();

    // Bound of the Gaussian error polynomial
    double Berr = sigma * sqrt(alpha);
    // Bound of the key polynomial
    // supports both discrete Gaussian (GAUSSIAN) and ternary uniform distribution
    // (UNIFORM_TERNARY) cases
    uint32_t thresholdParties = cryptoParamsBGVRNS->GetThresholdNumOfParties();

    // Bkey set to thresholdParties * 1 for ternary distribution
    double Bkey = (cryptoParamsBGVRNS->GetSecretKeyDist() == GAUSSIAN) ? sqrt(thresholdParties) * sigma * sqrt(alpha) :
                                                                         thresholdParties;

    // delta
    auto expansionFactor = 2. * sqrt(ringDimension);
    // Vnorm
    auto freshEncryptionNoise = Berr * (1. + 2. * expansionFactor * Bkey);

    double keySwitchingNoise = 0;
    if (ksTech == BV) {
        if (digitSize == 0) {
            OPENFHE_THROW(config_error,
                          "digitSize is not allowed to be 0 for BV key switching in BGV when scalingModSize = 0.");
        }
        int relinBase       = pow(2.0, digitSize);
        int modSizeEstimate = DCRT_MODULUS::MAX_SIZE;
        int numWindows      = floor(modSizeEstimate / log(relinBase)) + 1;
        keySwitchingNoise   = numWindows * numPrimes * expansionFactor * relinBase * Berr / 2.0;
    }
    else {
        double numTowersPerDigit = cryptoParamsBGVRNS->GetNumPerPartQ();
        int numDigits            = cryptoParamsBGVRNS->GetNumPartQ();
        keySwitchingNoise        = numTowersPerDigit * numDigits * expansionFactor * Berr / 2.0;
        keySwitchingNoise += auxBits * (1 + expansionFactor * Bkey) / 2.0;
    }

    // V_ms
    auto modSwitchingNoise = (1 + expansionFactor * Bkey) / 2.;

    // V_c
    double noisePerLevel = 0;
    if (scalTech == FLEXIBLEAUTOEXT) {
        noisePerLevel = 1 + expansionFactor * Bkey;
    }
    else {
        noisePerLevel = (evalAddCount + 1) * freshEncryptionNoise + (keySwitchCount + 1) * keySwitchingNoise;
    }

    return BGVNoiseEstimates(Berr, Bkey, expansionFactor, freshEncryptionNoise, keySwitchingNoise, modSwitchingNoise,
                             noisePerLevel);
}

uint64_t ParameterGenerationBGVRNS::getCyclicOrder(const uint32_t ringDimension, const int plainModulus,
                                                   const ScalingTechnique scalTech) const {
    // Moduli need to be primes that are 1 (mod 2n)
    usint cyclOrder          = 2 * ringDimension;
    uint64_t lcmCyclOrderPtm = 0;

    if (scalTech == FIXEDAUTO) {
        // In FIXEDAUTO, moduli also need to be 1 (mod t)
        usint plaintextModulus = plainModulus;
        usint pow2ptm          = 1;  // The largest power of 2 dividing ptm (check whether it
                                     // is larger than cyclOrder or not)
        while (plaintextModulus % 2 == 0) {
            plaintextModulus >>= 1;
            pow2ptm <<= 1;
        }

        if (pow2ptm < cyclOrder)
            pow2ptm = cyclOrder;

        lcmCyclOrderPtm = (uint64_t)pow2ptm * plaintextModulus;
    }
    else {
        lcmCyclOrderPtm = cyclOrder;
    }
    return lcmCyclOrderPtm;
}

std::pair<std::vector<NativeInteger>, uint32_t> ParameterGenerationBGVRNS::computeModuli(
    std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams, uint32_t ringDimension, uint32_t evalAddCount,
    uint32_t keySwitchCount, uint32_t auxBits, usint numPrimes) const {
    if (numPrimes < 1) {
        OPENFHE_THROW(config_error, "numPrimes must be at least 1");
    }

    const auto cryptoParamsBGVRNS = std::dynamic_pointer_cast<CryptoParametersBGVRNS>(cryptoParams);
    ScalingTechnique scalTech     = cryptoParamsBGVRNS->GetScalingTechnique();

    size_t numModuli = scalTech == FLEXIBLEAUTOEXT ? numPrimes + 1 : numPrimes;
    std::vector<NativeInteger> moduliQ(numModuli);

    uint64_t plainModulus         = cryptoParamsBGVRNS->GetPlaintextModulus();
    NativeInteger plainModulusInt = NativeInteger(plainModulus);

    BGVNoiseEstimates noiseEstimates =
        computeNoiseEstimates(cryptoParams, ringDimension, evalAddCount, keySwitchCount, auxBits, numPrimes);
    uint64_t cyclOrder = getCyclicOrder(ringDimension, plainModulus, scalTech);

    double firstModLowerBound = 0;
    if (scalTech == FLEXIBLEAUTOEXT)
        firstModLowerBound = 2.0 * plainModulus * noiseEstimates.freshEncryptionNoise - plainModulus;
    else
        firstModLowerBound = 2.0 * plainModulus * noiseEstimates.noisePerLevel - plainModulus;
    usint firstModSize = ceil(log2(firstModLowerBound));
    if (firstModSize >= DCRT_MODULUS::MAX_SIZE) {
        OPENFHE_THROW(
            config_error,
            "Change parameters! Try reducing the number of additions per level, "
            "number of key switches per level, or the digit size. We cannot support moduli greater than 60 bits.");
    }

    moduliQ[0]            = FirstPrime<NativeInteger>(firstModSize, cyclOrder);

    if (scalTech == FLEXIBLEAUTOEXT) {
        double extraModLowerBound =
            noiseEstimates.freshEncryptionNoise / noiseEstimates.noisePerLevel * (evalAddCount + 1);
        extraModLowerBound += keySwitchCount * noiseEstimates.keySwitchingNoise / noiseEstimates.noisePerLevel;
        extraModLowerBound *= 2;
        usint extraModSize = ceil(log2(extraModLowerBound));

        if (extraModSize >= DCRT_MODULUS::MAX_SIZE) {
            OPENFHE_THROW(
                config_error,
                "Change parameters! Try reducing the number of additions per level, "
                "number of key switches per level, or the digit size. We cannot support moduli greater than 60 bits.");
        }

        moduliQ[numPrimes] = FirstPrime<NativeInteger>(extraModSize, cyclOrder);
        while (moduliQ[numPrimes] == moduliQ[0] || moduliQ[numPrimes] == plainModulusInt) {
            moduliQ[numPrimes] = NextPrime<NativeInteger>(moduliQ[numPrimes], cyclOrder);
        }
    }

    if (numPrimes > 1) {
        // Compute bounds.
        double modLowerBound = 0;
        if (scalTech == FLEXIBLEAUTOEXT) {
            modLowerBound = 2 * noiseEstimates.noisePerLevel + 2 + 1.0 / noiseEstimates.noisePerLevel;
            modLowerBound *= noiseEstimates.expansionFactor * plainModulus * (evalAddCount + 1) / 2.0;
            modLowerBound += (keySwitchCount + 1) * noiseEstimates.keySwitchingNoise / noiseEstimates.noisePerLevel;
            modLowerBound *= 2;
        }
        else {
            double modLowerBoundNumerator =
                2 * noiseEstimates.noisePerLevel * noiseEstimates.noisePerLevel + 2 * noiseEstimates.noisePerLevel + 1;
            modLowerBoundNumerator *= noiseEstimates.expansionFactor * plainModulus / 2. * (evalAddCount + 1);
            modLowerBoundNumerator += (keySwitchCount + 1) * noiseEstimates.keySwitchingNoise;
            double modLowerBoundDenom = noiseEstimates.noisePerLevel - noiseEstimates.modSwitchingNoise;
            modLowerBound             = modLowerBoundNumerator / modLowerBoundDenom;
        }

        usint modSize = ceil(log2(modLowerBound));
        if (modSize >= DCRT_MODULUS::MAX_SIZE) {
            OPENFHE_THROW(
                config_error,
                "Change parameters! Try reducing the number of additions per level, "
                "number of key switches per level, or the digit size. We cannot support moduli greater than 60 bits.");
        }

        // Compute moduli.
        moduliQ[1] = FirstPrime<NativeInteger>(modSize, cyclOrder);
        if (scalTech == FLEXIBLEAUTOEXT) {
            while (moduliQ[1] == moduliQ[0] || moduliQ[1] == moduliQ[numPrimes] || moduliQ[1] == plainModulusInt) {
                moduliQ[1] = NextPrime<NativeInteger>(moduliQ[1], cyclOrder);
            }

            for (size_t i = 2; i < numPrimes; i++) {
                moduliQ[i] = NextPrime<NativeInteger>(moduliQ[i - 1], cyclOrder);
                while (moduliQ[i] == moduliQ[0] || moduliQ[i] == moduliQ[numPrimes] || moduliQ[i] == plainModulusInt) {
                    moduliQ[i] = NextPrime<NativeInteger>(moduliQ[i], cyclOrder);
                }
            }
        }
        else {
            while (moduliQ[1] == moduliQ[0] || moduliQ[1] == plainModulusInt) {
                moduliQ[1] = NextPrime<NativeInteger>(moduliQ[1], cyclOrder);
            }

            for (size_t i = 2; i < numPrimes; i++) {
                moduliQ[i] = NextPrime<NativeInteger>(moduliQ[i - 1], cyclOrder);
                while (moduliQ[i] == moduliQ[0] || moduliQ[i] == plainModulusInt) {
                    moduliQ[i] = NextPrime<NativeInteger>(moduliQ[i], cyclOrder);
                }
            }
        }
    }

    BigInteger composite(1);
    for (BigInteger m : moduliQ)
        composite *= m;

    return std::make_pair(moduliQ, composite.GetMSB());
}

void ParameterGenerationBGVRNS::InitializeFloodingDgg(std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams,
                                                      usint numPrimes) const {
    const auto cryptoParamsBGVRNS = std::dynamic_pointer_cast<CryptoParametersBGVRNS>(cryptoParams);

    KeySwitchTechnique ksTech     = cryptoParamsBGVRNS->GetKeySwitchTechnique();
    ProxyReEncryptionMode PREMode = cryptoParamsBGVRNS->GetPREMode();

    // compute the flooding distribution parameter based on the security mode for pre
    // get the re-encryption level and set the level after re-encryption
    usint ringDimension       = cryptoParamsBGVRNS->GetElementParams()->GetRingDimension();
    double sigma              = cryptoParamsBGVRNS->GetDistributionParameter();
    double alpha              = cryptoParamsBGVRNS->GetAssuranceMeasure();
    usint r                   = cryptoParamsBGVRNS->GetDigitSize();
    double B_e                = sqrt(alpha) * sigma;
    uint32_t auxBits          = DCRT_MODULUS::MAX_SIZE;
    uint32_t thresholdParties = cryptoParamsBGVRNS->GetThresholdNumOfParties();
    // bound on the secret key is sigma*sqrt(alpha) if the secret is sampled from discrete gaussian distribution
    // and is 1 * threshold number of parties if the secret is sampled from ternary distribution. The threshold number of
    // parties is 1 by default but can be set to the number of parties in a threshold application.
    // Bkey set to thresholdParties * 1 for ternary distribution
    double Bkey = (cryptoParamsBGVRNS->GetSecretKeyDist() == GAUSSIAN) ? sigma * sqrt(alpha) : thresholdParties;

    double stat_sec_half = cryptoParamsBGVRNS->GetStatisticalSecurity() / 2;
    double num_queries   = cryptoParamsBGVRNS->GetNumAdversarialQueries();

    // get the flooding discrete gaussian distribution
    auto dggFlooding   = cryptoParamsBGVRNS->GetFloodingDiscreteGaussianGenerator();
    double noise_param = 1;
    if (PREMode == FIXED_NOISE_HRA) {
        noise_param = NOISE_FLOODING::PRE_SD;
    }
    else if (PREMode == NOISE_FLOODING_HRA) {
        if (ksTech == BV) {
            if (r > 0) {
                // sqrt(12*num_queries) factor required for security analysis
                noise_param = sqrt(12 * num_queries) * pow(2, stat_sec_half) * (1 + 2 * Bkey) * numPrimes *
                              (auxBits / r + 1) * sqrt(ringDimension) * (pow(2, r) - 1) * B_e;
            }
            else {
                OPENFHE_THROW(config_error, "Relinwindow value cannot be 0 for BV keyswitching");
            }
        }
        else if (ksTech == HYBRID) {
            if (r == 0) {
                double numTowersPerDigit = cryptoParamsBGVRNS->GetNumPerPartQ();
                int numDigits            = cryptoParamsBGVRNS->GetNumPartQ();
                noise_param              = numTowersPerDigit * numDigits * sqrt(ringDimension) * B_e * (1 + 2 * Bkey);
                noise_param += auxBits * (1 + sqrt(ringDimension) * Bkey);
                // sqrt(12*num_queries) factor required for security analysis
                noise_param = sqrt(12 * num_queries) * pow(2, stat_sec_half) * noise_param;
            }
            else {
                OPENFHE_THROW(config_error, "Relinwindow value can only  be zero for Hybrid keyswitching");
            }
        }
    }
    else if (PREMode == DIVIDE_AND_ROUND_HRA) {
        OPENFHE_THROW(config_error, "Noise Flooding not applicable for PRE DIVIDE_AND_ROUND_HRA mode");
    }
    // set the flooding distribution parameter to the distribution.
    dggFlooding.SetStd(noise_param);
    const auto cryptoParamsRNS = std::dynamic_pointer_cast<CryptoParametersRNS>(cryptoParams);
    cryptoParamsRNS->SetFloodingDistributionParameter(noise_param);
}

bool ParameterGenerationBGVRNS::ParamsGenBGVRNS(std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams,
                                                uint32_t evalAddCount, uint32_t keySwitchCount, usint cyclOrder,
                                                usint numPrimes, usint firstModSize, usint dcrtBits, uint32_t numPartQ,
                                                usint multihopQBound) const {
    const auto cryptoParamsBGVRNS = std::dynamic_pointer_cast<CryptoParametersBGVRNS>(cryptoParams);

    uint32_t ptm                     = cryptoParamsBGVRNS->GetPlaintextModulus();
    KeySwitchTechnique ksTech        = cryptoParamsBGVRNS->GetKeySwitchTechnique();
    ScalingTechnique scalTech        = cryptoParamsBGVRNS->GetScalingTechnique();
    EncryptionTechnique encTech      = cryptoParamsBGVRNS->GetEncryptionTechnique();
    MultiplicationTechnique multTech = cryptoParamsBGVRNS->GetMultiplicationTechnique();
    ProxyReEncryptionMode PREMode    = cryptoParamsBGVRNS->GetPREMode();
    MultipartyMode multipartyMode    = cryptoParamsBGVRNS->GetMultipartyMode();
    if (!ptm)
        OPENFHE_THROW(config_error, "plaintextModulus cannot be zero.");

    if ((PREMode != INDCPA) && (PREMode != FIXED_NOISE_HRA) && (PREMode != NOISE_FLOODING_HRA) &&
        (PREMode != NOT_SET)) {
        std::stringstream s;
        s << "This PRE mode " << PREMode << " is not supported for BGVRNS";
        OPENFHE_THROW(not_available_error, s.str());
    }

    bool dcrtBitsSet = (dcrtBits == 0) ? false : true;

    // Select the size of moduli according to the plaintext modulus
    if (dcrtBits == 0) {
        dcrtBits = 28 + GetMSB64(ptm);
        if (dcrtBits > DCRT_MODULUS::MAX_SIZE) {
            dcrtBits = DCRT_MODULUS::MAX_SIZE;
        }
    }

    // Select firstModSize to be dcrtBits if no indicated otherwise
    if (firstModSize == 0)
        firstModSize = dcrtBits;

    // Size of modulus P
    uint32_t auxBits = DCRT_MODULUS::MAX_SIZE;

    // Estimate ciphertext modulus Q bound (in case of GHS/HYBRID P*Q)
    usint extraModSize = (scalTech == FLEXIBLEAUTOEXT) ? DCRT_MODULUS::DEFAULT_EXTRA_MOD_SIZE : 0;
    uint32_t qBound    = firstModSize + (numPrimes - 1) * dcrtBits + extraModSize;
    if (ksTech == HYBRID)
        qBound += ceil(ceil(static_cast<double>(qBound) / numPartQ) / auxBits) * auxBits;

    // Note this code is not executed if multihopQBound == 0 so it is backwards
    // compatable
    if (qBound < multihopQBound) {
        // need to increase qBound to multihopQBound
        qBound = multihopQBound;

        // need to increase numPrimes to support new larger qBound
        numPrimes = static_cast<usint>((qBound - firstModSize) / static_cast<float>(dcrtBits) + 1);
    }

    uint32_t n = computeRingDimension(cryptoParams, qBound, cyclOrder);
    //// End HE Standards compliance logic/check

    uint32_t vecSize = (scalTech != FLEXIBLEAUTOEXT) ? numPrimes : numPrimes + 1;
    std::vector<NativeInteger> moduliQ(vecSize);
    std::vector<NativeInteger> rootsQ(vecSize);
    uint64_t modulusOrder = 0;

    if ((scalTech == FIXEDAUTO || scalTech == FLEXIBLEAUTO || scalTech == FLEXIBLEAUTOEXT) && (dcrtBitsSet == false)) {
        auto moduliInfo    = computeModuli(cryptoParams, n, evalAddCount, keySwitchCount, auxBits, numPrimes);
        moduliQ            = std::get<0>(moduliInfo);
        uint32_t newQBound = std::get<1>(moduliInfo);
        while (qBound < newQBound) {
            qBound          = newQBound;
            n               = computeRingDimension(cryptoParams, newQBound, cyclOrder);
            auto moduliInfo = computeModuli(cryptoParams, n, evalAddCount, keySwitchCount, auxBits, numPrimes);
            moduliQ         = std::get<0>(moduliInfo);
            newQBound       = std::get<1>(moduliInfo);
            if (ksTech == HYBRID)
                newQBound += ceil(ceil(static_cast<double>(newQBound) / numPartQ) / auxBits) * auxBits;
        }
        cyclOrder    = 2 * n;
        modulusOrder = getCyclicOrder(n, ptm, scalTech);

        for (size_t i = 0; i < vecSize; i++) {
            rootsQ[i] = RootOfUnity<NativeInteger>(cyclOrder, moduliQ[i]);
        }
    }
    else {
        cyclOrder = 2 * n;
        // For ModulusSwitching to work we need the moduli to be also congruent to 1
        // modulo ptm
        usint plaintextModulus = ptm;
        usint pow2ptm          = 1;  // The largest power of 2 dividing ptm (check whether it
                                     // is larger than cyclOrder or not)
        while (plaintextModulus % 2 == 0) {
            plaintextModulus >>= 1;
            pow2ptm <<= 1;
        }

        if (pow2ptm < cyclOrder)
            pow2ptm = cyclOrder;

        modulusOrder = (uint64_t)pow2ptm * plaintextModulus;

        // Get the largest prime with size less or equal to firstModSize bits.
        moduliQ[0] = LastPrime<NativeInteger>(firstModSize, modulusOrder);
        rootsQ[0]  = RootOfUnity<NativeInteger>(cyclOrder, moduliQ[0]);

        if (numPrimes > 1) {
            NativeInteger q =
                (firstModSize != dcrtBits) ? LastPrime<NativeInteger>(dcrtBits, modulusOrder) : moduliQ[0];

            moduliQ[1] = PreviousPrime<NativeInteger>(q, modulusOrder);
            rootsQ[1]  = RootOfUnity<NativeInteger>(cyclOrder, moduliQ[1]);

            for (size_t i = 2; i < numPrimes; i++) {
                moduliQ[i] = PreviousPrime<NativeInteger>(moduliQ[i - 1], modulusOrder);
                rootsQ[i]  = RootOfUnity<NativeInteger>(cyclOrder, moduliQ[i]);
            }
        }
    }
    if (multipartyMode == NOISE_FLOODING_MULTIPARTY) {
        NativeInteger extraModulus = LastPrime<NativeInteger>(NOISE_FLOODING::MULTIPARTY_MOD_SIZE, modulusOrder);
        std::vector<NativeInteger> extraModuli(NOISE_FLOODING::NUM_MODULI_MULTIPARTY);
        std::vector<NativeInteger> extraRoots(NOISE_FLOODING::NUM_MODULI_MULTIPARTY);

        for (size_t i = 0; i < NOISE_FLOODING::NUM_MODULI_MULTIPARTY; i++) {
            while (std::find(moduliQ.begin(), moduliQ.end(), extraModulus) != moduliQ.end() ||
                   std::find(extraModuli.begin(), extraModuli.end(), extraModulus) != extraModuli.end()) {
                extraModulus = PreviousPrime<NativeInteger>(extraModulus, modulusOrder);
            }
            extraModuli[i] = extraModulus;
            extraRoots[i]  = RootOfUnity<NativeInteger>(cyclOrder, extraModulus);
        }
        moduliQ.reserve(moduliQ.size() + extraModuli.size());
        rootsQ.reserve(rootsQ.size() + extraRoots.size());
        // We insert the extraModuli after the first modulus to improve security in multiparty decryption.
        moduliQ.insert(moduliQ.begin() + 1, std::make_move_iterator(extraModuli.begin()),
                       std::make_move_iterator(extraModuli.end()));
        rootsQ.insert(rootsQ.begin() + 1, std::make_move_iterator(extraRoots.begin()),
                      std::make_move_iterator(extraRoots.end()));
    }
    auto paramsDCRT = std::make_shared<ILDCRTParams<BigInteger>>(cyclOrder, moduliQ, rootsQ);

    ChineseRemainderTransformFTT<NativeVector>().PreCompute(rootsQ, cyclOrder, moduliQ);

    cryptoParamsBGVRNS->SetElementParams(paramsDCRT);

    const EncodingParams encodingParams = cryptoParamsBGVRNS->GetEncodingParams();
    if (encodingParams->GetBatchSize() > n)
        OPENFHE_THROW(config_error, "The batch size cannot be larger than the ring dimension.");

    if (encodingParams->GetBatchSize() & (encodingParams->GetBatchSize() - 1))
        OPENFHE_THROW(config_error, "The batch size can only be set to zero (for full packing) or a power of two.");

    // if no batch size was specified compute a default value
    if (encodingParams->GetBatchSize() == 0) {
        // Check whether ptm and cyclOrder are coprime
        usint a, b, gcd;
        if (cyclOrder > ptm) {
            a = cyclOrder;
            b = ptm;
        }
        else {
            b = cyclOrder;
            a = ptm;
        }

        gcd = b;
        while (b != 0) {
            gcd = b;
            b   = a % b;
            a   = gcd;
        }

        // if ptm and CyclOrder are not coprime we set batchSize = n by default (for
        // full packing)
        uint32_t batchSize;
        if (gcd != 1) {
            batchSize = n;
        }
        else {  // set batchsize to the actual batchsize i.e. n/d where d is the
            // order of ptm mod CyclOrder
            a = (uint64_t)ptm % cyclOrder;
            b = 1;
            while (a != 1) {
                a = ((uint64_t)(a * ptm)) % cyclOrder;
                b++;
            }

            if (n % b != 0)
                OPENFHE_THROW(math_error,
                              "BGVrns.ParamsGen: something went wrong when computing "
                              "the batchSize");

            batchSize = n / b;
        }

        EncodingParams encodingParamsNew(
            std::make_shared<EncodingParamsImpl>(encodingParams->GetPlaintextModulus(), batchSize));
        cryptoParamsBGVRNS->SetEncodingParams(encodingParamsNew);
    }
    cryptoParamsBGVRNS->PrecomputeCRTTables(ksTech, scalTech, encTech, multTech, numPartQ, auxBits, 0);
    InitializeFloodingDgg(cryptoParams, numPrimes);
    return true;
}

}  // namespace lbcrypto
