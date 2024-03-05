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

#ifndef LBCRYPTO_CRYPTO_RNS_PARAMETERGENERATION_H
#define LBCRYPTO_CRYPTO_RNS_PARAMETERGENERATION_H

#include "lattice/lat-hal.h"

#include "schemebase/base-parametergeneration.h"

#include <string>
#include <memory>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief Abstract interface for parameter generation algorithm
 * @tparam Element a ring element.
 */
class ParameterGenerationRNS : public ParameterGenerationBase<DCRTPoly> {
public:
    virtual ~ParameterGenerationRNS() {}

    /**
   * Method for computing all derived parameters based on chosen primitive
   * parameters
   *
   * @param *cryptoParams the crypto parameters object to be populated with
   * parameters.
   * @param evalAddCount number of EvalAdds assuming no EvalMult and KeySwitch
   * operations are performed.
   * @param multiplicativeDepth number of EvalMults assuming no EvalAdd and
   * KeySwitch operations are performed.
   * @param keySwitchCount number of KeySwitch operations assuming no EvalAdd
   * and EvalMult operations are performed.
   * @param dcrtBits number of bits in each CRT modulus*
   * @param n ring dimension in case the user wants to use a custom ring
   * dimension
   */
    bool ParamsGenBFVRNS(std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams, uint32_t evalAddCount,
                         uint32_t multiplicativeDepth, uint32_t keySwitchCount, size_t dcrtBits, uint32_t numPartQ,
                         uint32_t n) const override {
        OPENFHE_THROW("This signature for ParamsGen is not supported for this scheme.");
    }

    /**
   * Method for computing all derived parameters based on chosen primitive
   * parameters.
   *
   * @param cryptoParams the crypto parameters object to be populated with parameters.
   * @param cyclOrder the cyclotomic order.
   * @param numPrimes number of modulus towers to support.
   * @param scalingModSize the bit-width for plaintexts and DCRTPoly's.
   * @param firstModSize the bit-size of the first modulus
   * @param numPartQ number of partitions of Q for HYBRID key switching
   *
   */
    bool ParamsGenCKKSRNS(std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams, usint cyclOrder,
                          usint numPrimes, usint scalingModSize, usint firstModSize, uint32_t mulPartQ,
                          COMPRESSION_LEVEL mPIntBootCiphertextCompressionLevel) const override {
        OPENFHE_THROW("This signature for ParamsGen is not supported for this scheme.");
    }

    /**
   * Method for computing all derived parameters based on chosen primitive
   * parameters. This is intended for BGVrns
   * @param *cryptoParams the crypto parameters object to be populated with
   * parameters.
   * @param evalAddCount number of EvalAdds per level.
   * @param keySwitchCount number of KeySwitch operations per level.
   * @param cyclOrder the cyclotomic order.
   * @param numPrimes number of modulus towers to support.
   * @param digitSize the digit size
   * @param secretKeyDist
   * @param ksTech the key switching technique used (e.g., BV or GHS)
   * @param firstModSize the bit-size of the first modulus
   * @param dcrtBits the bit-width of moduli.
   */
    bool ParamsGenBGVRNS(std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams, uint32_t evalAddCount,
                         uint32_t keySwitchCount, usint cyclOrder, usint numPrimes, usint firstModSize, usint dcrtBits,
                         uint32_t numPartQ, usint multihopQBound) const override {
        OPENFHE_THROW("This signature for ParamsGen is not supported for this scheme.");
    }

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {}

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {}

    std::string SerializedObjectName() const {
        return "ParameterGenerationRNS";
    }

protected:
    enum DCRT_MODULUS {
        DEFAULT_EXTRA_MOD_SIZE = 20,
        MIN_SIZE               = 14,
        MAX_SIZE               = 60,
    };
};

}  // namespace lbcrypto

#endif
