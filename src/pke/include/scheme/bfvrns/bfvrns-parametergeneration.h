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

#ifndef SRC_PKE_INCLUDE_SCHEME_BFVRNS_BFVRNS_PARAMETERGENERATION_H_
#define SRC_PKE_INCLUDE_SCHEME_BFVRNS_BFVRNS_PARAMETERGENERATION_H_

#include <cstdint>
#include <memory>
#include <string>

#include "schemerns/rns-parametergeneration.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief Parameter generation for the BFV scheme in the RNS representation: derives the ring dimension and
 * the CRT modulus chain from the noise bounds of the requested computation and the security level.
 */
class ParameterGenerationBFVRNS : public ParameterGenerationRNS {
  public:
    virtual ~ParameterGenerationBFVRNS() {}

    /**
   * Generates the BFV element parameters (ring dimension and CRT moduli) for the requested computation. The
   * ciphertext modulus is sized from the BFV noise bounds for the given numbers of additions, multiplications
   * and key switches, the ring dimension is chosen to satisfy the security level (unless a custom one is
   * given), the encoding batch size is set to n when not specified, and the CRT tables are precomputed.
   *
   * @param cryptoParams the crypto parameters object to be populated with parameters.
   * @param evalAddCount number of EvalAdds assuming no EvalMult and KeySwitch operations are performed.
   * @param multiplicativeDepth number of EvalMults assuming no EvalAdd and KeySwitch operations are performed.
   * @param keySwitchCount number of KeySwitch operations assuming no EvalAdd and EvalMult operations are
   * performed.
   * @param dcrBits number of bits in each CRT modulus.
   * @param n ring dimension in case the user wants to use a custom ring dimension (0 to derive it from the
   * security level).
   * @param numPartQ number of partitions (digits) of Q for HYBRID key switching.
   * @return true on success (an exception is thrown otherwise).
   */
    bool ParamsGenBFVRNSInternal(std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams, uint32_t evalAddCount,
                                 uint32_t multiplicativeDepth, uint32_t keySwitchCount, size_t dcrBits, uint32_t n,
                                 uint32_t numPartQ) const override;

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {}

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {}

    std::string SerializedObjectName() const {
        return "ParameterGenerationBFVRNS";
    }
};

}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_SCHEME_BFVRNS_BFVRNS_PARAMETERGENERATION_H_
