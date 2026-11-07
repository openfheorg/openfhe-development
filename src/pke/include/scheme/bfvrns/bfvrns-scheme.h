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

#ifndef SRC_PKE_INCLUDE_SCHEME_BFVRNS_BFVRNS_SCHEME_H_
#define SRC_PKE_INCLUDE_SCHEME_BFVRNS_BFVRNS_SCHEME_H_

#include <cstdint>
#include <memory>
#include <string>

#include "scheme/bfvrns/bfvrns-advancedshe.h"
#include "scheme/bfvrns/bfvrns-cryptoparameters.h"
#include "scheme/bfvrns/bfvrns-fhe.h"
#include "scheme/bfvrns/bfvrns-leveledshe.h"
#include "scheme/bfvrns/bfvrns-multiparty.h"
#include "scheme/bfvrns/bfvrns-parametergeneration.h"
#include "scheme/bfvrns/bfvrns-pke.h"
#include "scheme/bfvrns/bfvrns-pre.h"
#include "schemerns/rns-scheme.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief The BFV scheme in the RNS representation: instantiates the BFV parameter generation, PKE, PRE,
 * leveled SHE, advanced SHE, multiparty and FHE components.
 */
class SchemeBFVRNS : public SchemeRNS {
  public:
    SchemeBFVRNS() {
        this->m_ParamsGen = std::make_shared<ParameterGenerationBFVRNS>();
    }

    virtual ~SchemeBFVRNS() {}

    /**
     * Compares two schemes by type.
     *
     * @param sch the scheme to compare to.
     * @return true if sch is also a SchemeBFVRNS.
     */
    bool operator==(const SchemeBase<DCRTPoly>& sch) const override {
        return (typeid(sch) == typeid(SchemeBFVRNS));
    }

    /**
     * Instantiates the BFV implementation of the given feature (PKE, PRE, LEVELEDSHE, MULTIPARTY, ADVANCEDSHE
     * or FHE) if it has not been instantiated yet. KEYSWITCH is set up separately by SetKeySwitchingTechnique().
     *
     * @param feature the feature to enable; unsupported features throw.
     */
    void Enable(PKESchemeFeature feature) override;

    /////////////////////////////////////
    // KEY SWITCH
    // BFV does not support evaluation keys generated or compressed at a reduced level: every key
    // generation path (relinearization, automorphism, summation, multiparty) ends in one of these
    // methods, which reject a nonzero levels argument and otherwise defer to the base class.
    // GetNumEvalKeyTowers is queried before the parallel loop of EvalAutomorphismKeyGen, so the
    // rejection happens outside the OpenMP region.
    /////////////////////////////////////

    using SchemeRNS::KeySwitchGen;

    EvalKey<DCRTPoly> KeySwitchGen(const PrivateKey<DCRTPoly> oldPrivateKey, const PrivateKey<DCRTPoly> newPrivateKey,
                                   uint32_t levels = 0) const override {
        ValidateEvalKeyLevels(levels);
        return SchemeRNS::KeySwitchGen(oldPrivateKey, newPrivateKey, levels);
    }

    EvalKey<DCRTPoly> KeySwitchGen(const PrivateKey<DCRTPoly> oldPrivateKey, const PrivateKey<DCRTPoly> newPrivateKey,
                                   const EvalKey<DCRTPoly> evalKey, uint32_t levels = 0) const override {
        ValidateEvalKeyLevels(levels);
        return SchemeRNS::KeySwitchGen(oldPrivateKey, newPrivateKey, evalKey, levels);
    }

    EvalKey<DCRTPoly> CompressEvalKey(const EvalKey<DCRTPoly> evalKey, uint32_t levels) const override {
        ValidateEvalKeyLevels(levels);
        return SchemeRNS::CompressEvalKey(evalKey, levels);
    }

    uint32_t GetNumEvalKeyTowers(const std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams,
                                 uint32_t levels) const override {
        ValidateEvalKeyLevels(levels);
        return SchemeRNS::GetNumEvalKeyTowers(cryptoParams, levels);
    }

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(cereal::base_class<SchemeRNS>(this));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        ar(cereal::base_class<SchemeRNS>(this));
    }

    std::string SerializedObjectName() const override {
        return "SchemeBFVRNS";
    }

  private:
    static void ValidateEvalKeyLevels(uint32_t levels) {
        if (levels > 0)
            OPENFHE_THROW("Generating or compressing evaluation keys at a nonzero level is not supported for BFV");
    }
};
}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_SCHEME_BFVRNS_BFVRNS_SCHEME_H_
