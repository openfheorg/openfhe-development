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

#ifndef SRC_PKE_INCLUDE_SCHEME_CKKSRNS_CKKSRNS_SCHEME_H_
#define SRC_PKE_INCLUDE_SCHEME_CKKSRNS_CKKSRNS_SCHEME_H_

#include <cstdint>
#include <memory>
#include <string>

#include "scheme/ckksrns/ckksrns-advancedshe.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "scheme/ckksrns/ckksrns-fhe.h"
#include "scheme/ckksrns/ckksrns-leveledshe.h"
#include "scheme/ckksrns/ckksrns-multiparty.h"
#include "scheme/ckksrns/ckksrns-parametergeneration.h"
#include "scheme/ckksrns/ckksrns-pke.h"
#include "scheme/ckksrns/ckksrns-pre.h"
#include "scheme/ckksrns/ckksrns-schemeswitching.h"
#include "schemerns/rns-scheme.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief The CKKS scheme in RNS form: assembles the CKKS parameter generation, PKE, key switching, PRE,
 * leveled SHE, advanced SHE, multiparty, FHE (bootstrapping) and scheme switching capabilities. Capabilities
 * other than parameter generation are instantiated on demand by Enable.
 */
class SchemeCKKSRNS : public SchemeRNS {
  public:
    /**
   * Constructs the scheme with its parameter generation capability; the other capabilities are created by
   * Enable.
   */
    SchemeCKKSRNS() {
        this->m_ParamsGen = std::make_shared<ParameterGenerationCKKSRNS>();
    }

    virtual ~SchemeCKKSRNS() = default;

    /**
   * Compares two schemes by type: any two SchemeCKKSRNS objects are equal.
   *
   * @param sch the scheme to compare to
   * @return true if sch is a SchemeCKKSRNS
   */
    bool operator==(const SchemeBase<DCRTPoly>& sch) const override {
        return (typeid(sch) == typeid(SchemeCKKSRNS));
    }

    /**
   * Enables a feature by instantiating the corresponding CKKS capability object (PKE, KEYSWITCH, PRE,
   * LEVELEDSHE, ADVANCEDSHE, MULTIPARTY, FHE or SCHEMESWITCH) if it is not enabled yet.
   *
   * @param feature the feature to enable
   */
    void Enable(PKESchemeFeature feature) override;

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
        return "SchemeCKKSRNS";
    }
};

}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_SCHEME_CKKSRNS_CKKSRNS_SCHEME_H_
