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

#ifndef LBCRYPTO_CRYPTO_RNS_SCHEME_H
#define LBCRYPTO_CRYPTO_RNS_SCHEME_H

#include "lattice/lat-hal.h"

#include "schemebase/base-scheme.h"

#include "schemerns/rns-cryptoparameters.h"
#include "schemerns/rns-parametergeneration.h"
#include "schemerns/rns-pke.h"
#include "schemerns/rns-pre.h"
#include "schemerns/rns-leveledshe.h"
#include "schemerns/rns-advancedshe.h"
#include "schemerns/rns-multiparty.h"

#include "keyswitch/keyswitch-hybrid.h"
#include "keyswitch/keyswitch-bv.h"
#include "constants.h"
#include "utils/exception.h"

#include <string>
#include <memory>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief Abstract interface class for LBC PRE algorithms
 * @tparam Element a ring element.
 */
class SchemeRNS : public SchemeBase<DCRTPoly> {
public:
    SchemeRNS() {}

    virtual ~SchemeRNS() {}

    void SetKeySwitchingTechnique(KeySwitchTechnique ksTech) {
        if (ksTech == BV) {
            m_KeySwitch = std::make_shared<KeySwitchBV>();
        }
        else if (ksTech == HYBRID) {
            m_KeySwitch = std::make_shared<KeySwitchHYBRID>();
        }
        else
            OPENFHE_THROW("ksTech is invalid");
    }

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(cereal::base_class<SchemeBase<DCRTPoly>>(this));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        ar(cereal::base_class<SchemeBase<DCRTPoly>>(this));
    }

    std::string SerializedObjectName() const override {
        return "SchemeRNS";
    }
};

}  // namespace lbcrypto

#endif
