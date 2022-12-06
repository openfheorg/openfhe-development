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
#ifndef __BASETESTCASE_H__
#define __BASETESTCASE_H__

#include "scheme/ckksrns/cryptocontext-ckksrns.h"
#include "scheme/bfvrns/cryptocontext-bfvrns.h"
#include "scheme/bgvrns/cryptocontext-bgvrns.h"
#include "scheme/cryptocontextparams-base.h"

#include <memory>
#include <string>
#include <vector>

struct BaseTestCase {
private:
    // std::shared_ptr<lbcrypto::Params> params;
    lbcrypto::SCHEME scheme;
    std::vector<std::string> paramOverrides;

public:
    // const std::shared_ptr<lbcrypto::Params> getCryptoContextParams() const {
    //    return params;
    // }

    // void setCryptoContextParams(std::shared_ptr<lbcrypto::Params> params0) {
    //    params = params0;
    // }

    const std::vector<std::string>& getCryptoContextParamOverrides() const {
        return paramOverrides;
    }

    /**
     * creates a new cryptocontext parameter object, overrides its data members if necessary and assigns it to params
     *
     * @param vec vector with overrides
     * @return number of all data members of Params or number of vec's elements that can override params
     */
    // size_t populateCryptoContextParams(const std::vector<std::string>::const_iterator& start) {
    //    // get the total number of the parameter override values
    //    size_t numOverrides = lbcrypto::Params::getAllParamsDataMembers().size();

    //    // get the subset of elements with the parameter override values
    //    std::vector<std::string> overrideValues(start, start + numOverrides);

    //    lbcrypto::SCHEME scheme = lbcrypto::convertToSCHEME(*start);
    //    switch (scheme) {
    //    case lbcrypto::CKKSRNS_SCHEME:
    //        setCryptoContextParams(std::make_shared<lbcrypto::CCParams<lbcrypto::CryptoContextCKKSRNS>>(overrideValues));
    //        break;
    //    case lbcrypto::BFVRNS_SCHEME:
    //        setCryptoContextParams(std::make_shared<lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS>>(overrideValues));
    //        break;
    //    case lbcrypto::BGVRNS_SCHEME:
    //        setCryptoContextParams(std::make_shared<lbcrypto::CCParams<lbcrypto::CryptoContextBGVRNS>>(overrideValues));
    //        break;
    //    default: {
    //        std::string errMsg(std::string("Unknown schemeId ") + std::to_string(scheme));
    //        OPENFHE_THROW(lbcrypto::config_error, errMsg);
    //    }
    //    }

    //    return numOverrides;
    //}

    size_t setCryptoContextParamsOverrides(const std::vector<std::string>::const_iterator& start) {
        // get the total number of the parameter override values
        size_t numOverrides = lbcrypto::Params::getAllParamsDataMembers().size();

        scheme = lbcrypto::convertToSCHEME(*start);

        // get the subset of elements with the parameter override values
        paramOverrides = std::vector<std::string>(start, start + numOverrides);

        return numOverrides;
    }
};

#endif  // __BASETESTCASE_H__
