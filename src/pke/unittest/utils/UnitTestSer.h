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
  helper function to test serialization
 */

#ifndef __UNITTESTSER_H__
#define __UNITTESTSER_H__

#include "UnitTestException.h"
#include "cryptocontext-ser.h"
#include "gtest/gtest.h"
#include <string>
#include <iostream>
#include "globals.h"  // for SERIALIZE_PRECOMPUTE

using namespace lbcrypto;

template <typename Element, typename ST>
void UnitTestContextWithSertype(CryptoContext<Element> cc, const ST& sertype,
                                const std::string& failmsg = std::string()) {
    try {
        KeyPair<Element> kp = cc->KeyGen();
        cc->EvalMultKeyGen(kp.secretKey);
        cc->EvalSumKeyGen(kp.secretKey, kp.publicKey);

        std::stringstream s;
        Serial::Serialize(cc, s, sertype);

        // std::cerr << " Output " << s.str() << std::endl;

        DisablePrecomputeCRTTablesAfterDeserializaton();
        CryptoContext<Element> newcc;
        Serial::Deserialize(newcc, s, sertype);

        ASSERT_TRUE(newcc) << failmsg << " Deserialize failed";

        EXPECT_EQ(*cc, *newcc) << failmsg << " Mismatched context";

        EXPECT_EQ(*cc->GetScheme(), *newcc->GetScheme()) << failmsg << " Scheme mismatch after ser/deser";
        EXPECT_EQ(*cc->GetCryptoParameters(), *newcc->GetCryptoParameters())
            << failmsg << " Crypto parms mismatch after ser/deser";
        EXPECT_EQ(*cc->GetEncodingParams(), *newcc->GetEncodingParams())
            << failmsg << " Encoding parms mismatch after ser/deser";
        EXPECT_EQ(cc->GetScheme()->GetEnabled(), newcc->GetScheme()->GetEnabled())
            << failmsg << " Enabled features mismatch after ser/deser";

        s.str("");
        s.clear();
        Serial::Serialize(kp.publicKey, s, sertype);

        PublicKey<Element> newPub;
        Serial::Deserialize(newPub, s, sertype);
        ASSERT_TRUE(newPub) << failmsg << " Key deserialize failed";

        EXPECT_EQ(*kp.publicKey, *newPub) << failmsg << " Key mismatch";

        CryptoContext<Element> newccFromkey = newPub->GetCryptoContext();
        EXPECT_EQ(*cc, *newccFromkey) << failmsg << " Key deser has wrong context";
        EnablePrecomputeCRTTablesAfterDeserializaton();
    }
    catch (std::exception& e) {
        EnablePrecomputeCRTTablesAfterDeserializaton();

        std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
        // make it fail
        EXPECT_TRUE(0 == 1) << failmsg;
    }
    catch (...) {
        EnablePrecomputeCRTTablesAfterDeserializaton();

        UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
    }
}

#endif  // __UNITTESTSER_H__
