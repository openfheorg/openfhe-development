#if 0 // TODO uncomment test after merge to github
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

#include "UnitTestSer.h"
#include "gtest/gtest.h"

#include "scheme/bfvrns/bfvrns-ser.h"

using namespace std;
using namespace lbcrypto;

class UTPKESer : public ::testing::Test {
 protected:
  void SetUp() {}

  void TearDown() {
    CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
    CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
  }
};

CryptoContext<DCRTPoly> GenerateTestDCRTCryptoContext(const string& parmsetName,
    usint nTower,
    usint pbits) {
    CryptoContext<DCRTPoly> cc =
        CryptoContextHelper::getNewDCRTContext(parmsetName, nTower, pbits);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    return cc;
}

template <typename T>
void UnitTestContext(CryptoContext<T> cc) {
  UnitTestContextWithSertype(cc, SerType::JSON, "json");
  UnitTestContextWithSertype(cc, SerType::BINARY, "binary");
}

TEST_F(UTPKESer, BFVrns_DCRTPoly_Serial) {
  CryptoContext<DCRTPoly> cc = GenerateTestDCRTCryptoContext("BFVrns2", 3, 20);
  UnitTestContext<DCRTPoly>(cc);
}
#endif