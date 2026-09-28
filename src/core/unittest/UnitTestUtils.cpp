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

#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "include/gtest/gtest.h"
#include "utils/exception.h"
#include "utils/hashutil.h"
#include "utils/utilities.h"

using namespace lbcrypto;

TEST(Utilities, IsPowerOfTwo) {
    std::vector<uint32_t> powers_of_two{1, 2, 4, 8, 16, 32, 512, 1024, 2048, 4096, 16384, 32768};
    std::vector<uint32_t> not_powers_of_two{0, 3, 5, 7, 9, 31, 33, 1025, 4095};

    for (auto power_of_two : powers_of_two) {
        EXPECT_TRUE(IsPowerOfTwo(power_of_two));
    }

    for (auto not_power_of_two : not_powers_of_two) {
        EXPECT_FALSE(IsPowerOfTwo(not_power_of_two));
    }
}

TEST(Utilities, HashUtil) {
    const std::string abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    EXPECT_EQ(abc, HashUtil::HashString("abc"));

    std::vector<int64_t> digest;
    HashUtil::Hash("abc", SHA_256, digest);
    ASSERT_EQ(32u, digest.size());
    for (size_t i = 0; i < digest.size(); ++i)
        EXPECT_EQ(std::stoll(abc.substr(2 * i, 2), nullptr, 16), digest[i]) << "byte " << i;

    // a message byte above 0x7f must not be sign-extended into the message schedule
    std::vector<int64_t> digestHigh;
    HashUtil::Hash("\xff", SHA_256, digestHigh);
    const std::string ff = "a8100ae6aa1940d0b663bb31cd466142ebbdbd5187131b92d93818987832eb89";
    ASSERT_EQ(32u, digestHigh.size());
    for (size_t i = 0; i < digestHigh.size(); ++i)
        EXPECT_EQ(std::stoll(ff.substr(2 * i, 2), nullptr, 16), digestHigh[i]) << "byte " << i;
    EXPECT_EQ(ff, HashUtil::HashString("\xff"));

    // an unimplemented algorithm must not silently return another algorithm's digest
    std::vector<int64_t> digest512;
    EXPECT_THROW(HashUtil::Hash("abc", SHA_512, digest512), OpenFHEException);
}
