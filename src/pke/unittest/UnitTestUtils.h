// @file UnitTestUtils.cpp - Unit test utilities
//
// @copyright Copyright (c) 2019, Duality Technologies Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef _UNIT_TEST_UTILS_H_
#define _UNIT_TEST_UTILS_H_

#include "gtest/gtest.h"
#include <vector>
#include <string>
#include <algorithm>

// simple macro for in cases with exceptions
#define UT_EXPECT_THROW_SIMPLE(function) \
    PackedEncoding::Destroy();           \
    try {                                \
        function;                        \
        EXPECT_EQ(0, 1);                 \
    }                                    \
    catch(const exception& e) {          \
        EXPECT_EQ(1, 1);                 \
    }
    
/**
 * Function to check equality of 2 numeric values
 *
 * @param a      first vector to compare
 * @param b      second vector to compare
 */
constexpr double eps = 0.000000001;
template<typename T>
bool checkEquality(const T& a,
                   const T& b) {
  return (abs(a - b) <= eps);
}

/**
 * Function to check equality of 2 numeric vectors
 *
 * @param a      first vector to compare
 * @param b      second vector to compare
 */
template<typename V>
bool checkEquality(const std::vector<V>& a,
                   const std::vector<V>& b) {
  if( a.size() != b.size() )
    return false;

  return std::equal(a.begin(), a.end(), b.begin(),
                    [](const V& a, const V& b) { return checkEquality(a, b); });
}

/**
 * Function to check equality of 2 numeric vectors
 *
 * @param a      first vector to compare
 * @param b      second vector to compare
 * @param errMsg Debug message to display upon failure
 */
template<typename V>
void checkEquality(const std::vector<V>& a,
                   const std::vector<V>& b,
                   const std::string& errMsg) {
  EXPECT_TRUE(checkEquality(a, b)) << errMsg;
}

// Helper function to check automorphism
inline bool CheckAutomorphism(const std::vector<int64_t>& result,
                              const std::vector<int64_t>& init) {
  for (const auto& val : init) {
    if (!(std::find(result.begin(), result.end(), val) != result.end())) {
      return false;
    }
  }

  return true;
}

// generate a random printable string of length outStrLength
inline std::string RandomString(uint64_t outStringLength) {
    auto getRandomChar = []() -> char {
        const char charset[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";
        const size_t max_index = (sizeof(charset) - 1);
        return charset[rand() % max_index];
    };

    std::string retString(outStringLength, 0);
    std::generate_n(retString.begin(), outStringLength, getRandomChar);

    return retString;
}

#endif // _UNIT_TEST_UTILS_H_
