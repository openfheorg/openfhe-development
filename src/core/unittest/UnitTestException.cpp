// @file UnitTestException - tests PALISADE_THROW in and out of omp
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
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
/*
This code tests the transform feature of the PALISADE lattice encryption
library.
 */

#include "gtest/gtest.h"
#include <iostream>
#include <vector>

#include "utils/inttypes.h"
#include "utils/exception.h"

using namespace std;
using namespace lbcrypto;

static void regthrow(const string& msg) { PALISADE_THROW(config_error, msg); }

static void parthrow(const string& msg) {
  // now try throw inside omp
  ThreadException e;
#pragma omp parallel for
  for (int i = 0; i < 10; i++) {
    try {
      if (i == 7) regthrow("inside throw");
    } catch (...) {
      e.CaptureException();
    }
  }
  e.Rethrow();
}

static void runthrow(const string& msg) {
  // now try throw inside omp
  ThreadException e;
#pragma omp parallel for
  for (int i = 0; i < 10; i++) {
    e.Run([=] {
      if (i == 7) regthrow("inside throw");
    });
  }
  e.Rethrow();
}

// instantiate various test for common_set_format()
TEST(UTException, palisade_exception) {
  ASSERT_THROW(regthrow("outside throw"), config_error);

  ASSERT_THROW(parthrow("inside throw"), config_error);

  ASSERT_THROW(runthrow("using lambda inside throw"), config_error);
}
