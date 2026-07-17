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
  Default diagnostic sink for OpenFHE: routes OpenFHEErrStream() /
  OpenFHEOutStream() to std::cerr / std::cout.

  This translation unit is the ONLY place in the library that names
  std::cerr / std::cout. It is compiled only when OPENFHE_DEFAULT_LOG_SINK
  is defined (controlled by the CMake option of the same name, ON by
  default). When the option is OFF this file compiles to nothing, and the
  embedding application must provide its own definitions of
  lbcrypto::OpenFHEErrStream() / OpenFHEOutStream() (and, if it uses them,
  the Set* setters). That lets an embedder keep std::cerr / std::cout out
  of the compiled OpenFHE archive entirely — e.g. an R package, where
  CRAN's "compiled code should not write to stdout/stderr" rule forbids
  those symbols — while still receiving the library's diagnostics.
*/

#include "utils/openfhe_log.h"

#ifdef OPENFHE_DEFAULT_LOG_SINK

    #include <iostream>

namespace lbcrypto {

namespace {
std::ostream* g_errStream = &std::cerr;
std::ostream* g_outStream = &std::cout;
}  // namespace

std::ostream& OpenFHEErrStream() {
    return *g_errStream;
}
std::ostream& OpenFHEOutStream() {
    return *g_outStream;
}

void SetOpenFHEErrStream(std::ostream& os) {
    g_errStream = &os;
}
void SetOpenFHEOutStream(std::ostream& os) {
    g_outStream = &os;
}

}  // namespace lbcrypto

#endif  // OPENFHE_DEFAULT_LOG_SINK
