//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
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

// Built-in diagnostic sink; see diagnostic_output.h for the interface contract.

#include "config_core.h"
#include "utils/diagnostic_output.h"

#ifdef WITH_DEFAULT_LOG_SINK

    #include <iostream>

namespace lbcrypto {

namespace {
std::ostream* g_errStream = &std::cerr;
std::ostream* g_outStream = &std::cout;
}  // namespace

namespace internal_diagnostics {

std::ostream& OpenFHEErrStream() {
    return *g_errStream;
}
std::ostream& OpenFHEOutStream() {
    return *g_outStream;
}

}  // namespace internal_diagnostics

void SetOpenFHEErrStream(std::ostream& os) {
    g_errStream = &os;
}
void SetOpenFHEOutStream(std::ostream& os) {
    g_outStream = &os;
}

}  // namespace lbcrypto

#endif  // WITH_DEFAULT_LOG_SINK
