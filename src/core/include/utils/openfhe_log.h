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
  Pluggable diagnostic output channel for OpenFHE.

  Library code that needs to emit a diagnostic message writes to
  OPENFHE_LOG_ERR / OPENFHE_LOG_OUT instead of std::cerr / std::cout
  directly. Each macro expands to a std::ostream&, so every built-in
  operator<< overload and manipulator (std::endl, std::hex, ...) works
  transparently and existing call sites need no other change.

  Routing the streams through an indirection lets an embedding
  application redirect OpenFHE's diagnostics without editing every call
  site. Two mechanisms are provided, and they compose:

    * Runtime: call SetOpenFHEErrStream() / SetOpenFHEOutStream() to
      point the channel at any std::ostream (a file, a string stream, a
      GUI log widget) whose lifetime outlives subsequent diagnostics.

    * Build time: the default sink (which targets std::cerr / std::cout)
      lives in a single translation unit, openfhe_log_default.cpp, that
      is compiled only when the OPENFHE_DEFAULT_LOG_SINK CMake option is
      ON (the default). An embedder that must keep std::cerr / std::cout
      out of the compiled OpenFHE archive entirely — for example an R
      package, where CRAN forbids compiled code that writes to
      stdout/stderr — builds with -DOPENFHE_DEFAULT_LOG_SINK=OFF and
      links its own definitions of the accessors below.

  With OPENFHE_DEFAULT_LOG_SINK=ON (the default) the behavior is
  byte-for-byte identical to writing to std::cerr / std::cout directly.
*/

#ifndef _LBCRYPTO_UTILS_OPENFHE_LOG_H_
#define _LBCRYPTO_UTILS_OPENFHE_LOG_H_

#include <ostream>

namespace lbcrypto {

// Diagnostic error / output channels. All library diagnostics route
// here via OPENFHE_LOG_ERR / OPENFHE_LOG_OUT. The default sink
// (openfhe_log_default.cpp, compiled iff OPENFHE_DEFAULT_LOG_SINK)
// targets std::cerr / std::cout; an embedder may supply its own.
std::ostream& OpenFHEErrStream();
std::ostream& OpenFHEOutStream();

// Redirect the channels at runtime. The referenced stream must outlive
// any subsequent OpenFHE diagnostic. Intended to be called once during
// initialization; concurrent use with library diagnostics is the
// caller's responsibility.
void SetOpenFHEErrStream(std::ostream& os);
void SetOpenFHEOutStream(std::ostream& os);

}  // namespace lbcrypto

#define OPENFHE_LOG_ERR (::lbcrypto::OpenFHEErrStream())
#define OPENFHE_LOG_OUT (::lbcrypto::OpenFHEOutStream())

#endif  // _LBCRYPTO_UTILS_OPENFHE_LOG_H_
