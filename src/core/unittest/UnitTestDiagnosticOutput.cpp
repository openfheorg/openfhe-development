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

#include "gtest/gtest.h"
#include "utils/diagnostic_output.h"

#include <ostream>
#include <sstream>
#include <string>

using namespace lbcrypto;

namespace {

// Installs a capture buffer on both channels and restores the previous streams
// when it goes out of scope, so a failing expectation cannot leave the channels
// pointing at a destroyed stream.
class ScopedDiagnosticCapture {
public:
    ScopedDiagnosticCapture() : m_previousErr(SetOpenFHEErrStream(m_err)), m_previousOut(SetOpenFHEOutStream(m_out)) {}

    ~ScopedDiagnosticCapture() {
        SetOpenFHEErrStream(m_previousErr);
        SetOpenFHEOutStream(m_previousOut);
    }

    std::string Err() const {
        return m_err.str();
    }
    std::string Out() const {
        return m_out.str();
    }

private:
    std::ostringstream m_err;
    std::ostringstream m_out;
    std::ostream& m_previousErr;
    std::ostream& m_previousOut;
};

}  // namespace

TEST(UTDiagnosticOutput, redirect_captures_each_channel_separately) {
    ScopedDiagnosticCapture capture;

    OPENFHE_DIAGNOSTIC_ERR << "to err" << std::endl;
    OPENFHE_DIAGNOSTIC_OUT << "to out" << std::endl;

    EXPECT_EQ(capture.Err(), "to err\n");
    EXPECT_EQ(capture.Out(), "to out\n");
}

TEST(UTDiagnosticOutput, manipulators_and_chaining_work) {
    ScopedDiagnosticCapture capture;

    OPENFHE_DIAGNOSTIC_ERR << std::hex << 255 << " " << std::dec << 255 << std::endl;

    EXPECT_EQ(capture.Err(), "ff 255\n");
    EXPECT_TRUE(capture.Out().empty());
}

TEST(UTDiagnosticOutput, setter_returns_the_previously_installed_stream) {
    std::ostringstream first;
    std::ostringstream second;

    std::ostream& original = SetOpenFHEErrStream(first);
    std::ostream& returned = SetOpenFHEErrStream(second);
    EXPECT_EQ(&returned, &first);

    OPENFHE_DIAGNOSTIC_ERR << "second" << std::endl;
    EXPECT_TRUE(first.str().empty());
    EXPECT_EQ(second.str(), "second\n");

    // restoring gives back the stream the channel started on
    EXPECT_EQ(&SetOpenFHEErrStream(original), &second);
    EXPECT_EQ(&SetOpenFHEErrStream(original), &original);
}
